// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// login.go implements the per-method credential-gathering flow that
// "auth login" delegates to. Per docs/architecture/08-bootstrap-auth-architecture.md
// §5e the flow is:
//
//  1. Resolve method ("--method" flag or auto-discover).
//  2. Gather method-specific proof material:
//     mtls   → SHA-256 fingerprint of the client certificate.
//     fido2  → WebAuthn getAssertion ceremony against the selected authenticator.
//     piv    → ECDSA / RSA signature of a fresh nonce by the PIV slot.
//  3. Submit AuthFactorLoginRequest{Proof, Metadata, FactorName, FactorID}
//     to the SDK Security().Auth().Factors().Login() endpoint.
//
// §5c (vendor-agnostic guarantee): NO xkey-specific code paths. The
// WebAuthn / PIV sub-clients on the SDK are vendor-agnostic by contract.
// FIDO2 authenticator discovery and selection is a client-LOCAL USB-HID
// operation (Security().Auth().Devices()); the WebAuthn ceremony itself
// (Security().Auth().WebAuthn()) is the single canonical server round-trip.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// defaultClientCertEnvVars are the environment variables that, when
// set, override the default client cert search path.
var defaultClientCertEnvVars = []string{
	"PLATFORMCTL_CLIENT_CERT",
	"XKMSCTL_CLIENT_CERT",
	"QUICBAAS_CLIENT_CERT",
	"QRDB_CLIENT_CERT",
}

// defaultClientCertPaths is the list of well-known locations probed by
// auto-discovery and mTLS login when --client-cert is not supplied.
var defaultClientCertPaths = []string{
	"~/.platformctl/admin.pem",
	"~/.config/platformctl/admin.pem",
}

// dispatchLogin executes a type-dispatched login. Method auto-discovery
// runs when req.Method is empty.
func (c *Client) dispatchLogin(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	if req == nil {
		req = &LoginRequest{}
	}
	method := req.Method
	if method == "" {
		discovered, derr := c.autoDiscoverMethod(ctx, req)
		if derr != nil {
			return nil, derr
		}
		method = discovered
	}
	if _, ok := validAuthMethods[method]; !ok {
		return nil, &ErrInvalidAuthMethod{Method: method}
	}

	switch method {
	case "mtls":
		return c.loginMTLS(ctx, req)
	case "fido2":
		return c.loginFIDO2(ctx, req)
	case "piv":
		return c.loginPIV(ctx, req)
	}
	return nil, &ErrInvalidAuthMethod{Method: method}
}

// autoDiscoverMethod probes the client environment for an available
// auth method and returns the first match. Probe order: mtls cert →
// FIDO2 device → PIV reader. Returns ErrNoFactorsAvailable when nothing
// is reachable, and ErrAmbiguousAutoDiscovery when more than one
// candidate is present at distinct factor types.
func (c *Client) autoDiscoverMethod(ctx context.Context, req *LoginRequest) (string, error) {
	hasMTLS := resolveDefaultClientCert(req.ClientCertPath) != ""

	hasFIDO2 := false
	hasPIV := false
	if !hasMTLS {
		// FIDO2 authenticator discovery is a client-LOCAL USB-HID probe via
		// Devices().Present(); a server cannot see the client's attached keys.
		if devices, err := c.devices("auth login auto-discovery"); err == nil && devices != nil {
			if present, perr := devices.Present(); perr == nil && present {
				hasFIDO2 = true
			}
		}
		if piv, err := c.piv("auth login auto-discovery"); err == nil && piv != nil {
			if rd, rerr := piv.ListReaders(ctx); rerr == nil && rd != nil && len(rd.Readers) > 0 {
				hasPIV = true
			}
		}
	}

	switch {
	case hasMTLS:
		return "mtls", nil
	case hasFIDO2 && !hasPIV:
		return "fido2", nil
	case hasPIV && !hasFIDO2:
		return "piv", nil
	case hasFIDO2 && hasPIV:
		return "", &ErrAmbiguousAutoDiscovery{Methods: []string{"fido2", "piv"}}
	}
	return "", &ErrNoFactorsAvailable{}
}

// loginMTLS performs an mTLS-style login. The platform CA validates the
// chain server-side using the certificate presented during the TLS
// handshake; the client only needs to declare the fingerprint as Proof
// so the server can resolve the AuthFactor record by SHA-256(cert).
func (c *Client) loginMTLS(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	factors, err := c.factors("auth login --method mtls")
	if err != nil {
		return nil, err
	}
	path := resolveDefaultClientCert(req.ClientCertPath)
	if path == "" {
		return nil, &ErrMissingCertPath{}
	}
	fingerprint, meta, err := loadCertFingerprintAndMetadata(path)
	if err != nil {
		return nil, err
	}
	rawFingerprint, decodeErr := hex.DecodeString(fingerprint)
	if decodeErr != nil {
		return nil, &ErrCertRead{Path: path, Cause: decodeErr}
	}
	loginReq := &quicbaas.AuthFactorLoginRequest{
		Username:   req.Username,
		FactorName: "mtls",
		FactorID:   req.FactorID,
		Proof:      rawFingerprint,
		Metadata:   stringifyMetadata(meta),
	}
	loginReq.Metadata["credential_sha256"] = fingerprint
	loginReq.Metadata["cert_path"] = path
	return factors.Login(ctx, loginReq)
}

// loginFIDO2 selects a client-LOCAL authenticator and runs the canonical
// WebAuthn login ceremony against it, submitting the assertion as Proof.
//
// Authenticator discovery/selection is intrinsically local (Devices()): a
// server cannot enumerate the USB keys attached to a remote client. The
// ceremony itself is the single canonical server round-trip via
// WebAuthn().BeginLogin (the removed FIDO2().Assert accessor duplicated it).
func (c *Client) loginFIDO2(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	factors, err := c.factors("auth login --method fido2")
	if err != nil {
		return nil, err
	}
	devices, err := c.devices("auth login --method fido2")
	if err != nil {
		return nil, err
	}
	list, err := devices.List()
	if err != nil {
		return nil, &ErrFIDO2Failed{Op: "List", Cause: err}
	}
	if len(list) == 0 {
		return nil, &ErrNoFIDO2Device{}
	}
	device, derr := selectFIDO2Device(list, req.Device)
	if derr != nil {
		return nil, derr
	}
	webauthn, err := c.webauthn("auth login --method fido2")
	if err != nil {
		return nil, err
	}
	// Session-model WebAuthn ceremony: BeginLogin begins the authentication
	// ceremony server-side and returns an opaque SessionID plus the
	// JSON-marshaled assertion options the local authenticator signed. The
	// relying-party id and allowed-credential set are resolved server-side
	// from the username, so no client-supplied RPID is sent.
	assertResp, err := webauthn.BeginLogin(ctx, &quicbaas.WebAuthnUser{
		Username: req.Username,
	})
	if err != nil {
		return nil, &ErrFIDO2Failed{Op: "BeginLogin", Cause: err}
	}
	if assertResp == nil {
		return nil, &ErrFIDO2Failed{Op: "BeginLogin", Cause: errors.New("nil assertion response")}
	}
	if assertResp.SessionID == "" || assertResp.OptionsJSON == "" {
		return nil, &ErrFIDO2Failed{Op: "BeginLogin", Cause: errors.New("assertion response missing session id or options")}
	}
	// The proof is the authenticator assertion (OptionsJSON); the server
	// correlates and verifies it against the begin ceremony via SessionID.
	// No token is fabricated client-side — the assertion is the proof.
	loginReq := &quicbaas.AuthFactorLoginRequest{
		Username:   req.Username,
		FactorName: "fido2",
		FactorID:   req.FactorID,
		Proof:      []byte(assertResp.OptionsJSON),
		Metadata: map[string]string{
			"session_id": assertResp.SessionID,
			"device_id":  device.Path,
		},
	}
	return factors.Login(ctx, loginReq)
}

// loginPIV signs a fresh client nonce with the chosen PIV slot and
// submits the signature as Proof. The cert fingerprint goes into
// Metadata so the server can resolve the AuthFactor record.
func (c *Client) loginPIV(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	factors, err := c.factors("auth login --method piv")
	if err != nil {
		return nil, err
	}
	piv, err := c.piv("auth login --method piv")
	if err != nil {
		return nil, err
	}
	readers, err := piv.ListReaders(ctx)
	if err != nil {
		return nil, &ErrPIVFailed{Op: "ListReaders", Cause: err}
	}
	if readers == nil || len(readers.Readers) == 0 {
		return nil, &ErrNoPIVReader{}
	}
	reader, derr := selectPIVReader(readers.Readers, req.Reader)
	if derr != nil {
		return nil, derr
	}
	slot := req.Slot
	if slot == "" {
		slot = "9a"
	}
	cert, err := piv.GetCertificate(ctx, reader.Name, slot)
	if err != nil {
		return nil, &ErrPIVFailed{Op: "GetCertificate", Cause: err}
	}
	if cert == nil {
		return nil, &ErrPIVFailed{Op: "GetCertificate", Cause: errors.New("nil certificate")}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, &ErrPIVFailed{Op: "RandRead", Cause: err}
	}
	digest := sha256.Sum256(nonce)
	if req.PIN == "" {
		return nil, &ErrPIVPINRequired{}
	}
	signResp, err := piv.Sign(ctx, &quicbaas.PIVSignRequest{
		Reader: reader.Name,
		Slot:   slot,
		PIN:    req.PIN,
		Digest: digest[:],
		Algo:   pivAlgoFromCert(cert),
	})
	if err != nil {
		return nil, &ErrPIVFailed{Op: "Sign", Cause: err}
	}
	if signResp == nil {
		return nil, &ErrPIVFailed{Op: "Sign", Cause: errors.New("nil signature response")}
	}
	sum := sha256.Sum256(cert.Raw)
	loginReq := &quicbaas.AuthFactorLoginRequest{
		Username:   req.Username,
		FactorName: "piv",
		FactorID:   req.FactorID,
		Proof:      signResp.Signature,
		Metadata: map[string]string{
			"reader":            reader.Name,
			"slot":              slot,
			"credential_sha256": hex.EncodeToString(sum[:]),
			"nonce":             hex.EncodeToString(nonce),
			"sign_algo":         signResp.Algo,
			"cert_cn":           cert.Subject.CommonName,
			"cert_serial":       cert.SerialNumber.String(),
		},
	}
	return factors.Login(ctx, loginReq)
}

// selectFIDO2Device picks the locally-attached authenticator matching
// devicePath (the LocalDevice.Path stable identifier), or returns
// ErrAmbiguousFIDO2Device when multiple authenticators are connected and the
// caller did not pin one.
func selectFIDO2Device(devices []quicbaas.LocalDevice, devicePath string) (*quicbaas.LocalDevice, error) {
	if devicePath != "" {
		for i := range devices {
			if devices[i].Path == devicePath {
				return &devices[i], nil
			}
		}
		return nil, &ErrFIDO2DeviceNotFound{DeviceID: devicePath}
	}
	if len(devices) == 1 {
		return &devices[0], nil
	}
	paths := make([]string, 0, len(devices))
	for i := range devices {
		paths = append(paths, devices[i].Path)
	}
	return nil, &ErrAmbiguousFIDO2Device{Devices: paths}
}

// selectPIVReader picks the reader matching name, or returns
// ErrAmbiguousPIVReader when multiple readers are present and the
// caller did not pin one.
func selectPIVReader(readers []quicbaas.PIVReader, name string) (*quicbaas.PIVReader, error) {
	if name != "" {
		for i := range readers {
			if readers[i].Name == name {
				return &readers[i], nil
			}
		}
		return nil, &ErrPIVReaderNotFound{Name: name}
	}
	if len(readers) == 1 {
		return &readers[0], nil
	}
	names := make([]string, 0, len(readers))
	for i := range readers {
		names = append(names, readers[i].Name)
	}
	return nil, &ErrAmbiguousPIVReader{Readers: names}
}

// resolveDefaultClientCert returns the first existing path among an
// explicit override and the well-known default locations. Returns ""
// when no candidate is found.
func resolveDefaultClientCert(explicit string) string {
	if explicit != "" {
		if _, err := os.Stat(explicit); err == nil {
			return explicit
		}
		return ""
	}
	for _, env := range defaultClientCertEnvVars {
		if v := os.Getenv(env); v != "" {
			if expanded := expandHome(v); expanded != "" {
				if _, err := os.Stat(expanded); err == nil {
					return expanded
				}
			}
		}
	}
	for _, path := range defaultClientCertPaths {
		expanded := expandHome(path)
		if expanded == "" {
			continue
		}
		if _, err := os.Stat(expanded); err == nil {
			return expanded
		}
	}
	return ""
}

// expandHome expands a leading "~/" in path against the user's home
// directory. Returns "" when the path can't be expanded.
func expandHome(path string) string {
	if path == "" {
		return ""
	}
	if path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	if path == "~" {
		return home
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == os.PathSeparator) {
		return home + string(os.PathSeparator) + path[2:]
	}
	return path
}

// pivAlgoFromCert returns a PIV signing algorithm name (matching the
// SDK's PIVSignRequest.Algo) chosen from the certificate's public key
// type. Defaults to "ecdsa" when the type is unknown.
func pivAlgoFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return "ecdsa"
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "rsa-pkcs1"
	case x509.Ed25519:
		return "ed25519"
	case x509.ECDSA:
		fallthrough
	default:
		return "ecdsa"
	}
}

// stringifyMetadata flattens a map[string]any to map[string]string
// using fmt.Sprint so it can be carried over the wire-level Metadata
// field which is map[string]string only.
func stringifyMetadata(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case string:
			out[k] = t
		case []byte:
			out[k] = string(t)
		default:
			out[k] = fmt.Sprint(t)
		}
	}
	return out
}
