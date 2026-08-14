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
// "auth login" delegates to. The flow rides the unified login ceremony
// (Security().Auth().BeginLogin / FinishLogin — qrdb's canonical login
// backbone):
//
//  1. Resolve method ("--method" flag or auto-discover).
//  2. BeginLogin opens the ceremony; the registered factor authenticator
//     issues the method-specific challenge (server nonce for mtls / piv,
//     WebAuthn request options for fido2).
//  3. Gather the method-specific proof:
//     mtls   → SHA-256(cert DER) lookup key; possession is proven by the
//     TLS handshake, so no in-band signature.
//     fido2  → WebAuthn assertion produced by the client-LOCAL CTAP2
//     authenticator over the server-issued request options.
//     piv    → signature over the server nonce by the PIV slot key.
//  4. FinishLogin submits {SessionID, Type, LookupKey, Signature,
//     MethodMetadata}; the server verifies the proof and mints the bearer.
//
// Vendor-agnostic guarantee: NO xkey-specific code paths. FIDO2
// authenticator discovery and selection is a client-LOCAL USB-HID
// operation (Security().Auth().Devices()); the assertion is produced by
// the quicbaas sdk/go/xkms/fido2 re-export of the go-xkms CTAP2 handler.
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsfido2 "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"
)

// Canonical WebAuthn challenge / proof metadata keys. These are matched
// EXACTLY against the keys the server's tenant WebAuthn verifier reads
// and writes (go-xkms/pkg/auth_factors/webauthn.go): BeginChallenge sets
// the assertion request options under "options" and the relying-party
// session id under "session_id"; Verify reads the session id from
// MethodMetadata["session_id"], the credential id from
// MethodMetadata["credential_id"], and the assertion JSON from the
// FinishLoginRequest.Signature field. Do NOT rename these without
// changing the server verifier in lockstep.
const (
	fido2OptionsKey      = "options"
	fido2SessionIDKey    = "session_id"
	fido2CredentialIDKey = "credential_id"
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

// fido2AssertFunc drives a connected CTAP2 authenticator through a
// WebAuthn assertion ceremony whose options were issued by the server,
// and returns the navigator.credentials.get() assertion JSON the server
// verifies.
//
// It is a package-level seam so the device-free login plumbing (options
// extraction, lookup-key derivation, metadata assembly) can be
// unit-tested without a physical authenticator. The production default
// drives a real HID authenticator over CTAP2 (fido2AssertWithOptions);
// the seam never bypasses CTAP2 in production code.
var fido2AssertFunc = fido2AssertWithOptions

// fido2AssertWithOptions is the production implementation behind
// fido2AssertFunc. It builds a FIDO2 handler over the platform HID
// enumerator (via the quicbaas sdk/go/xkms/fido2 re-export) and drives
// the connected authenticator with the server-issued WebAuthn request
// options. devicePath, when non-empty, pins a specific local HID device.
// origin, when non-empty, overrides the WebAuthn-standard same-origin
// default ("https://<rpId>").
func fido2AssertWithOptions(ctx context.Context, optionsJSON []byte, devicePath, origin string) ([]byte, error) {
	fidoConfig := xkmsfido2.DefaultConfig
	if devicePath != "" {
		fidoConfig.DevicePath = devicePath
	}
	handler, err := xkmsfido2.NewHandler(&fidoConfig, xkmsfido2.NewDefaultEnumerator())
	if err != nil {
		return nil, &ErrFIDO2Failed{Op: "NewHandler", Cause: err}
	}
	defer func() { _ = handler.Close() }()

	assertion, aerr := handler.AssertWithOptionsAndOrigin(ctx, optionsJSON, origin)
	if aerr != nil {
		return nil, &ErrFIDO2Failed{Op: "Assert", Cause: aerr}
	}
	return assertion, nil
}

// pivSignNonceFunc signs the server-issued login nonce with the PIV slot
// key resolved through the go-xkms PIV backend resolver (client-local,
// in-process). SHA-256 is forced because the server-side verifier
// (go-xkms PIVHardwareFactorVerifier) always digests the nonce with
// SHA-256 regardless of key size.
//
// It is a package-level seam so the login plumbing can be unit-tested
// without local PIV key material; the production default never bypasses
// the xkms PIV backends.
var pivSignNonceFunc = pivSignNonce

// pivSignNonce is the production implementation behind pivSignNonceFunc.
func pivSignNonce(ctx context.Context, backend, slot, pin string, nonce []byte) ([]byte, error) {
	resp, err := xkms.SignPIV(ctx, &xkms.PIVSignRequest{
		Backend:       backend,
		Slot:          slot,
		Payload:       nonce,
		HashAlgorithm: "sha256",
		PIN:           pin,
	})
	if err != nil {
		return nil, &ErrPIVFailed{Op: "SignPIV", Cause: err}
	}
	if resp == nil || len(resp.Signature) == 0 {
		return nil, &ErrPIVFailed{Op: "SignPIV", Cause: errors.New("empty signature")}
	}
	return resp.Signature, nil
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
// FIDO2 device → PIV slot certificate. Returns ErrNoFactorsAvailable
// when nothing is reachable, and ErrAmbiguousAutoDiscovery when more
// than one candidate is present at distinct factor types.
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
		// A certificate present in the configured slot of the PIV backend
		// means a PIV login is possible.
		if piv, err := c.piv("auth login auto-discovery"); err == nil && piv != nil {
			backend := pivBackendOr(req.Reader)
			slot := req.Slot
			if slot == "" {
				slot = "9a"
			}
			if cert, cerr := c.pivSlotCertificate(ctx, piv, backend, slot); cerr == nil && cert != nil {
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

// loginMTLS performs an mTLS login over the unified ceremony. Possession
// of the client key is proven by the TLS handshake, so there is no
// in-band signature; the lookup key is the certificate SHA-256 the
// server resolves to the bound user (the server derives the
// authoritative keys — SPKI-first, cert.Raw fallback — from the VERIFIED
// peer certificate, so the client value is advisory).
func (c *Client) loginMTLS(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
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
	auth, err := c.authService("auth login --method mtls")
	if err != nil {
		return nil, err
	}
	begin, err := auth.BeginLogin(ctx, quicbaas.BeginLoginRequest{
		Type:     quicbaas.FactorTypeMTLS,
		Hint:     req.Username,
		TenantID: req.Tenant,
	})
	if err != nil {
		return nil, &ErrLoginFailed{Op: "BeginLogin", Cause: err}
	}
	if begin == nil {
		return nil, &ErrLoginFailed{Op: "BeginLogin", Cause: errors.New("nil begin-login response")}
	}
	metadata := stringifyMetadata(meta)
	metadata["credential_sha256"] = fingerprint
	metadata["cert_path"] = path
	resp, err := auth.FinishLogin(ctx, quicbaas.FinishLoginRequest{
		SessionID:      begin.SessionID,
		Type:           quicbaas.FactorTypeMTLS,
		LookupKey:      rawFingerprint,
		MethodMetadata: metadata,
	})
	if err != nil {
		return nil, &ErrLoginFailed{Op: "FinishLogin", Cause: err}
	}
	return loginResultFrom(resp, req.Username)
}

// loginFIDO2 selects a client-LOCAL authenticator, opens the unified
// ceremony (the server's tenant WebAuthn verifier issues the assertion
// request options), drives the authenticator over CTAP2 to produce the
// assertion, and submits it as the login proof.
//
// The lookup key is the WebAuthn credential id recovered from the
// assertion — the exact key the factor was enrolled under — and the
// assertion JSON rides FinishLoginRequest.Signature, which the server
// verifier accepts when MethodMetadata["assertion"] is absent.
func (c *Client) loginFIDO2(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
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
	auth, err := c.authService("auth login --method fido2")
	if err != nil {
		return nil, err
	}
	begin, err := auth.BeginLogin(ctx, quicbaas.BeginLoginRequest{
		Type:     quicbaas.FactorTypeFIDO2,
		Hint:     req.Username,
		TenantID: req.Tenant,
	})
	if err != nil {
		return nil, &ErrLoginFailed{Op: "BeginLogin", Cause: err}
	}
	optionsJSON, oerr := fido2OptionsFromBegin(begin)
	if oerr != nil {
		return nil, oerr
	}
	assertion, aerr := fido2AssertFunc(ctx, optionsJSON, device.Path, "")
	if aerr != nil {
		return nil, aerr
	}
	credentialID, cerr := fido2CredentialID(assertion)
	if cerr != nil {
		return nil, cerr
	}
	sessionID := ""
	if begin.ChallengeMetadata != nil {
		sessionID = begin.ChallengeMetadata[fido2SessionIDKey]
	}
	resp, err := auth.FinishLogin(ctx, quicbaas.FinishLoginRequest{
		SessionID: begin.SessionID,
		Type:      quicbaas.FactorTypeFIDO2,
		LookupKey: []byte(credentialID),
		Signature: assertion,
		MethodMetadata: map[string]string{
			fido2SessionIDKey:    sessionID,
			fido2CredentialIDKey: credentialID,
			"device_id":          device.Path,
		},
	})
	if err != nil {
		return nil, &ErrLoginFailed{Op: "FinishLogin", Cause: err}
	}
	return loginResultFrom(resp, req.Username)
}

// loginPIV signs the SERVER-issued challenge nonce with the PIV slot key
// and submits the signature as the login proof. Signing the server nonce
// (rather than a client-chosen value) gives the ceremony replay
// protection; the server verifies the signature over SHA-256(nonce)
// against the enrolled certificate.
//
// The primary lookup key is the renewal-stable SHA-256 of the slot
// certificate's SubjectPublicKeyInfo; AltLookupKeys carries the legacy
// SHA-256(cert DER) so factors enrolled before the SPKI index existed
// keep resolving. The lookup keys only locate the factor — possession is
// proven by the signature.
func (c *Client) loginPIV(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	piv, err := c.piv("auth login --method piv")
	if err != nil {
		return nil, err
	}
	backend := pivBackendOr(req.Reader)
	slot := req.Slot
	if slot == "" {
		slot = "9a"
	}
	cert, err := c.pivSlotCertificate(ctx, piv, backend, slot)
	if err != nil {
		return nil, err
	}
	auth, err := c.authService("auth login --method piv")
	if err != nil {
		return nil, err
	}
	begin, err := auth.BeginLogin(ctx, quicbaas.BeginLoginRequest{
		Type:     quicbaas.FactorTypePIV,
		Hint:     req.Username,
		TenantID: req.Tenant,
	})
	if err != nil {
		return nil, &ErrLoginFailed{Op: "BeginLogin", Cause: err}
	}
	if begin == nil || len(begin.Nonce) == 0 {
		return nil, &ErrLoginFailed{Op: "BeginLogin", Cause: errors.New("missing challenge nonce")}
	}
	signature, serr := pivSignNonceFunc(ctx, backend, slot, req.PIN, begin.Nonce)
	if serr != nil {
		return nil, serr
	}
	sum := sha256.Sum256(cert.Raw)
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	resp, err := auth.FinishLogin(ctx, quicbaas.FinishLoginRequest{
		SessionID:     begin.SessionID,
		Type:          quicbaas.FactorTypePIV,
		LookupKey:     spkiSum[:],
		AltLookupKeys: [][]byte{sum[:]},
		Signature:     signature,
		MethodMetadata: map[string]string{
			"backend":     backend,
			"slot":        slot,
			"sign_algo":   pivAlgoFromCert(cert),
			"cert_cn":     cert.Subject.CommonName,
			"cert_serial": cert.SerialNumber.String(),
		},
	})
	if err != nil {
		return nil, &ErrLoginFailed{Op: "FinishLogin", Cause: err}
	}
	return loginResultFrom(resp, req.Username)
}

// fido2OptionsFromBegin extracts the JSON-marshaled WebAuthn request
// options from a BeginLogin response. Returns ErrMissingFIDO2Challenge
// when the server did not issue a WebAuthn challenge (e.g. the tenant
// relying party is not configured).
func fido2OptionsFromBegin(begin *quicbaas.BeginLoginResponse) ([]byte, error) {
	if begin == nil || begin.ChallengeMetadata == nil {
		return nil, &ErrMissingFIDO2Challenge{}
	}
	options := begin.ChallengeMetadata[fido2OptionsKey]
	if options == "" {
		return nil, &ErrMissingFIDO2Challenge{}
	}
	return []byte(options), nil
}

// fido2CredentialID recovers the base64url-encoded WebAuthn credential
// id from a navigator.credentials.get() assertion document. The
// credential id is the FIDO2 factor lookup key.
func fido2CredentialID(assertion []byte) (string, error) {
	var doc struct {
		ID    string `json:"id"`
		RawID string `json:"rawId"`
	}
	if err := json.Unmarshal(assertion, &doc); err != nil {
		return "", &ErrFIDO2AssertionParse{Cause: err}
	}
	credentialID := doc.RawID
	if credentialID == "" {
		credentialID = doc.ID
	}
	if credentialID == "" {
		return "", &ErrFIDO2AssertionParse{Cause: errors.New("assertion carries no credential id (id/rawId)")}
	}
	return credentialID, nil
}

// loginResultFrom projects the unified ceremony's FinishLoginResponse
// onto the platform LoginResult. fallbackUsername fills the identity
// fields when the server returns no resolved identity.
func loginResultFrom(resp *quicbaas.FinishLoginResponse, fallbackUsername string) (*LoginResult, error) {
	if resp == nil || resp.FinishLoginResponse == nil {
		return nil, &ErrLoginFailed{Op: "FinishLogin", Cause: errors.New("nil finish-login response")}
	}
	return newLoginResult(resp.Bearer, resp.RefreshToken, resp.FactorID,
		resp.ExpiresAt, resp.Identity, fallbackUsername), nil
}

// newLoginResult assembles a LoginResult from the unified ceremony's
// response fields. identity may be nil, in which case fallbackUsername
// fills the principal fields.
func newLoginResult(bearer, refreshToken, factorID string, expiresAt time.Time, identity *quicbaas.Identity, fallbackUsername string) *LoginResult {
	result := &LoginResult{
		UserID:       fallbackUsername,
		Username:     fallbackUsername,
		Token:        bearer,
		RefreshToken: refreshToken,
		FactorID:     factorID,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    expiresAt,
	}
	if identity != nil {
		result.UserID = identity.Subject
		result.Username = identity.Subject
		result.TenantID = identity.TenantID
	}
	return result
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

// pivAlgoFromCert returns a PIV signing algorithm name chosen from the
// certificate's public key type. Defaults to "ecdsa" when the type is
// unknown. Reported as login method metadata for audit purposes.
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
