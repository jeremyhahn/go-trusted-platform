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

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// validFactorTypes is the canonical "--type" set for "auth factor add".
var validFactorTypes = map[string]struct{}{
	"mtls":  {},
	"fido2": {},
	"piv":   {},
}

// validAuthMethods is the canonical "--method" set for "auth login".
var validAuthMethods = map[string]struct{}{
	"mtls":  {},
	"fido2": {},
	"piv":   {},
}

// Service is the platform-level auth service interface.
//
// Implementations dispatch to the quicbaas SDK Security().Auth().Factors()
// surface (M10) which in turn delegates to the qrdb User N-AuthFactor
// service (M14).
type Service interface {
	// AddFactor enrolls a new factor for the active user.
	AddFactor(ctx context.Context, req *AddFactorRequest) (*EnrollmentResult, error)

	// ListFactors lists enrolled factors. user="" lists factors for
	// the calling identity (server-determined).
	ListFactors(ctx context.Context, user string) (*ListResult, error)

	// RemoveFactor revokes an enrollment. force=true allows removing
	// the last remaining factor (admin override).
	RemoveFactor(ctx context.Context, factorID string, force bool) error

	// RotateFactor enrolls a fresh factor and revokes the old one in
	// a single transaction.
	RotateFactor(ctx context.Context, oldID string, req *AddFactorRequest) (*EnrollmentResult, error)

	// RelabelFactor updates a factor's human-readable label.
	RelabelFactor(ctx context.Context, factorID, label string) error

	// Login executes a type-dispatched login.
	Login(ctx context.Context, req *LoginRequest) (*LoginResult, error)

	// Close releases the underlying SDK client.
	Close() error
}

// ClientConfig configures NewClient.
type ClientConfig struct {
	// Address is the quicbaas SDK address (gRPC, unix socket, etc.).
	Address string

	// Options are passed to quicbaas.NewClient.
	Options []quicbaas.Option
}

// Client is the default Service implementation. It owns the
// quicbaas.Client lifecycle.
type Client struct {
	sdk quicbaas.Client
}

// NewClient builds a Client bound to the supplied quicbaas SDK address.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Address == "" {
		return nil, &ErrEmptyAddress{}
	}
	sdk, err := quicbaas.NewClient(cfg.Address, cfg.Options...)
	if err != nil {
		return nil, &ErrSDKConnectFailed{Cause: err}
	}
	return &Client{sdk: sdk}, nil
}

// NewClientFromSDK builds a Client wrapping an existing
// quicbaas.Client. Useful for tests and embedded scenarios.
func NewClientFromSDK(sdk quicbaas.Client) *Client {
	return &Client{sdk: sdk}
}

// Close closes the underlying quicbaas client.
func (c *Client) Close() error {
	if c.sdk == nil {
		return nil
	}
	return c.sdk.Close()
}

// factors resolves the AuthFactorsClient from the M10 extended
// security surface.
func (c *Client) factors(op string) (quicbaas.AuthFactorsClient, error) {
	if c.sdk == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	auth := c.sdk.Security().Auth()
	if auth == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	f := auth.Factors()
	if f == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	return f, nil
}

// webauthn resolves the WebAuthn relying-party client. It is the single
// canonical ceremony accessor (registration + login) — the removed FIDO2()
// accessor duplicated this ceremony and no longer exists.
func (c *Client) webauthn(op string) (quicbaas.WebAuthnClient, error) {
	if c.sdk == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	auth := c.sdk.Security().Auth()
	if auth == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	w := auth.WebAuthn()
	if w == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	return w, nil
}

// devices resolves the client-LOCAL CTAP2 authenticator helper. Unlike the
// WebAuthn ceremony, Devices() enumerates USB-HID authenticators physically
// attached to THIS client and performs no transport request.
func (c *Client) devices(op string) (quicbaas.LocalDevices, error) {
	if c.sdk == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	auth := c.sdk.Security().Auth()
	if auth == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	d := auth.Devices()
	if d == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	return d, nil
}

// piv resolves the PIV sub-client.
func (c *Client) piv(op string) (quicbaas.PIVClient, error) {
	if c.sdk == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	auth := c.sdk.Security().Auth()
	if auth == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	p := auth.PIV()
	if p == nil {
		return nil, &ErrSecuritySurfaceUnavailable{Op: op}
	}
	return p, nil
}

// AddFactor enrolls a new factor.
func (c *Client) AddFactor(ctx context.Context, req *AddFactorRequest) (*EnrollmentResult, error) {
	factors, err := c.factors("auth factor add")
	if err != nil {
		return nil, err
	}
	enroll, err := c.buildEnrollRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return factors.Add(ctx, enroll)
}

// ListFactors returns enrolled factors.
func (c *Client) ListFactors(ctx context.Context, user string) (*ListResult, error) {
	factors, err := c.factors("auth factor list")
	if err != nil {
		return nil, err
	}
	return factors.List(ctx, user)
}

// RemoveFactor revokes a factor enrollment.
func (c *Client) RemoveFactor(ctx context.Context, factorID string, force bool) error {
	if factorID == "" {
		return &ErrMissingFactorID{Op: "auth factor remove"}
	}
	factors, err := c.factors("auth factor remove")
	if err != nil {
		return err
	}
	return factors.Remove(ctx, factorID, force)
}

// RotateFactor performs an atomic rotation.
func (c *Client) RotateFactor(ctx context.Context, oldID string, req *AddFactorRequest) (*EnrollmentResult, error) {
	if oldID == "" {
		return nil, &ErrMissingFactorID{Op: "auth factor rotate"}
	}
	factors, err := c.factors("auth factor rotate")
	if err != nil {
		return nil, err
	}
	enroll, err := c.buildEnrollRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	return factors.Rotate(ctx, oldID, enroll)
}

// RelabelFactor updates a factor's label.
func (c *Client) RelabelFactor(ctx context.Context, factorID, label string) error {
	if factorID == "" {
		return &ErrMissingFactorID{Op: "auth factor relabel"}
	}
	if label == "" {
		return &ErrMissingLabel{Op: "auth factor relabel"}
	}
	factors, err := c.factors("auth factor relabel")
	if err != nil {
		return err
	}
	return factors.Relabel(ctx, factorID, label)
}

// Login executes a type-dispatched login by gathering method-specific
// proof material (mTLS cert fingerprint, FIDO2 assertion, or PIV
// signature) and submitting it via Security().Auth().Factors().Login.
// See login.go for the per-method flow.
func (c *Client) Login(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	return c.dispatchLogin(ctx, req)
}

// buildEnrollRequest validates the canonical add/rotate flag set and
// builds an AuthFactorEnrollRequest with type-specific MethodParams.
func (c *Client) buildEnrollRequest(ctx context.Context, req *AddFactorRequest) (*quicbaas.AuthFactorEnrollRequest, error) {
	if req == nil {
		return nil, &ErrInvalidFactorType{Type: ""}
	}
	if req.Type == "" {
		return nil, &ErrInvalidFactorType{Type: ""}
	}
	if _, ok := validFactorTypes[req.Type]; !ok {
		return nil, &ErrInvalidFactorType{Type: req.Type}
	}
	if req.Label == "" {
		return nil, &ErrMissingLabel{Op: "auth factor add"}
	}

	params := map[string]any{"label": req.Label}

	switch req.Type {
	case "mtls":
		if req.CertPath == "" {
			return nil, &ErrMissingCertPath{}
		}
		fingerprint, certMeta, err := loadCertFingerprintAndMetadata(req.CertPath)
		if err != nil {
			return nil, err
		}
		params["credential_sha256"] = fingerprint
		for k, v := range certMeta {
			params[k] = v
		}
	case "fido2":
		webauthn, err := c.webauthn("auth factor add --type fido2")
		if err != nil {
			return nil, err
		}
		// BeginRegistration is the single canonical registration ceremony
		// (the removed FIDO2().Register accessor was a duplicate). It returns
		// the CredentialCreationOptions the local authenticator consumes.
		regResp, err := webauthn.BeginRegistration(ctx, &quicbaas.WebAuthnUser{
			Username:    req.User,
			DisplayName: req.User,
		})
		if err != nil {
			return nil, &ErrFIDO2Failed{Op: "BeginRegistration", Cause: err}
		}
		params["fido2_credential_create_options"] = regResp
		if req.FIDO2Device != "" {
			params["device_id"] = req.FIDO2Device
		}
	case "piv":
		piv, err := c.piv("auth factor add --type piv")
		if err != nil {
			return nil, err
		}
		reader := req.PIVReader
		if reader == "" {
			readers, err := piv.ListReaders(ctx)
			if err != nil {
				return nil, &ErrPIVFailed{Op: "ListReaders", Cause: err}
			}
			if len(readers.Readers) == 0 {
				return nil, &ErrNoPIVReader{}
			}
			reader = readers.Readers[0].Name
		}
		slot := req.PIVSlot
		if slot == "" {
			slot = "9a"
		}
		cert, err := piv.GetCertificate(ctx, reader, slot)
		if err != nil {
			return nil, &ErrPIVFailed{Op: "GetCertificate", Cause: err}
		}
		sum := sha256.Sum256(cert.Raw)
		params["credential_sha256"] = hex.EncodeToString(sum[:])
		params["reader"] = reader
		params["slot"] = slot
		params["cert_serial"] = cert.SerialNumber.String()
		params["cert_cn"] = cert.Subject.CommonName
		params["cert_not_after"] = cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	}

	subject, err := c.resolveSubject(ctx, req.Tenant, req.User)
	if err != nil {
		return nil, err
	}

	return &quicbaas.AuthFactorEnrollRequest{
		FactorName:   req.Type,
		Subject:      subject,
		TenantID:     req.Tenant,
		MethodParams: params,
	}, nil
}

// resolveSubject converts a CLI-supplied "--user" value into the
// stable user identifier expected by the AuthFactor service Subject
// field. When the value is a username (no "@" sigil), it is resolved
// via the IAM Security().IAM().User().FindByUsername primitive
// (delegating to the qrdb User service). Empty values pass through
// unchanged so the server can apply caller identity.
func (c *Client) resolveSubject(ctx context.Context, tenantID, user string) (string, error) {
	if user == "" {
		return "", nil
	}
	if c.sdk == nil {
		return user, nil
	}
	identity := c.sdk.Identity()
	if identity == nil {
		return user, nil
	}
	iamClient := identity.IAM()
	if iamClient == nil {
		return user, nil
	}
	users := iamClient.User()
	if users == nil {
		return user, nil
	}

	resolved, err := users.FindByUsername(ctx, tenantID, user)
	if err != nil {
		return "", &ErrUsernameLookupFailed{Username: user, Cause: err}
	}
	if resolved == nil || resolved.ID == "" {
		return "", &ErrUsernameLookupFailed{Username: user, Cause: errors.New("nil user record")}
	}
	return resolved.ID, nil
}

// loadCertFingerprintAndMetadata reads a PEM certificate from path,
// computes a hex-encoded SHA-256 fingerprint of the DER bytes, and
// returns selected metadata.
func loadCertFingerprintAndMetadata(path string) (string, map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, &ErrCertRead{Path: path, Cause: err}
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", nil, &ErrCertRead{Path: path, Cause: errors.New("no CERTIFICATE block found")}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, &ErrCertRead{Path: path, Cause: err}
	}
	sum := sha256.Sum256(cert.Raw)
	fingerprint := hex.EncodeToString(sum[:])
	meta := map[string]any{
		"cert_cn":         cert.Subject.CommonName,
		"cert_serial":     cert.SerialNumber.String(),
		"cert_not_after":  cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		"cert_not_before": cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
	}
	return fingerprint, meta, nil
}

// Compile-time check.
var _ Service = (*Client)(nil)
