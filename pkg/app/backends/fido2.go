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

package backends

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// FIDO2 backend typed errors.

// ErrFIDO2DeviceNotFound indicates no matching authenticator was found.
var ErrFIDO2DeviceNotFound = errors.New("fido2 backend: device not found")

// ErrFIDO2HandlerUnavailable indicates the underlying CTAP2 handler could not
// be created (typically because no HID enumerator is wired).
var ErrFIDO2HandlerUnavailable = errors.New("fido2 backend: ctap2 handler not available")

// ErrFIDO2AuthenticateNotWired indicates that the backend has no credential
// store to look up the credential against. Authentication requires an
// external WebAuthn service which the daemon must inject.
var ErrFIDO2AuthenticateNotWired = errors.New("fido2 backend: webauthn credential store not configured")

// FIDO2CredentialStore is the narrow surface the backend needs to look up a
// stored WebAuthn credential by id. Implementations typically wrap the
// platform's WebAuthn credential table.
type FIDO2CredentialStore interface {
	LookupCredential(ctx context.Context, credentialID string) (*FIDO2CredentialRecord, error)
}

// FIDO2CredentialRecord is the minimum data we need to re-issue a challenge
// against a stored credential.
type FIDO2CredentialRecord struct {
	CredentialID []byte
	RPID         string
	AAGUID       string
	UserID       []byte
	UserName     string
	PublicKeyPEM string
	SignCount    uint32
}

// FIDO2Backend implements daemon.FIDO2Backend by delegating to the go-xkms
// FIDO2 + WebAuthn stacks. CTAP2 operations require a live HID authenticator,
// so the backend is expected to be initialised with a real enumerator when
// deployed on hardware and a mock enumerator in tests.
type FIDO2Backend struct {
	logger     *logging.Logger
	handler    *fido2.FIDO2Handler
	config     *fido2.Config
	credStore  FIDO2CredentialStore
	pollTicker time.Duration
}

// Compile-time assertion.
var _ daemon.FIDO2Backend = (*FIDO2Backend)(nil)

// NewFIDO2Backend constructs a backend. When cfg is nil the package-default
// config is used. When enumerator is nil the backend will lazy-create the
// default Linux HID enumerator at first use.
func NewFIDO2Backend(logger *logging.Logger, cfg *fido2.Config, enumerator fido2.HIDDeviceEnumerator) (*FIDO2Backend, error) {
	if cfg == nil {
		defaultCfg := fido2.DefaultConfig
		cfg = &defaultCfg
	}
	enum := enumerator
	if enum == nil {
		enum = fido2.NewDefaultEnumerator()
	}
	handler, err := fido2.NewHandler(cfg, enum)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFIDO2HandlerUnavailable, err)
	}
	return &FIDO2Backend{
		logger:     logger,
		handler:    handler,
		config:     cfg,
		pollTicker: 250 * time.Millisecond,
	}, nil
}

// SetCredentialStore injects the credential lookup implementation used by
// Authenticate.
func (b *FIDO2Backend) SetCredentialStore(s FIDO2CredentialStore) {
	b.credStore = s
}

// XKMSHandler returns the underlying go-xkms FIDO2 Handler so callers can
// share it with adjacent subsystems (e.g. LUKS) without creating a second
// authenticator connection. Returns nil when the backend was constructed
// without a live handler.
func (b *FIDO2Backend) XKMSHandler() fido2.Handler {
	if b.handler == nil {
		return nil
	}
	return b.handler
}

// XKMSConfig returns the FIDO2 configuration active on this backend.
func (b *FIDO2Backend) XKMSConfig() *fido2.Config {
	return b.config
}

// Close releases the CTAP2 handler resources.
func (b *FIDO2Backend) Close() error {
	if b.handler == nil {
		return nil
	}
	return b.handler.Close()
}

// ListDevices returns all attached FIDO2 authenticators.
func (b *FIDO2Backend) ListDevices(ctx context.Context) ([]daemon.FIDO2Device, error) {
	if b.handler == nil {
		return nil, ErrFIDO2HandlerUnavailable
	}
	devs, err := b.handler.ListDevices()
	if err != nil {
		return nil, err
	}
	out := make([]daemon.FIDO2Device, 0, len(devs))
	for _, d := range devs {
		out = append(out, fido2DeviceFromXKMS(d))
	}
	return out, nil
}

// WaitDevice blocks until a device appears or the context / timeout expires.
// The upstream handler already implements a polling loop; we just bound it
// with a context deadline derived from `timeout`.
func (b *FIDO2Backend) WaitDevice(ctx context.Context, timeout time.Duration) (*daemon.FIDO2Device, error) {
	if b.handler == nil {
		return nil, ErrFIDO2HandlerUnavailable
	}
	waitCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	dev, err := b.handler.WaitForDevice(waitCtx)
	if err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, ErrFIDO2DeviceNotFound
	}
	mapped := fido2DeviceFromXKMS(*dev)
	return &mapped, nil
}

// Info enumerates devices, matches the requested id, opens the CTAP2 channel
// and returns the authenticator info.
func (b *FIDO2Backend) Info(ctx context.Context, device string) (*daemon.FIDO2Info, error) {
	if b.handler == nil {
		return nil, ErrFIDO2HandlerUnavailable
	}
	devs, err := b.handler.ListDevices()
	if err != nil {
		return nil, err
	}
	var match *fido2.Device
	for i := range devs {
		if devs[i].Path == device || deviceIDForXKMS(devs[i]) == device {
			match = &devs[i]
			break
		}
	}
	if match == nil {
		return nil, ErrFIDO2DeviceNotFound
	}

	// Open the device and ask for authenticator info.
	enum := fido2.NewDefaultEnumerator()
	hidDev, err := enum.Open(match.Path)
	if err != nil {
		return nil, err
	}
	ctap, err := fido2.NewCTAPHIDDevice(hidDev, b.config)
	if err != nil {
		_ = hidDev.Close()
		return nil, err
	}
	defer func() { _ = ctap.Close() }()

	auth, err := fido2.NewAuthenticator(ctap, b.config)
	if err != nil {
		return nil, err
	}
	info, err := auth.GetInfo()
	if err != nil {
		return nil, err
	}

	return &daemon.FIDO2Info{
		Device:          fido2DeviceFromXKMS(*match),
		AAGUID:          hex.EncodeToString(info.AAGUID),
		FirmwareVersion: fmt.Sprintf("%d", info.FirmwareVersion),
		Extensions:      append([]string(nil), info.Extensions...),
		Options:         copyFIDO2Options(info.Options),
		MaxMsgSize:      uint32(info.MaxMsgSize),
	}, nil
}

// Register enrolls a new credential against the given user. A fresh salt is
// generated so the same authenticator can be re-enrolled for multiple uses.
func (b *FIDO2Backend) Register(ctx context.Context, req *daemon.FIDO2RegisterRequest) (*daemon.FIDO2RegisterResult, error) {
	if b.handler == nil {
		return nil, ErrFIDO2HandlerUnavailable
	}

	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("fido2 backend: generate salt: %w", err)
	}

	userID := make([]byte, 16)
	if _, err := rand.Read(userID); err != nil {
		return nil, fmt.Errorf("fido2 backend: generate user id: %w", err)
	}

	cfg := fido2.DefaultEnrollmentConfig(req.Username)
	cfg.Salt = salt
	cfg.User = fido2.User{
		ID:          userID,
		Name:        req.Username,
		DisplayName: req.Username,
	}
	if req.RPID != "" {
		cfg.RelyingParty.ID = req.RPID
	}
	cfg.RequireUserVerification = req.RequireUV

	result, err := b.handler.EnrollKey(cfg)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrFIDO2DeviceNotFound
	}

	return &daemon.FIDO2RegisterResult{
		CredentialID: hex.EncodeToString(result.CredentialID),
		AAGUID:       hex.EncodeToString(result.AAGUID),
		PublicKeyPEM: hex.EncodeToString(result.PublicKey),
	}, nil
}

// Authenticate runs a GetAssertion against the stored credential and reports
// success / updated sign count.
func (b *FIDO2Backend) Authenticate(ctx context.Context, credentialID string) (*daemon.FIDO2AuthenticateResult, error) {
	if b.handler == nil {
		return nil, ErrFIDO2HandlerUnavailable
	}
	if b.credStore == nil {
		return nil, ErrFIDO2AuthenticateNotWired
	}
	record, err := b.credStore.LookupCredential(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, ErrFIDO2DeviceNotFound
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	authCfg := fido2.DefaultAuthenticationConfig(record.CredentialID, salt)
	authCfg.RelyingPartyID = record.RPID
	authCfg.Challenge = challenge
	authCfg.RequireUserVerification = false

	// UnlockWithKey returns the derived key on success; we don't need the
	// actual bytes here, just that it did not error.
	if _, err := b.handler.UnlockWithKey(authCfg); err != nil {
		return &daemon.FIDO2AuthenticateResult{Authenticated: false}, err
	}
	return &daemon.FIDO2AuthenticateResult{
		Authenticated: true,
		Counter:       record.SignCount,
	}, nil
}

// fido2DeviceFromXKMS maps an xkms FIDO2 Device to the service-layer shape.
func fido2DeviceFromXKMS(d fido2.Device) daemon.FIDO2Device {
	return daemon.FIDO2Device{
		ID:           deviceIDForXKMS(d),
		Path:         d.Path,
		Manufacturer: d.Manufacturer,
		Product:      d.Product,
		ProductID:    uint32(d.ProductID),
		VendorID:     uint32(d.VendorID),
	}
}

// deviceIDForXKMS returns a stable device id for an xkms fido2.Device. We
// prefer the serial number when present (stable across re-plugs); otherwise
// fall back to path.
func deviceIDForXKMS(d fido2.Device) string {
	if d.SerialNumber != "" {
		return d.SerialNumber
	}
	return d.Path
}

// copyFIDO2Options shallow-copies the options map so consumers can mutate
// without racing the authenticator cache.
func copyFIDO2Options(in map[string]bool) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
