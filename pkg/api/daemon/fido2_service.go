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

package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// FIDO2 service errors.

// ErrFIDO2NotConfigured indicates the FIDO2 backend is not wired.
var ErrFIDO2NotConfigured = errors.New("fido2: backend not configured")

// ErrFIDO2DeviceRequired indicates the device id argument was empty.
var ErrFIDO2DeviceRequired = errors.New("fido2: device id is required")

// ErrFIDO2UsernameRequired indicates the username was empty.
var ErrFIDO2UsernameRequired = errors.New("fido2: username is required")

// ErrFIDO2CredentialRequired indicates the credential id was empty.
var ErrFIDO2CredentialRequired = errors.New("fido2: credential id is required")

// FIDO2Role enumerates ceremony roles a WebAuthn credential binds to.
type FIDO2Role string

const (
	// FIDO2RoleUnspecified indicates no role.
	FIDO2RoleUnspecified FIDO2Role = ""
	// FIDO2RoleSO is the Security Officer role.
	FIDO2RoleSO FIDO2Role = "so"
	// FIDO2RoleAdmin is the Admin officer role.
	FIDO2RoleAdmin FIDO2Role = "admin"
	// FIDO2RoleUser is the User officer role.
	FIDO2RoleUser FIDO2Role = "user"
)

// FIDO2Device describes a FIDO2 authenticator.
type FIDO2Device struct {
	ID           string
	Path         string
	Manufacturer string
	Product      string
	ProductID    uint32
	VendorID     uint32
}

// FIDO2Info describes an authenticator's capabilities.
type FIDO2Info struct {
	Device          FIDO2Device
	AAGUID          string
	FirmwareVersion string
	Extensions      []string
	Options         map[string]bool
	MaxMsgSize      uint32
}

// FIDO2RegisterRequest registers a WebAuthn credential.
type FIDO2RegisterRequest struct {
	Username   string
	Role       FIDO2Role
	RequirePIN bool
	RequireUV  bool
	RPID       string
}

// FIDO2RegisterResult is returned by Register.
type FIDO2RegisterResult struct {
	CredentialID string
	AAGUID       string
	PublicKeyPEM string
}

// FIDO2AuthenticateResult is returned by Authenticate.
type FIDO2AuthenticateResult struct {
	Authenticated bool
	Counter       uint32
}

// FIDO2Backend abstracts the upstream FIDO2 / WebAuthn implementation.
type FIDO2Backend interface {
	ListDevices(ctx context.Context) ([]FIDO2Device, error)
	WaitDevice(ctx context.Context, timeout time.Duration) (*FIDO2Device, error)
	Info(ctx context.Context, device string) (*FIDO2Info, error)
	Register(ctx context.Context, req *FIDO2RegisterRequest) (*FIDO2RegisterResult, error)
	Authenticate(ctx context.Context, credentialID string) (*FIDO2AuthenticateResult, error)
}

// FIDO2Service is the platformd-side FIDO2 business-logic layer.
type FIDO2Service struct {
	logger  *logging.Logger
	backend FIDO2Backend

	mu sync.RWMutex
}

// NewFIDO2Service constructs a new FIDO2 service.
func NewFIDO2Service(logger *logging.Logger, backend FIDO2Backend) *FIDO2Service {
	return &FIDO2Service{logger: logger, backend: backend}
}

// Backend returns the configured backend.
func (s *FIDO2Service) Backend() FIDO2Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend
}

// SetBackend replaces the configured backend.
func (s *FIDO2Service) SetBackend(b FIDO2Backend) {
	s.mu.Lock()
	s.backend = b
	s.mu.Unlock()
}

// ListDevices delegates to the backend.
func (s *FIDO2Service) ListDevices(ctx context.Context) ([]FIDO2Device, error) {
	b := s.Backend()
	if b == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return b.ListDevices(ctx)
}

// WaitDevice delegates to the backend.
func (s *FIDO2Service) WaitDevice(ctx context.Context, timeout time.Duration) (*FIDO2Device, error) {
	b := s.Backend()
	if b == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return b.WaitDevice(ctx, timeout)
}

// Info delegates to the backend.
func (s *FIDO2Service) Info(ctx context.Context, device string) (*FIDO2Info, error) {
	if device == "" {
		return nil, ErrFIDO2DeviceRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return b.Info(ctx, device)
}

// Register delegates to the backend.
func (s *FIDO2Service) Register(ctx context.Context, req *FIDO2RegisterRequest) (*FIDO2RegisterResult, error) {
	if req == nil || req.Username == "" {
		return nil, ErrFIDO2UsernameRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return b.Register(ctx, req)
}

// Authenticate delegates to the backend.
func (s *FIDO2Service) Authenticate(ctx context.Context, credentialID string) (*FIDO2AuthenticateResult, error) {
	if credentialID == "" {
		return nil, ErrFIDO2CredentialRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrFIDO2NotConfigured
	}
	return b.Authenticate(ctx, credentialID)
}
