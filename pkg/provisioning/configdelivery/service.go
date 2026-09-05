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

package configdelivery

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	devicewire "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
)

const (
	defaultSessionTTL   = 30 * time.Minute
	defaultPollInterval = 5 // seconds
)

// ProfileResolver resolves device profiles by identity and ID.
// This interface is satisfied by *device.ProfileService.
type ProfileResolver interface {
	// FindConfigForDevice finds a profile for a device using resolution priority:
	// EK serial -> exact MAC -> prefix match rules.
	FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error)

	// Get retrieves a device profile by its ID.
	Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error)
}

// ServiceParams contains the dependencies for creating a config delivery Service.
type ServiceParams struct {
	ProfileService ProfileResolver
	EABService     eab.Service
	NonceStore     *NonceStore
	BaseURL        string
	SessionTTL     time.Duration
	Logger         *logging.Logger

	// RequireEKMatch controls whether a prestaged EK certificate is mandatory
	// for config resolution. A nil value defaults to true (enforce): a matched
	// profile must carry a prestaged EKCert and the device must present a
	// matching EK certificate. Set to a pointer-to-false to opt out (the
	// private-repo escape hatch), which falls back to EK-serial/MAC matching
	// when the matched profile has no prestaged EK certificate.
	RequireEKMatch *bool

	// DBKeySigner backs the remote Secure Boot DB digest-signing endpoint
	// (SignDigest). When nil the sign endpoint returns ErrSignerUnavailable;
	// nonce, config resolution, and session endpoints are unaffected. It is
	// wired in production by the platform daemon's KMS-backed signer.
	DBKeySigner DBKeySigner
}

// Service handles pre-enrollment config delivery for devices.
type Service struct {
	profileService ProfileResolver
	eabService     eab.Service
	nonceStore     *NonceStore
	sessions       map[string]*Session
	sessionsMu     sync.RWMutex
	sessionTTL     time.Duration
	baseURL        string
	requireEKMatch bool
	dbKeySigner    DBKeySigner
	logger         *logging.Logger
}

// NewService creates a new config delivery service.
func NewService(params ServiceParams) (*Service, error) {
	if params.Logger == nil {
		return nil, ErrMissingLogger{}
	}
	// ProfileService and EABService are optional — when nil, config resolution
	// returns ErrMissingProfileService/ErrMissingEABService but nonce and
	// session endpoints still work for the interactive QR provisioning flow.

	sessionTTL := params.SessionTTL
	if sessionTTL == 0 {
		sessionTTL = defaultSessionTTL
	}

	nonceStore := params.NonceStore
	if nonceStore == nil {
		nonceStore = NewNonceStore(defaultNonceTTL)
	}

	// EK matching is enforced by default (secure default). Callers opt out by
	// passing a pointer-to-false from configuration.
	requireEKMatch := true
	if params.RequireEKMatch != nil {
		requireEKMatch = *params.RequireEKMatch
	}

	return &Service{
		profileService: params.ProfileService,
		eabService:     params.EABService,
		nonceStore:     nonceStore,
		sessions:       make(map[string]*Session),
		sessionTTL:     sessionTTL,
		baseURL:        params.BaseURL,
		requireEKMatch: requireEKMatch,
		dbKeySigner:    params.DBKeySigner,
		logger:         params.Logger,
	}, nil
}

// IssueNonce generates a new nonce for a config request.
func (s *Service) IssueNonce() (string, error) {
	nonce, err := s.nonceStore.Issue()
	if err != nil {
		s.logger.Errorf("configdelivery: failed to issue nonce: %v", err)
		return "", err
	}
	s.logger.Debug("configdelivery: nonce issued")
	return nonce, nil
}

// ResolveConfig authenticates the request and resolves the device config.
// Returns ConfigResponse if a matching profile is found, or PendingResponse
// if no match exists (device should display QR code).
func (s *Service) ResolveConfig(ctx context.Context, req *ConfigRequest) (*ConfigResponse, *PendingResponse, error) {
	if err := s.validateRequest(req); err != nil {
		return nil, nil, err
	}

	if err := s.verifyNonceAndEAB(ctx, req.Nonce, req.EABKeyID, req.EABHMAC); err != nil {
		return nil, nil, err
	}

	if s.profileService == nil {
		// No profile service — go directly to pending session
		session := s.CreateSession(req.EKSerial, req.MACAddress)
		pending := &PendingResponse{
			SessionID:    session.ID,
			ProvisionURL: s.provisionURL(session.ID),
			PollInterval: defaultPollInterval,
		}
		return nil, pending, nil
	}

	profile, err := s.profileService.FindConfigForDevice(ctx, req.EKSerial, req.MACAddress)
	if err != nil {
		var noMatch device.ErrNoMatchingConfig
		if errors.As(err, &noMatch) {
			s.logger.Info("configdelivery: no matching profile, creating pending session",
				slog.String("ek_serial", req.EKSerial),
				slog.String("mac_address", req.MACAddress))

			session := s.CreateSession(req.EKSerial, req.MACAddress)
			pending := &PendingResponse{
				SessionID:    session.ID,
				ProvisionURL: s.provisionURL(session.ID),
				PollInterval: defaultPollInterval,
			}
			return nil, pending, nil
		}
		return nil, nil, err
	}

	// Cryptographically bind the resolved config to the device's hardware EK.
	// When a prestaged EK certificate exists (or EK matching is required) the
	// presented EK certificate's public key must match before any config is
	// released. Mismatch or a missing certificate rejects the request.
	if err := s.verifyEKBinding(profile, req.EKCert); err != nil {
		s.logger.Warn("configdelivery: ek binding verification failed",
			slog.Uint64("profile_id", profile.ID),
			slog.String("ek_serial", req.EKSerial),
			slog.String("mac_address", req.MACAddress),
			slog.String("error", err.Error()))
		return nil, nil, err
	}

	s.logger.Info("configdelivery: profile resolved",
		slog.Uint64("profile_id", profile.ID),
		slog.String("ek_serial", req.EKSerial),
		slog.String("mac_address", req.MACAddress))

	return &ConfigResponse{
		Config: profile.Config,
		Status: "ok",
	}, nil, nil
}

// provisionURL builds the pending-session provisioning URL a device polls when
// no config could be auto-resolved. It uses the configured public base URL and
// the canonical provisioning route prefix. When baseURL is empty the result is
// a host-relative path the device resolves against the host it POSTed to.
func (s *Service) provisionURL(sessionID string) string {
	return s.baseURL + "/api/v1/provisioning/sessions/" + sessionID
}

// publicKeyEqualer is satisfied by *rsa.PublicKey, *ecdsa.PublicKey and
// ed25519.PublicKey via their standard-library Equal method.
type publicKeyEqualer interface {
	Equal(crypto.PublicKey) bool
}

// verifyEKBinding enforces the EK-certificate binding policy for a matched
// profile. The presented certificate is the standard-base64 encoding of a
// DER-encoded x509 certificate; the prestaged certificate on the profile is
// PEM-encoded. The two public keys must be equal.
//
// Policy:
//   - profile has a prestaged EKCert: the request MUST present a matching EK
//     certificate (missing -> ErrEKCertRequired, mismatch -> ErrEKCertMismatch).
//   - profile has no prestaged EKCert and requireEKMatch is false: fall back to
//     the EK-serial/MAC match that already resolved this profile (back-compat).
//   - profile has no prestaged EKCert and requireEKMatch is true: reject with
//     ErrEKCertRequired because there is nothing to verify against.
func (s *Service) verifyEKBinding(profile *entities.DeviceProfile, presentedB64DER string) error {
	hasPrestaged := profile != nil && profile.EKCert != ""

	if !hasPrestaged {
		if s.requireEKMatch {
			return ErrEKCertRequired{}
		}
		return nil
	}

	if presentedB64DER == "" {
		return ErrEKCertRequired{}
	}

	prestaged, err := parsePrestagedEKCert(profile.EKCert)
	if err != nil {
		return err
	}
	presented, err := parsePresentedEKCert(presentedB64DER)
	if err != nil {
		return err
	}

	prestagedKey, ok := prestaged.PublicKey.(publicKeyEqualer)
	if !ok {
		return ErrEKCertParseFailed{Cause: ErrUnsupportedEKKeyType{}}
	}
	if !prestagedKey.Equal(presented.PublicKey) {
		return ErrEKCertMismatch{}
	}
	return nil
}

// parsePrestagedEKCert decodes a PEM-encoded EK certificate via the
// canonical entities parser (the same validator every transport DTO seam
// applies at prestage-write time), wrapping failures in the read-side
// ErrEKCertParseFailed error.
func parsePrestagedEKCert(pemData string) (*x509.Certificate, error) {
	cert, err := entities.ParseEKCertPEM(pemData)
	if err != nil {
		return nil, ErrEKCertParseFailed{Cause: err}
	}
	return cert, nil
}

// parsePresentedEKCert decodes a standard-base64-encoded DER EK certificate.
func parsePresentedEKCert(b64DER string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(b64DER)
	if err != nil {
		return nil, ErrEKCertParseFailed{Cause: err}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrEKCertParseFailed{Cause: err}
	}
	return cert, nil
}

// ProvisionBaseURL builds the public base URL (https://host[:port]) used to
// construct pending-session provisioning URLs. It returns "" when host is empty
// or unset (FQDN "."), in which case ProvisionURL falls back to a host-relative
// path. A zero or negative port omits the port component.
func ProvisionBaseURL(host string, port int) string {
	if host == "" || host == "." {
		return ""
	}
	if port > 0 {
		return "https://" + net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "https://" + host
}

// CreateSession creates a new pending provisioning session.
func (s *Service) CreateSession(ekSerial, mac string) *Session {
	now := time.Now().UTC()
	session := &Session{
		ID:         uuid.New().String(),
		EKSerial:   ekSerial,
		MACAddress: mac,
		Fulfilled:  false,
		CreatedAt:  now,
		ExpiresAt:  now.Add(s.sessionTTL),
	}

	s.sessionsMu.Lock()
	s.sessions[session.ID] = session
	s.sessionsMu.Unlock()

	s.logger.Info("configdelivery: session created",
		slog.String("session_id", session.ID),
		slog.String("ek_serial", ekSerial),
		slog.String("mac_address", mac))

	return session
}

// FulfillSession links a profile to a pending session.
func (s *Service) FulfillSession(ctx context.Context, sessionID string, profileID uint64) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound{SessionID: sessionID}
	}

	if time.Now().After(session.ExpiresAt) {
		return ErrSessionExpired{SessionID: sessionID}
	}

	if session.Fulfilled {
		return ErrSessionAlreadyFulfilled{SessionID: sessionID}
	}

	// When profile service is available, fetch the full profile.
	// When nil (integration test mode), fulfill with just the profile ID.
	if s.profileService != nil {
		profile, err := s.profileService.Get(ctx, profileID)
		if err != nil {
			return ErrProfileNotFound{ProfileID: profileID}
		}
		session.Profile = profile
	}

	session.ProfileID = devicewire.ID(profileID)
	session.Fulfilled = true

	s.logger.Info("configdelivery: session fulfilled",
		slog.String("session_id", sessionID),
		slog.Uint64("profile_id", profileID))

	return nil
}

// PollSession checks if a session has been fulfilled.
// Returns the ConfigResponse if fulfilled, nil if still pending.
func (s *Service) PollSession(ctx context.Context, sessionID string) (*ConfigResponse, error) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound{SessionID: sessionID}
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired{SessionID: sessionID}
	}

	if !session.Fulfilled {
		return nil, nil
	}

	// A session fulfilled with a bare profile ID (no profile service wired)
	// carries no resolved profile: there is no configuration to deliver.
	// Surface the invalid state as a typed error instead of dereferencing a
	// nil profile.
	if session.Profile == nil {
		return nil, ErrSessionProfileMissing{SessionID: sessionID}
	}

	return &ConfigResponse{
		Config: session.Profile.Config,
		Status: "ok",
	}, nil
}

// GetSession returns a session by ID.
func (s *Service) GetSession(sessionID string) (*Session, error) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound{SessionID: sessionID}
	}

	return session, nil
}

// ListSessions returns all active (non-expired) sessions.
func (s *Service) ListSessions() []*Session {
	s.cleanupExpiredSessions()

	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	result := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		result = append(result, session)
	}

	return result
}

// cleanupExpiredSessions removes expired sessions from the in-memory store.
// Called inline during session access operations to prevent memory leaks.
func (s *Service) cleanupExpiredSessions() {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	now := time.Now()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
}

// validateRequest checks that all required fields are present in the config
// request, reusing the shared identity-field validation also used by SignDigest.
func (s *Service) validateRequest(req *ConfigRequest) error {
	return validateIdentityFields(req.EKSerial, req.MACAddress, req.EABKeyID, req.EABHMAC, req.Nonce)
}

// verifyNonceAndEAB performs the shared pre-enrollment credential checks used by
// both ResolveConfig and SignDigest: it consumes the single-use nonce and, when
// an EAB service is configured, validates the External Account Binding HMAC.
func (s *Service) verifyNonceAndEAB(ctx context.Context, nonce, eabKeyID, eabHMAC string) error {
	if !s.nonceStore.Validate(nonce) {
		return ErrNonceExpired{}
	}
	if s.eabService != nil {
		hmacKey, err := base64.RawURLEncoding.DecodeString(eabHMAC)
		if err != nil {
			return ErrEABValidationFailed{Cause: err}
		}
		if _, err := s.eabService.Validate(ctx, eabKeyID, hmacKey); err != nil {
			return ErrEABValidationFailed{Cause: err}
		}
	}
	return nil
}
