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
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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

	return &Service{
		profileService: params.ProfileService,
		eabService:     params.EABService,
		nonceStore:     nonceStore,
		sessions:       make(map[string]*Session),
		sessionTTL:     sessionTTL,
		baseURL:        params.BaseURL,
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

	if !s.nonceStore.Validate(req.Nonce) {
		return nil, nil, ErrNonceExpired{}
	}

	if s.eabService != nil {
		hmacKey, err := base64.RawURLEncoding.DecodeString(req.EABHMAC)
		if err != nil {
			return nil, nil, ErrEABValidationFailed{Cause: err}
		}
		if _, err := s.eabService.Validate(ctx, req.EABKeyID, hmacKey); err != nil {
			return nil, nil, ErrEABValidationFailed{Cause: err}
		}
	}

	if s.profileService == nil {
		// No profile service — go directly to pending session
		session := s.CreateSession(req.EKSerial, req.MACAddress)
		pending := &PendingResponse{
			SessionID:    session.ID,
			ProvisionURL: s.baseURL + "/provision/sessions/" + session.ID,
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
				ProvisionURL: s.baseURL + "/provision/sessions/" + session.ID,
				PollInterval: defaultPollInterval,
			}
			return nil, pending, nil
		}
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

	session.ProfileID = profileID
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

// validateRequest checks that all required fields are present in the config request.
func (s *Service) validateRequest(req *ConfigRequest) error {
	if req.EABKeyID == "" {
		return ErrInvalidRequest{Reason: "eab_key_id is required"}
	}
	if req.EABHMAC == "" {
		return ErrInvalidRequest{Reason: "eab_hmac is required"}
	}
	if req.Nonce == "" {
		return ErrNonceRequired{}
	}
	if req.EKSerial == "" && req.MACAddress == "" {
		return ErrInvalidRequest{Reason: "at least one of ek_serial or mac_address is required"}
	}
	return nil
}
