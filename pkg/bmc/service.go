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

package bmc

import (
	"context"
	"log/slog"
	"sync"
)

// Service manages BMC client lifecycle and provides the business logic layer.
type Service struct {
	clients  sync.Map // map[uint64]Client
	factory  ClientFactory
	profiles ProfileStore
	logger   *slog.Logger
}

// ServiceParams holds dependencies for creating a BMC Service.
type ServiceParams struct {
	Factory  ClientFactory
	Profiles ProfileStore
	Logger   *slog.Logger
}

// NewService creates a new BMC service with the given dependencies.
func NewService(params ServiceParams) (*Service, error) {
	if params.Factory == nil {
		return nil, ErrInvalidConfig{Reason: "client factory is required"}
	}
	// Profiles is optional — when nil, callers must provide BMC config directly
	// via ConnectDirect() instead of using profile-based methods.
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		factory:  params.Factory,
		profiles: params.Profiles,
		logger:   logger,
	}, nil
}

// clientFor returns a cached BMC client for the given profile ID,
// creating one if it does not already exist.
func (s *Service) clientFor(ctx context.Context, profileID uint64) (Client, error) {
	if existing, ok := s.clients.Load(profileID); ok {
		return existing.(Client), nil
	}

	config, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}

	client, err := s.factory.NewClient(config)
	if err != nil {
		return nil, err
	}

	// Use LoadOrStore to handle concurrent creation for the same profile.
	actual, _ := s.clients.LoadOrStore(profileID, client)
	if actual != client {
		// Another goroutine created the client first; close ours.
		closeErr := client.Close()
		if closeErr != nil {
			s.logger.Warn("bmc: failed to close duplicate client",
				slog.Uint64("profile_id", profileID),
				slog.String("error", closeErr.Error()))
		}
	}
	return actual.(Client), nil
}

// PowerOn powers on the system identified by the given profile ID.
func (s *Service) PowerOn(ctx context.Context, profileID uint64) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.PowerOn(ctx)
}

// PowerOff powers off the system identified by the given profile ID.
func (s *Service) PowerOff(ctx context.Context, profileID uint64) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.PowerOff(ctx)
}

// PowerReset performs a hard reset on the system identified by the given profile ID.
func (s *Service) PowerReset(ctx context.Context, profileID uint64) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.PowerReset(ctx)
}

// PowerCycle power cycles the system identified by the given profile ID.
func (s *Service) PowerCycle(ctx context.Context, profileID uint64) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.PowerCycle(ctx)
}

// PowerStatus returns the power state of the system identified by the given profile ID.
func (s *Service) PowerStatus(ctx context.Context, profileID uint64) (PowerState, error) {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return PowerStateUnknown, err
	}
	return client.PowerStatus(ctx)
}

// SetBootDevice sets the boot device for the system identified by the given profile ID.
func (s *Service) SetBootDevice(ctx context.Context, profileID uint64, device BootDevice, persistent bool) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.SetBootDevice(ctx, device, persistent)
}

// GetBootDevice returns the boot device override for the system identified by the given profile ID.
func (s *Service) GetBootDevice(ctx context.Context, profileID uint64) (BootDevice, error) {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return BootDeviceNone, err
	}
	return client.GetBootDevice(ctx)
}

// MountISO mounts an ISO image on the system identified by the given profile ID.
func (s *Service) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.MountISO(ctx, isoURL)
}

// UnmountISO unmounts virtual media on the system identified by the given profile ID.
func (s *Service) UnmountISO(ctx context.Context, profileID uint64) error {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return err
	}
	return client.UnmountISO(ctx)
}

// VirtualMediaStatus returns virtual media state for the system identified by the given profile ID.
func (s *Service) VirtualMediaStatus(ctx context.Context, profileID uint64) (*VirtualMediaInfo, error) {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return client.VirtualMediaStatus(ctx)
}

// GetSensors returns sensor readings from the system identified by the given profile ID.
func (s *Service) GetSensors(ctx context.Context, profileID uint64) ([]SensorReading, error) {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return client.GetSensors(ctx)
}

// GetSystemInfo returns system info from the system identified by the given profile ID.
func (s *Service) GetSystemInfo(ctx context.Context, profileID uint64) (*SystemInfo, error) {
	client, err := s.clientFor(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return client.GetSystemInfo(ctx)
}

// Close closes all cached BMC clients and removes them from the cache.
func (s *Service) Close() error {
	var firstErr error
	s.clients.Range(func(key, value any) bool {
		client := value.(Client)
		if err := client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.clients.Delete(key)
		return true
	})
	return firstErr
}
