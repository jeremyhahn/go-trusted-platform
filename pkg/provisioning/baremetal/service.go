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

package baremetal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// provisionState holds the mutable state for a single provision.
type provisionState struct {
	result      atomic.Pointer[ProvisionResult]
	installDone chan struct{}
}

// Service orchestrates bare metal provisioning via BMC.
type Service struct {
	bmc        BMCOperator
	profiles   ProfileChecker
	config     *Config
	provisions sync.Map // map[string]*provisionState
	inFlight   sync.Map // map[uint64]string (profileID -> provisionID)
	logger     *slog.Logger
}

// ServiceParams holds dependencies for creating a provisioning Service.
type ServiceParams struct {
	BMC      BMCOperator
	Profiles ProfileChecker
	Config   *Config
	Logger   *slog.Logger
}

// NewService creates a new bare metal provisioning service.
func NewService(params ServiceParams) (*Service, error) {
	if params.BMC == nil {
		return nil, ErrInvalidProvisionRequest{Reason: "BMC operator is required"}
	}
	if params.Profiles == nil {
		return nil, ErrInvalidProvisionRequest{Reason: "profile checker is required"}
	}
	config := params.Config
	if config == nil {
		config = DefaultConfig()
	}
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		bmc:      params.BMC,
		profiles: params.Profiles,
		config:   config,
		logger:   logger,
	}, nil
}

// Provision starts an asynchronous bare metal provisioning workflow.
// It returns immediately with the provision ID; callers poll Status or
// call CompleteInstall to advance through the installation phase.
func (s *Service) Provision(ctx context.Context, req *ProvisionRequest) (*ProvisionResult, error) {
	if req == nil {
		return nil, ErrInvalidProvisionRequest{Reason: "request is nil"}
	}
	if req.ProfileID == 0 {
		return nil, ErrInvalidProvisionRequest{Reason: "profile ID is required"}
	}

	// Verify the profile exists.
	if _, err := s.profiles.Get(ctx, req.ProfileID); err != nil {
		return nil, ErrProfileNoBMC{ProfileID: req.ProfileID}
	}

	// Reject if a provision is already running for this profile.
	if _, loaded := s.inFlight.Load(req.ProfileID); loaded {
		return nil, ErrProvisionInProgress{ProfileID: req.ProfileID}
	}

	provisionID, err := generateID()
	if err != nil {
		return nil, ErrProvisionFailed{ProfileID: req.ProfileID, Step: "generate_id", Cause: err}
	}

	now := time.Now().UTC()
	result := &ProvisionResult{
		ProvisionID: provisionID,
		ProfileID:   req.ProfileID,
		Status:      StatusPending,
		StartedAt:   now,
		UpdatedAt:   now,
	}

	state := &provisionState{
		installDone: make(chan struct{}),
	}
	state.result.Store(result)

	// Atomically claim the in-flight slot for this profile.
	if _, loaded := s.inFlight.LoadOrStore(req.ProfileID, provisionID); loaded {
		return nil, ErrProvisionInProgress{ProfileID: req.ProfileID}
	}

	s.provisions.Store(provisionID, state)

	go s.runProvision(provisionID, req)

	return result, nil
}

// Status returns the current state of a provision.
func (s *Service) Status(provisionID string) (*ProvisionResult, error) {
	state, err := s.loadState(provisionID)
	if err != nil {
		return nil, err
	}
	return state.result.Load(), nil
}

// List returns all tracked provisions.
func (s *Service) List() []*ProvisionResult {
	var results []*ProvisionResult
	s.provisions.Range(func(_, value any) bool {
		state := value.(*provisionState)
		results = append(results, state.result.Load())
		return true
	})
	return results
}

// CompleteInstall signals that OS installation has finished, allowing
// the provisioning workflow to proceed to finalization.
func (s *Service) CompleteInstall(provisionID string) error {
	state, err := s.loadState(provisionID)
	if err != nil {
		return err
	}

	current := state.result.Load()
	if current.Status != StatusInstalling {
		return ErrProvisionFailed{
			ProfileID: current.ProfileID,
			Step:      "complete_install",
			Cause:     ErrInvalidProvisionRequest{Reason: "provision is not in installing state"},
		}
	}

	// Signal the install goroutine. Close is idempotent only on the first call;
	// use select to guard against double-close.
	select {
	case <-state.installDone:
		// Already closed.
	default:
		close(state.installDone)
	}
	return nil
}

// runProvision executes the provisioning steps sequentially in a goroutine.
func (s *Service) runProvision(provisionID string, req *ProvisionRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), s.config.InstallTimeout)
	defer cancel()

	profileID := req.ProfileID
	hasISO := req.ISOURL != ""

	state, err := s.loadState(provisionID)
	if err != nil {
		return
	}

	steps := []struct {
		name   string
		status ProvisioningStatus
		fn     func(context.Context) error
	}{
		{
			name:   "check_power",
			status: StatusConnecting,
			fn: func(ctx context.Context) error {
				_, err := s.bmc.PowerStatus(ctx, profileID)
				return err
			},
		},
		{
			name:   "power_off",
			status: StatusConnecting,
			fn: func(ctx context.Context) error {
				power, err := s.bmc.PowerStatus(ctx, profileID)
				if err != nil {
					return err
				}
				if power == bmc.PowerStateOn {
					return s.bmc.PowerOff(ctx, profileID)
				}
				return nil
			},
		},
		{
			name:   "set_boot_device",
			status: StatusSettingBoot,
			fn: func(ctx context.Context) error {
				device := bmc.BootDevicePXE
				if hasISO {
					device = bmc.BootDeviceVirtualMedia
				}
				return s.bmc.SetBootDevice(ctx, profileID, device, false)
			},
		},
		{
			name:   "mount_iso",
			status: StatusMountingISO,
			fn: func(ctx context.Context) error {
				if !hasISO {
					return nil
				}
				return s.bmc.MountISO(ctx, profileID, req.ISOURL)
			},
		},
		{
			name:   "power_on",
			status: StatusPoweringOn,
			fn: func(ctx context.Context) error {
				return s.bmc.PowerOn(ctx, profileID)
			},
		},
		{
			name:   "wait_install",
			status: StatusInstalling,
			fn: func(ctx context.Context) error {
				select {
				case <-state.installDone:
					return nil
				case <-ctx.Done():
					return ErrInstallTimeout{ProfileID: profileID, Timeout: s.config.InstallTimeout}
				}
			},
		},
		{
			name:   "unmount_iso",
			status: StatusFinalizing,
			fn: func(ctx context.Context) error {
				if !hasISO {
					return nil
				}
				return s.bmc.UnmountISO(ctx, profileID)
			},
		},
		{
			name:   "set_boot_disk",
			status: StatusFinalizing,
			fn: func(ctx context.Context) error {
				return s.bmc.SetBootDevice(ctx, profileID, bmc.BootDeviceDisk, true)
			},
		},
		{
			name:   "power_cycle",
			status: StatusFinalizing,
			fn: func(ctx context.Context) error {
				return s.bmc.PowerCycle(ctx, profileID)
			},
		},
	}

	for _, step := range steps {
		s.updateStatus(provisionID, step.status, "")
		s.logger.Info("baremetal: running provisioning step",
			slog.String("provision_id", provisionID),
			slog.String("step", step.name),
			slog.String("status", string(step.status)))

		if err := step.fn(ctx); err != nil {
			s.logger.Error("baremetal: provisioning step failed",
				slog.String("provision_id", provisionID),
				slog.String("step", step.name),
				slog.String("error", err.Error()))
			// Release in-flight before setting terminal status so callers
			// that observe the status can immediately re-provision.
			s.inFlight.Delete(profileID)
			s.updateStatus(provisionID, StatusFailed, step.name+": "+err.Error())
			return
		}
	}

	// Release in-flight before setting terminal status.
	s.inFlight.Delete(profileID)
	s.updateStatus(provisionID, StatusComplete, "")

	s.logger.Info("baremetal: provisioning complete",
		slog.String("provision_id", provisionID),
		slog.Uint64("profile_id", profileID))
}

// updateStatus atomically replaces the provision result with an updated status.
func (s *Service) updateStatus(provisionID string, status ProvisioningStatus, message string) {
	val, ok := s.provisions.Load(provisionID)
	if !ok {
		return
	}
	state := val.(*provisionState)
	current := state.result.Load()
	updated := &ProvisionResult{
		ProvisionID: current.ProvisionID,
		ProfileID:   current.ProfileID,
		Status:      status,
		Message:     message,
		StartedAt:   current.StartedAt,
		UpdatedAt:   time.Now().UTC(),
	}
	state.result.Store(updated)
}

// loadState retrieves the provisionState or returns ErrProvisionNotFound.
func (s *Service) loadState(provisionID string) (*provisionState, error) {
	val, ok := s.provisions.Load(provisionID)
	if !ok {
		return nil, ErrProvisionNotFound{ProvisionID: provisionID}
	}
	return val.(*provisionState), nil
}

// generateID produces a 16-byte random hex provision ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
