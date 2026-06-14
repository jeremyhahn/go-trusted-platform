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

package service

import (
	"context"
	"strconv"
)

// AttestationObserver is notified of attestation verification outcomes.
// Implementations drive the quarantine loop: a failed verification emits a
// ViolationEvent; a successful re-attestation triggers restore.
//
// Observers are registered on the Service via RegisterObserver and called
// synchronously inside VerifyManifest after the verification result is
// computed. Observers must not block; move slow work to a goroutine.
type AttestationObserver interface {
	// OnAttestationFailed is called when manifest verification fails.
	// deviceID identifies the platform device record associated with hostID.
	// The observer is responsible for determining severity based on the
	// VerificationResult details.
	OnAttestationFailed(ctx context.Context, deviceID uint64, hostID, detail string)

	// OnAttestationPassed is called when manifest verification succeeds.
	// It is the trigger for the quarantine restore path.
	OnAttestationPassed(ctx context.Context, deviceID uint64, hostID string)
}

// DeviceResolver maps a host identifier (CN / HostID from the manifest) to
// the platform device record so the service can supply a typed device ID to
// observers without coupling directly to the datastore layer.
type DeviceResolver interface {
	// DeviceForHost returns the device ID for the given host identifier.
	// Returns (0, false) when no device is found.
	DeviceForHost(hostID string) (deviceID uint64, ok bool)
}

// RegisterObserver adds observer to the set notified on every VerifyManifest
// call. Observers are called in registration order. This method is safe to
// call before or after the service handles its first verification.
func (s *Service) RegisterObserver(obs AttestationObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observers = append(s.observers, obs)
}

// SetDeviceResolver installs the DeviceResolver used to map manifest HostIDs
// to platform device records. When nil (the default), observer callbacks
// receive deviceID=0 which consumers must handle gracefully.
func (s *Service) SetDeviceResolver(r DeviceResolver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deviceResolver = r
}

// notifyObservers dispatches the attestation outcome to all registered
// observers. It is called inside VerifyManifest after the result is final.
func (s *Service) notifyObservers(ctx context.Context, hostID string, passed bool, detail string) {
	s.mu.RLock()
	obs := s.observers
	resolver := s.deviceResolver
	s.mu.RUnlock()

	if len(obs) == 0 {
		return
	}

	deviceID := uint64(0)
	if resolver != nil {
		if id, ok := resolver.DeviceForHost(hostID); ok {
			deviceID = id
		}
	}

	for _, o := range obs {
		if passed {
			o.OnAttestationPassed(ctx, deviceID, hostID)
		} else {
			o.OnAttestationFailed(ctx, deviceID, hostID, detail)
		}
	}
}

// attestationDetail builds a human-readable summary from the first errors in
// the VerificationResult's Errors slice.
func attestationDetail(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return errs[0] + " (+" + strconv.Itoa(len(errs)-1) + " more)"
}
