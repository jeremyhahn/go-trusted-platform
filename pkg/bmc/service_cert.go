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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// certManagerFor builds a CertificateManager for the given profile. The
// returned manager is per-call (not cached) because cert managers own
// short-lived TLS state and may run vendor probes lazily.
//
// Callers that obtain a ManagedCertificateManager via this helper must
// Close it when finished to release any open backend resources.
func (s *Service) certManagerFor(ctx context.Context, profileID uint64) (ManagedCertificateManager, error) {
	if s.profiles == nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}
	cfg, err := s.profiles.Get(ctx, profileID)
	if err != nil {
		return nil, ErrProfileNotFound{ProfileID: profileID}
	}
	backend := cfg.Backend
	if backend == "" {
		backend = CertBackendAuto
	}
	return NewAutoCertManager(cfg, backend, s.logger)
}

// GetWebCertificate returns metadata describing the certificate
// currently presented by the BMC's HTTPS interface for the given
// profile.
func (s *Service) GetWebCertificate(ctx context.Context, profileID uint64) (*CertificateInfo, error) {
	mgr, err := s.certManagerFor(ctx, profileID)
	if err != nil {
		return nil, err
	}
	defer mgr.Close()

	cert, err := mgr.GetWebCertificate(ctx)
	if err != nil {
		return nil, err
	}
	return NewCertificateInfo(cert, time.Now().UTC()), nil
}

// ReplaceWebCertificate uploads certPEM and keyPEM to the BMC identified
// by profileID. The keyPEM bytes are wrapped in a *memguard.MemoryEnclave for
// the duration of the operation. The caller's keyPEM slice is NOT
// scrubbed by this method — callers responsible for sensitive material
// should zero it after the call returns.
func (s *Service) ReplaceWebCertificate(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) error {
	mgr, err := s.certManagerFor(ctx, profileID)
	if err != nil {
		return err
	}
	defer mgr.Close()

	keySecret := memguard.NewMemoryEnclave(append([]byte(nil), keyPEM...))
	defer keySecret.Destroy()

	return mgr.ReplaceWebCertificate(ctx, certPEM, keySecret)
}
