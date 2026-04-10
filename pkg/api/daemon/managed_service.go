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
	"sync/atomic"
)

// configManagedService is a ManagedService backed by a ServiceConfig entry.
// It provides basic start/stop lifecycle tracking using lock-free atomics.
type configManagedService struct {
	name    string
	config  ServiceConfig
	running atomic.Bool
}

// newConfigManagedService creates a configManagedService for the given
// service name and configuration.
func newConfigManagedService(name string, cfg ServiceConfig) *configManagedService {
	return &configManagedService{
		name:   name,
		config: cfg,
	}
}

// Start marks the service as running.
func (s *configManagedService) Start(_ context.Context) error {
	s.running.Store(true)
	return nil
}

// Stop marks the service as stopped.
func (s *configManagedService) Stop(_ context.Context) error {
	s.running.Store(false)
	return nil
}

// IsRunning returns true when the service has been started and not yet stopped.
func (s *configManagedService) IsRunning() bool {
	return s.running.Load()
}

// Name returns the service name.
func (s *configManagedService) Name() string {
	return s.name
}
