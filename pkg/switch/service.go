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

package switchmgmt

import "log/slog"

// Service is a thin service layer wrapping Manager instances for API exposure.
// Each Manager is keyed by the switch name from its Config.
type Service struct {
	managers map[string]Manager
	logger   *slog.Logger
}

// NewService creates a Service that manages one Manager per configured switch.
func NewService(configs []Config, logger *slog.Logger) (*Service, error) {
	managers := make(map[string]Manager, len(configs))

	for i := range configs {
		cfg := &configs[i]

		name := cfg.Name
		if name == "" {
			name = cfg.Host
		}

		mgr, err := NewManager(cfg, logger)
		if err != nil {
			// Close any managers already created before returning.
			for _, m := range managers {
				m.Close()
			}
			return nil, err
		}
		managers[name] = mgr
	}

	return &Service{
		managers: managers,
		logger:   logger,
	}, nil
}

// Manager returns the Manager for the given switch name.
func (s *Service) Manager(name string) (Manager, error) {
	mgr, ok := s.managers[name]
	if !ok {
		return nil, ErrManagerNotFound{Name: name}
	}
	return mgr, nil
}

// Close releases all underlying Manager connections.
func (s *Service) Close() error {
	var firstErr error
	for name, mgr := range s.managers {
		if err := mgr.Close(); err != nil {
			s.logger.Error("failed to close switch manager", "name", name, "error", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
