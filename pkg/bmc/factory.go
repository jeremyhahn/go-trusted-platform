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

import "log/slog"

// protocolFactory is a function that creates a BMC client from configuration.
type protocolFactory func(config *Config, logger *slog.Logger) (Client, error)

// protocolFactories maps protocol values to their client constructors for O(1) dispatch.
var protocolFactories = map[Protocol]protocolFactory{
	ProtocolIPMI:    func(config *Config, logger *slog.Logger) (Client, error) { return newIPMIClient(config, logger), nil },
	ProtocolRedfish: func(config *Config, logger *slog.Logger) (Client, error) { return newRedfishClient(config, logger) },
}

// DefaultClientFactory creates BMC clients by dispatching on the configured protocol.
type DefaultClientFactory struct {
	logger *slog.Logger
}

// Compile-time interface check.
var _ ClientFactory = (*DefaultClientFactory)(nil)

// NewDefaultClientFactory creates a new DefaultClientFactory.
func NewDefaultClientFactory(logger *slog.Logger) *DefaultClientFactory {
	return &DefaultClientFactory{logger: logger}
}

// NewClient creates a new BMC client, selecting the implementation based on
// the config's Protocol field.
func (f *DefaultClientFactory) NewClient(config *Config) (Client, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	factory, ok := protocolFactories[config.Protocol]
	if !ok {
		return nil, ErrInvalidConfig{Field: "protocol", Reason: "unsupported protocol: " + string(config.Protocol)}
	}
	return factory(config, f.logger)
}

// RedfishClientFactory creates redfishClient instances.
type RedfishClientFactory struct {
	logger *slog.Logger
}

// Compile-time interface check.
var _ ClientFactory = (*RedfishClientFactory)(nil)

// NewRedfishClientFactory creates a new RedfishClientFactory.
func NewRedfishClientFactory(logger *slog.Logger) *RedfishClientFactory {
	return &RedfishClientFactory{logger: logger}
}

// NewClient creates a new Redfish BMC client from the given configuration.
func (f *RedfishClientFactory) NewClient(config *Config) (Client, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return newRedfishClient(config, f.logger)
}
