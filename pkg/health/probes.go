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

package health

import (
	"context"
	"sync/atomic"
	"time"
)

// ProbeType represents the type of Kubernetes-style health probe.
type ProbeType string

const (
	// ProbeLiveness indicates if the application is running.
	// If it fails, the container should be restarted.
	ProbeLiveness ProbeType = "liveness"

	// ProbeReadiness indicates if the application is ready to serve traffic.
	// If it fails, the container should be removed from service endpoints.
	ProbeReadiness ProbeType = "readiness"

	// ProbeStartup indicates if the application has started successfully.
	// If it fails during startup, the container should be restarted.
	ProbeStartup ProbeType = "startup"
)

// String returns the string representation of the probe type.
func (p ProbeType) String() string {
	return string(p)
}

// Probe is the interface for health probes.
type Probe interface {
	// Type returns the probe type.
	Type() ProbeType

	// Check performs the probe check and returns true if healthy.
	Check(ctx context.Context) bool

	// LastCheck returns the result and timestamp of the last check.
	LastCheck() (bool, time.Time)
}

// LivenessProbe checks if the application is alive and running.
type LivenessProbe struct {
	checkFunc func(ctx context.Context) bool
	lastOK    atomic.Bool
	lastCheck atomic.Value
}

// NewLivenessProbe creates a new liveness probe.
// The checkFunc should return true if the application is alive.
func NewLivenessProbe(checkFunc func(ctx context.Context) bool) *LivenessProbe {
	p := &LivenessProbe{
		checkFunc: checkFunc,
	}
	p.lastCheck.Store(time.Time{})
	return p
}

// Type returns the probe type.
func (p *LivenessProbe) Type() ProbeType {
	return ProbeLiveness
}

// Check performs the liveness check.
func (p *LivenessProbe) Check(ctx context.Context) bool {
	if p.checkFunc == nil {
		p.lastOK.Store(true)
		p.lastCheck.Store(time.Now())
		return true
	}

	result := p.checkFunc(ctx)
	p.lastOK.Store(result)
	p.lastCheck.Store(time.Now())
	return result
}

// LastCheck returns the result and timestamp of the last check.
func (p *LivenessProbe) LastCheck() (bool, time.Time) {
	t := p.lastCheck.Load().(time.Time)
	return p.lastOK.Load(), t
}

// ReadinessProbe checks if the application is ready to serve traffic.
type ReadinessProbe struct {
	checkFunc func(ctx context.Context) bool
	lastOK    atomic.Bool
	lastCheck atomic.Value
}

// NewReadinessProbe creates a new readiness probe.
// The checkFunc should return true if the application is ready.
func NewReadinessProbe(checkFunc func(ctx context.Context) bool) *ReadinessProbe {
	p := &ReadinessProbe{
		checkFunc: checkFunc,
	}
	p.lastCheck.Store(time.Time{})
	return p
}

// Type returns the probe type.
func (p *ReadinessProbe) Type() ProbeType {
	return ProbeReadiness
}

// Check performs the readiness check.
func (p *ReadinessProbe) Check(ctx context.Context) bool {
	if p.checkFunc == nil {
		p.lastOK.Store(false)
		p.lastCheck.Store(time.Now())
		return false
	}

	result := p.checkFunc(ctx)
	p.lastOK.Store(result)
	p.lastCheck.Store(time.Now())
	return result
}

// LastCheck returns the result and timestamp of the last check.
func (p *ReadinessProbe) LastCheck() (bool, time.Time) {
	t := p.lastCheck.Load().(time.Time)
	return p.lastOK.Load(), t
}

// StartupProbe checks if the application has completed its startup process.
type StartupProbe struct {
	checkFunc func(ctx context.Context) bool
	started   atomic.Bool
	lastOK    atomic.Bool
	lastCheck atomic.Value
}

// NewStartupProbe creates a new startup probe.
// The checkFunc should return true if the application has started successfully.
func NewStartupProbe(checkFunc func(ctx context.Context) bool) *StartupProbe {
	p := &StartupProbe{
		checkFunc: checkFunc,
	}
	p.lastCheck.Store(time.Time{})
	return p
}

// Type returns the probe type.
func (p *StartupProbe) Type() ProbeType {
	return ProbeStartup
}

// Check performs the startup check.
// Once it returns true, subsequent checks will always return true.
func (p *StartupProbe) Check(ctx context.Context) bool {
	// If already started, always return true
	if p.started.Load() {
		p.lastOK.Store(true)
		p.lastCheck.Store(time.Now())
		return true
	}

	if p.checkFunc == nil {
		p.lastOK.Store(false)
		p.lastCheck.Store(time.Now())
		return false
	}

	result := p.checkFunc(ctx)
	if result {
		p.started.Store(true)
	}
	p.lastOK.Store(result)
	p.lastCheck.Store(time.Now())
	return result
}

// LastCheck returns the result and timestamp of the last check.
func (p *StartupProbe) LastCheck() (bool, time.Time) {
	t := p.lastCheck.Load().(time.Time)
	return p.lastOK.Load(), t
}

// HasStarted returns true if the startup probe has ever succeeded.
func (p *StartupProbe) HasStarted() bool {
	return p.started.Load()
}

// RegistryBasedProbe creates a probe based on a health registry.
type RegistryBasedProbe struct {
	probeType ProbeType
	registry  Registry
	lastOK    atomic.Bool
	lastCheck atomic.Value
}

// NewRegistryBasedLivenessProbe creates a liveness probe that uses the health registry.
func NewRegistryBasedLivenessProbe(registry Registry) *RegistryBasedProbe {
	p := &RegistryBasedProbe{
		probeType: ProbeLiveness,
		registry:  registry,
	}
	p.lastCheck.Store(time.Time{})
	return p
}

// NewRegistryBasedReadinessProbe creates a readiness probe that uses the health registry.
func NewRegistryBasedReadinessProbe(registry Registry) *RegistryBasedProbe {
	p := &RegistryBasedProbe{
		probeType: ProbeReadiness,
		registry:  registry,
	}
	p.lastCheck.Store(time.Time{})
	return p
}

// Type returns the probe type.
func (p *RegistryBasedProbe) Type() ProbeType {
	return p.probeType
}

// Check performs the probe check using the registry.
func (p *RegistryBasedProbe) Check(ctx context.Context) bool {
	health := p.registry.Check(ctx)

	var result bool
	switch p.probeType {
	case ProbeLiveness:
		// Liveness passes unless completely unhealthy
		result = health.Status != StatusUnhealthy
	case ProbeReadiness:
		// Readiness requires healthy status
		result = health.Status == StatusHealthy
	default:
		result = health.Status == StatusHealthy
	}

	p.lastOK.Store(result)
	p.lastCheck.Store(time.Now())
	return result
}

// LastCheck returns the result and timestamp of the last check.
func (p *RegistryBasedProbe) LastCheck() (bool, time.Time) {
	t := p.lastCheck.Load().(time.Time)
	return p.lastOK.Load(), t
}

// CompositeProbe combines multiple probes with configurable logic.
type CompositeProbe struct {
	probeType  ProbeType
	probes     []Probe
	requireAll bool
	lastOK     atomic.Bool
	lastCheck  atomic.Value
}

// CompositeProbeOption is a functional option for configuring CompositeProbe.
type CompositeProbeOption func(*CompositeProbe)

// WithRequireAll sets whether all probes must pass (AND logic) or any (OR logic).
func WithRequireAll(requireAll bool) CompositeProbeOption {
	return func(p *CompositeProbe) {
		p.requireAll = requireAll
	}
}

// NewCompositeProbe creates a new composite probe.
func NewCompositeProbe(probeType ProbeType, probes []Probe, opts ...CompositeProbeOption) *CompositeProbe {
	p := &CompositeProbe{
		probeType:  probeType,
		probes:     probes,
		requireAll: true,
	}
	p.lastCheck.Store(time.Time{})
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Type returns the probe type.
func (p *CompositeProbe) Type() ProbeType {
	return p.probeType
}

// Check performs all probe checks.
func (p *CompositeProbe) Check(ctx context.Context) bool {
	if len(p.probes) == 0 {
		p.lastOK.Store(true)
		p.lastCheck.Store(time.Now())
		return true
	}

	var result bool
	if p.requireAll {
		result = true
		for _, probe := range p.probes {
			if !probe.Check(ctx) {
				result = false
				break
			}
		}
	} else {
		result = false
		for _, probe := range p.probes {
			if probe.Check(ctx) {
				result = true
				break
			}
		}
	}

	p.lastOK.Store(result)
	p.lastCheck.Store(time.Now())
	return result
}

// LastCheck returns the result and timestamp of the last check.
func (p *CompositeProbe) LastCheck() (bool, time.Time) {
	t := p.lastCheck.Load().(time.Time)
	return p.lastOK.Load(), t
}
