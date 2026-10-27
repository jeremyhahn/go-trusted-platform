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

package gateway

import (
	"context"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// ServiceSupervisor runs the gateway's services out of process (#557). When
// GatewayConfig.Supervisor is set, every enabled section it Supervises is
// registered as a supervisedServiceHandler that asks the supervisor to start,
// stop and report the service instead of building the backend in this
// process; the sections it does not supervise yet stay in-process. The
// supervisor owns the `gatewayd service run <process>` children, their
// restart policy and the IPC that reaches them. The interface is defined
// here so pkg/sdn/gateway/process can implement it without a cycle.
type ServiceSupervisor interface {
	// Supervises reports whether the service runs in a supervised child.
	// The services move out of process one process at a time; one that has
	// not moved yet keeps its in-process handler.
	Supervises(service string) bool
	// StartService makes sure the process owning the service is running and
	// the service reports active inside it. The error names the process and
	// the child's own start failure when the child came up but the service
	// did not.
	StartService(ctx context.Context, service string) error
	// StopService releases the service; the owning process is stopped once
	// none of its services remain.
	StopService(ctx context.Context, service string) error
	// ServiceActive reports the child's own active verdict for the service.
	ServiceActive(service string) bool
	// ServiceHealth is nil when the owning process is up and the child
	// reports the service healthy.
	ServiceHealth(service string) error
	// ServiceSnapshot is the snapshot of the child process hosting the
	// service, read over its control socket, so the state the service keeps
	// in the child reaches this process's snapshot.
	ServiceSnapshot(ctx context.Context, service string) (*gwstate.Snapshot, error)
	// Apply forwards the control plane's desired configuration to the
	// datapath and vpn processes and returns the reconciliation state the
	// datapath process reports.
	Apply(ctx context.Context, desired *gwstate.DesiredConfig) (gwstate.DesiredConfigState, error)
}

// supervisedServiceHandler is the parent-side stand-in for a service that
// runs in a supervised child process. It carries no backend: Start asks the
// supervisor to bring the owning process up and waits for the service to
// report active there, and IsActive/Health relay the child's verdicts, so a
// crashed child shows as a degraded component in the snapshot rather than
// a bool that stays true.
type supervisedServiceHandler struct {
	name       string
	supervisor ServiceSupervisor
}

func newSupervisedServiceHandler(name string, supervisor ServiceSupervisor) *supervisedServiceHandler {
	return &supervisedServiceHandler{name: name, supervisor: supervisor}
}

// RegisterSupervisedService registers the relay for a service that is not a
// gateway section, so the configured-section walk never sees it: the proxy,
// whose section belongs to gatewayd rather than to GatewayConfig. The
// service must be one the gateway's supervisor runs out of process.
func (g *Gateway) RegisterSupervisedService(name string) error {
	if !g.supervises(name) {
		return &ErrServiceNotSupervised{Service: name}
	}
	return g.RegisterServiceHandler(newSupervisedServiceHandler(name, g.config.Supervisor))
}

func (h *supervisedServiceHandler) Name() string { return h.name }

func (h *supervisedServiceHandler) Start(ctx context.Context) error {
	if err := h.supervisor.StartService(ctx, h.name); err != nil {
		return &ErrServiceStartFailed{Service: h.name, Cause: err}
	}
	return nil
}

func (h *supervisedServiceHandler) Stop(ctx context.Context) error {
	if err := h.supervisor.StopService(ctx, h.name); err != nil {
		return &ErrServiceStopFailed{Service: h.name, Cause: err}
	}
	return nil
}

func (h *supervisedServiceHandler) IsActive() bool {
	return h.supervisor.ServiceActive(h.name)
}

func (h *supervisedServiceHandler) Health() error {
	if err := h.supervisor.ServiceHealth(h.name); err != nil {
		return &ErrServiceUnhealthy{Service: h.name, Cause: err}
	}
	return nil
}

// ServiceReport is one registered service's liveness as the gateway sees
// it: the handler's active verdict and its Health() error. Health is nil
// when the service is healthy.
type ServiceReport struct {
	Name   string
	Active bool
	Health error
}

// ServiceReports returns one report per registered service handler in
// registration order. It is the surface the supervised child exposes over
// IPC and the snapshot's per-component health is derived from it.
func (g *Gateway) ServiceReports() []ServiceReport {
	g.mu.RLock()
	order := append([]string(nil), g.serviceOrder...)
	handlers := make(map[string]ServiceHandler, len(g.serviceHandlers))
	for name, h := range g.serviceHandlers {
		handlers[name] = h
	}
	g.mu.RUnlock()

	reports := make([]ServiceReport, 0, len(handlers))
	for _, name := range order {
		h := handlers[name]
		reports = append(reports, ServiceReport{Name: name, Active: h.IsActive(), Health: h.Health()})
	}
	return reports
}
