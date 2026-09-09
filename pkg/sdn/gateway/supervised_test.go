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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// fakeSupervisor records what the handlers ask of it and answers with
// scripted verdicts.
type fakeSupervisor struct {
	started  []string
	stopped  []string
	startErr map[string]error
	stopErr  map[string]error
	active   map[string]bool
	health   map[string]error

	applied    *gwstate.DesiredConfig
	applyState gwstate.DesiredConfigState
	applyErr   error
}

func newFakeSupervisor() *fakeSupervisor {
	return &fakeSupervisor{
		startErr: map[string]error{},
		stopErr:  map[string]error{},
		active:   map[string]bool{},
		health:   map[string]error{},
	}
}

func (f *fakeSupervisor) StartService(_ context.Context, service string) error {
	f.started = append(f.started, service)
	if err := f.startErr[service]; err != nil {
		return err
	}
	f.active[service] = true
	return nil
}

func (f *fakeSupervisor) StopService(_ context.Context, service string) error {
	f.stopped = append(f.stopped, service)
	if err := f.stopErr[service]; err != nil {
		return err
	}
	f.active[service] = false
	return nil
}

func (f *fakeSupervisor) ServiceActive(service string) bool { return f.active[service] }

func (f *fakeSupervisor) ServiceHealth(service string) error { return f.health[service] }

func (f *fakeSupervisor) Apply(_ context.Context, desired *gwstate.DesiredConfig) (gwstate.DesiredConfigState, error) {
	f.applied = desired
	return f.applyState, f.applyErr
}

// newSupervisedGateway builds a supervised gateway that already meets its
// admission gates, the way gatewayd's assembly does with SetNodeMetrics.
func newSupervisedGateway(t *testing.T, sup ServiceSupervisor) *Gateway {
	t.Helper()
	cfg := supervisedConfig(sup)
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(cfg.MinReputation, time.Duration(cfg.MinAgeDays)*24*time.Hour, cfg.MinUptimePct)
	return gw
}

// supervisedConfig is a gateway whose sections all run out of process.
// The firewall section would need an OVS runtime in-process; under a
// supervisor it must not, which is part of what these tests assert.
func supervisedConfig(sup ServiceSupervisor) *GatewayConfig {
	cfg := baseGatewayConfig("supervised-gw")
	cfg.Firewall = &FirewallConfig{Enabled: true, DefaultPolicy: "deny"}
	cfg.NAT = &NATConfig{Enabled: true, ExternalIP: "203.0.113.10", PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 1000, InternalCIDR: "10.0.100.0/24"}
	cfg.ManagementVPN = &ManagementVPNServiceConfig{Enabled: true}
	cfg.Supervisor = sup
	return cfg
}

func TestSupervisor_EverySectionIsSupervisedIncludingRefusedOnes(t *testing.T) {
	sup := newFakeSupervisor()
	gw := newSupervisedGateway(t, sup)

	// The refused-in-process sections are the supervisor's problem now:
	// the parent relays rather than refusing on its own authority.
	for _, name := range []string{ServiceFirewall, ServiceNAT, ServiceManagementVPN} {
		handler, ok := gw.serviceHandlers[name]
		require.True(t, ok, "%s registered", name)
		assert.IsType(t, &supervisedServiceHandler{}, handler, "%s is supervised", name)
	}
	assert.Equal(t, []string{ServiceFirewall, ServiceNAT, ServiceManagementVPN}, gw.serviceOrder)
}

func TestSupervisedStart_StartsEverySectionThroughTheSupervisor(t *testing.T) {
	sup := newFakeSupervisor()
	gw := newSupervisedGateway(t, sup)

	require.NoError(t, gw.Start(context.Background()))
	assert.Equal(t, []string{ServiceFirewall, ServiceNAT, ServiceManagementVPN}, sup.started)
	assert.Equal(t, GatewayStateRunning, gw.GetState())
	// No pipeline was installed here: the datapath child owns the bridge,
	// and this gateway has no runtime to install one with.
	assert.Nil(t, gw.config.Runtime)

	require.NoError(t, gw.Stop(context.Background()))
	assert.ElementsMatch(t, []string{ServiceFirewall, ServiceNAT, ServiceManagementVPN}, sup.stopped)
}

func TestSupervisedStart_AFailedServiceRollsBackTheStartedOnes(t *testing.T) {
	sup := newFakeSupervisor()
	sup.startErr[ServiceNAT] = errors.New("datapath process exited: signal killed")
	gw := newSupervisedGateway(t, sup)

	err := gw.Start(context.Background())
	require.Error(t, err)
	var startFailed *ErrStartupFailed
	require.ErrorAs(t, err, &startFailed)
	assert.Contains(t, err.Error(), "datapath process exited")
	assert.Equal(t, GatewayStateError, gw.GetState())
	assert.Equal(t, []string{ServiceFirewall}, sup.stopped, "the started service is rolled back")
}

func TestSupervisedHandler_RelaysActiveAndHealthVerdicts(t *testing.T) {
	sup := newFakeSupervisor()
	gw := newSupervisedGateway(t, sup)
	require.NoError(t, gw.Start(context.Background()))

	// A child that crashed after start: the supervisor says the service is
	// neither active nor healthy, and the parent must report that rather
	// than a bool it set at start.
	sup.active[ServiceNAT] = false
	sup.health[ServiceNAT] = errors.New("process nat exited 1; restart budget exhausted")

	handler := gw.serviceHandlers[ServiceNAT]
	assert.False(t, handler.IsActive())
	var unhealthy *ErrServiceUnhealthy
	require.ErrorAs(t, handler.Health(), &unhealthy)
	assert.Equal(t, ServiceNAT, unhealthy.Service)
	assert.Contains(t, unhealthy.Error(), "restart budget exhausted")

	health := gw.Snapshot().Health
	assert.Equal(t, healthStatusDegraded, health.Status)
	assert.Equal(t, componentUnhealthy, health.Components[ServiceNAT])
	assert.Equal(t, componentHealthy, health.Components[ServiceFirewall])
}

func TestSupervisedStop_ReportsTheSupervisorFailure(t *testing.T) {
	sup := newFakeSupervisor()
	sup.stopErr[ServiceFirewall] = errors.New("process datapath did not exit")
	gw := newSupervisedGateway(t, sup)
	require.NoError(t, gw.Start(context.Background()))

	err := gw.serviceHandlers[ServiceFirewall].Stop(context.Background())
	var stopFailed *ErrServiceStopFailed
	require.ErrorAs(t, err, &stopFailed)
	assert.Equal(t, ServiceFirewall, stopFailed.Service)
}

func TestSupervisedApply_ForwardsTheDocumentAndRecordsTheChildState(t *testing.T) {
	sup := newFakeSupervisor()
	sup.applyState = gwstate.DesiredConfigState{Version: "v3"}
	gw := newSupervisedGateway(t, sup)

	desired := &gwstate.DesiredConfig{GatewayID: "supervised-gw", Version: "v3", NAT: &gwstate.DesiredNAT{}}
	require.NoError(t, gw.Apply(context.Background(), desired))
	require.NotNil(t, sup.applied)
	assert.Equal(t, "v3", sup.applied.Version)

	state := gw.DesiredConfigState()
	assert.Equal(t, "v3", state.Version)
	assert.False(t, state.AttemptedAt.IsZero(), "the parent stamps its own attempt time")
	assert.Empty(t, state.LastError)
}

func TestSupervisedApply_ReportsTheChildFailureWithItsState(t *testing.T) {
	sup := newFakeSupervisor()
	sup.applyState = gwstate.DesiredConfigState{Version: "v2"}
	sup.applyErr = errors.New("gatewayd ipc: datapath apply failed: load balancer not enabled")
	gw := newSupervisedGateway(t, sup)

	err := gw.Apply(context.Background(), &gwstate.DesiredConfig{GatewayID: "supervised-gw", Version: "v4"})
	require.Error(t, err)
	state := gw.DesiredConfigState()
	assert.Equal(t, "v2", state.Version, "the version the child last applied is kept")
	assert.Contains(t, state.LastError, "load balancer not enabled")

	// An invalid document never reaches the child.
	sup.applied = nil
	require.Error(t, gw.Apply(context.Background(), nil))
	assert.Nil(t, sup.applied)
}

func TestServiceReports_OneEntryPerHandlerInRegistrationOrder(t *testing.T) {
	sup := newFakeSupervisor()
	gw := newSupervisedGateway(t, sup)
	require.NoError(t, gw.Start(context.Background()))
	sup.health[ServiceManagementVPN] = errors.New("no data plane")

	reports := gw.ServiceReports()
	require.Len(t, reports, 3)
	assert.Equal(t, []string{ServiceFirewall, ServiceNAT, ServiceManagementVPN},
		[]string{reports[0].Name, reports[1].Name, reports[2].Name})
	assert.True(t, reports[0].Active)
	assert.NoError(t, reports[0].Health)
	assert.Error(t, reports[2].Health)
}
