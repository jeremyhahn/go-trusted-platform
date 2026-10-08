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

package vxlan

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// OVSClient is the part of *ovs.Client the VTEP manager drives.
type OVSClient interface {
	// AddVXLANPortWithName creates a VXLAN port and waits until
	// ovs-vswitchd has applied it.
	AddVXLANPortWithName(ctx context.Context, bridge, port string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error)

	// GetVXLANPortWithOptions reads an existing VXLAN port and its options.
	GetVXLANPortWithOptions(ctx context.Context, bridge, port string) (*ovs.VXLANPort, error)

	// DeleteVXLANPort removes a VXLAN port from a bridge.
	DeleteVXLANPort(ctx context.Context, bridge, port string) error

	// GetOFPort returns the OpenFlow port number of an interface.
	GetOFPort(ctx context.Context, port string) (int32, error)
}

// VTEPManager owns the local VTEP's one flow-based VXLAN port. Every
// remote VTEP and VNI is reached through that port: a flow sets tun_dst
// and tun_id and outputs to it, and decapsulated traffic arrives on it with
// tun_src and tun_id set. There is no port per tunnel.
type VTEPManager struct {
	config     VTEPConfig
	ovsClient  OVSClient
	bridgeName string
	portName   string
	logger     *slog.Logger

	// ofPort is the OpenFlow number of the VXLAN port while started.
	ofPort atomic.Uint32

	// started indicates if the manager has been started
	started atomic.Bool

	// mu serialises Start and Stop
	mu sync.Mutex
}

// VTEPManagerOption is a functional option for configuring the VTEPManager.
type VTEPManagerOption func(*VTEPManager)

// WithVTEPLogger sets the logger for the VTEP manager.
func WithVTEPLogger(logger *slog.Logger) VTEPManagerOption {
	return func(m *VTEPManager) {
		m.logger = logger
	}
}

// WithPortName names the VXLAN port; DefaultPortName otherwise.
func WithPortName(name string) VTEPManagerOption {
	return func(m *VTEPManager) {
		m.portName = name
	}
}

// NewVTEPManager creates a new VTEP manager with the given configuration.
func NewVTEPManager(
	config VTEPConfig,
	ovsClient OVSClient,
	bridgeName string,
	logger *slog.Logger,
	opts ...VTEPManagerOption,
) (*VTEPManager, error) {
	if err := config.Validate(); err != nil {
		return nil, &ErrVTEPValidationFailed{
			Field: "config",
			Cause: err,
		}
	}

	if ovsClient == nil {
		return nil, ErrOVSClientNil
	}

	if bridgeName == "" {
		return nil, ErrBridgeNameEmpty
	}

	if logger == nil {
		return nil, ErrLoggerNil
	}

	manager := &VTEPManager{
		config:     config,
		ovsClient:  ovsClient,
		bridgeName: bridgeName,
		portName:   DefaultPortName,
		logger:     logger,
	}

	for _, opt := range opts {
		opt(manager)
	}

	if manager.portName == "" {
		return nil, ErrInvalidPortName
	}

	return manager, nil
}

// Start creates the flow-based VXLAN port, or adopts the one a previous
// run left behind when it is configured alike, and resolves its OpenFlow
// port number.
func (m *VTEPManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started.Load() {
		return ErrManagerAlreadyStarted
	}

	if err := m.ensurePort(ctx); err != nil {
		return err
	}

	ofPort, err := m.ovsClient.GetOFPort(ctx, m.portName)
	if err != nil {
		return &ErrOVSOperationFailed{Operation: "resolve ofport", Target: m.portName, Cause: err}
	}
	m.ofPort.Store(uint32(ofPort))
	m.started.Store(true)

	m.logger.Info("VTEP manager started",
		slog.String("local_vtep", m.config.LocalIP.String()),
		slog.String("port", m.portName),
		slog.Int("ofport", int(ofPort)),
		slog.String("underlay_iface", m.config.UnderlayIface),
		slog.Int("underlay_mtu", m.config.UnderlayMTU),
		slog.Int("vxlan_port", int(m.config.VXLANPort)),
	)

	return nil
}

// ensurePort creates the VXLAN port, adopting an existing one only when
// its remote and key are flow-based and it uses the configured UDP port.
func (m *VTEPManager) ensurePort(ctx context.Context) error {
	cfg := &ovs.VXLANPortConfig{
		RemoteFlow: true,
		LocalIP:    m.config.LocalIP,
		DstPort:    m.config.VXLANPort,
	}
	_, err := m.ovsClient.AddVXLANPortWithName(ctx, m.bridgeName, m.portName, cfg)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ovs.ErrVXLANPortExists) {
		return &ErrOVSOperationFailed{Operation: "create VXLAN port", Target: m.portName, Cause: err}
	}

	existing, err := m.ovsClient.GetVXLANPortWithOptions(ctx, m.bridgeName, m.portName)
	if err != nil {
		return &ErrOVSOperationFailed{Operation: "read VXLAN port", Target: m.portName, Cause: err}
	}
	dstPort := existing.DstPort
	if dstPort == 0 {
		dstPort = ovs.DefaultVXLANPort
	}
	if !existing.IsFlowRemote || !existing.IsFlowKey || dstPort != m.config.VXLANPort {
		return &ErrPortConflict{Port: m.portName, Options: existing.Options}
	}
	return nil
}

// Stop removes the VXLAN port. Flows that output to it go with it.
func (m *VTEPManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started.Load() {
		return nil
	}
	m.started.Store(false)
	m.ofPort.Store(0)

	if err := m.ovsClient.DeleteVXLANPort(ctx, m.bridgeName, m.portName); err != nil {
		return &ErrOVSOperationFailed{Operation: "delete VXLAN port", Target: m.portName, Cause: err}
	}

	m.logger.Info("VTEP manager stopped", slog.String("port", m.portName))
	return nil
}

// OFPort returns the OpenFlow port number of the VXLAN port, or
// ErrManagerNotStarted before Start.
func (m *VTEPManager) OFPort() (uint32, error) {
	if !m.started.Load() {
		return 0, ErrManagerNotStarted
	}
	return m.ofPort.Load(), nil
}

// PortName returns the name of the VXLAN port.
func (m *VTEPManager) PortName() string {
	return m.portName
}

// GetLocalVTEP returns the local VTEP IP address.
func (m *VTEPManager) GetLocalVTEP() netip.Addr {
	return m.config.LocalIP
}

// GetConfig returns a copy of the VTEP configuration.
func (m *VTEPManager) GetConfig() VTEPConfig {
	return m.config
}

// GetBridgeName returns the OVS bridge name.
func (m *VTEPManager) GetBridgeName() string {
	return m.bridgeName
}

// IsStarted returns true if the manager has been started.
func (m *VTEPManager) IsStarted() bool {
	return m.started.Load()
}
