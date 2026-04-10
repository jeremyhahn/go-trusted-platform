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

package overlay

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// Controller orchestrates overlay networking components including VXLAN tunnels,
// BGP/EVPN control plane, and gateway functionality.
type Controller struct {
	config *Config

	// Component dependencies
	ovsClient   *ovs.Client
	ofClient    *openflow.Client
	vtepManager *vxlan.VTEPManager
	bgpSpeaker  *bgp.Speaker
	evpnManager *bgp.EVPNManager
	gateway     *gateway.Gateway
	ipam        ipam.Allocator

	// State management
	state *StateManager

	// Logging
	logger *slog.Logger

	// Lifecycle state
	controllerState atomic.Uint32
	startedAt       time.Time
	mu              sync.RWMutex

	// Shutdown coordination
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New creates a new overlay controller with the given configuration.
func New(config *Config, opts ...Option) (*Controller, error) {
	if config == nil {
		return nil, ErrConfigNil
	}

	// Apply defaults before validation
	config.ApplyDefaults()

	if err := config.Validate(); err != nil {
		return nil, err
	}

	c := &Controller{
		config: config,
		state:  NewStateManager(),
		logger: slog.Default(),
		stopCh: make(chan struct{}),
	}

	c.controllerState.Store(uint32(ControllerStateStopped))

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Start starts the overlay controller and all sub-components.
func (c *Controller) Start(ctx context.Context) error {
	if !c.controllerState.CompareAndSwap(uint32(ControllerStateStopped), uint32(ControllerStateInitializing)) {
		currentState := ControllerState(c.controllerState.Load())
		if currentState == ControllerStateRunning || currentState == ControllerStateInitializing {
			return ErrControllerAlreadyRunning
		}
		return &ErrInvalidState{Expected: ControllerStateStopped, Actual: currentState}
	}

	c.logger.Info("starting overlay controller",
		"node_id", c.config.NodeID,
		"vtep_ip", c.config.VTEPIP)

	// Initialize components in order
	if err := c.initializeComponents(ctx); err != nil {
		c.controllerState.Store(uint32(ControllerStateError))
		return &ErrStartupFailed{NodeID: c.config.NodeID, Phase: "component-initialization", Cause: err}
	}

	// Initialize shutdown coordination BEFORE starting background tasks
	// This prevents a race condition where background tasks try to read
	// from stopCh before it's initialized
	c.mu.Lock()
	c.startedAt = time.Now()
	c.stopCh = make(chan struct{})
	c.stopOnce = sync.Once{}
	c.mu.Unlock()

	// Start background tasks (now that stopCh is initialized)
	c.startBackgroundTasks(ctx)

	c.controllerState.Store(uint32(ControllerStateRunning))

	c.logger.Info("overlay controller started",
		"node_id", c.config.NodeID)

	return nil
}

// Stop stops the overlay controller gracefully.
func (c *Controller) Stop(ctx context.Context) error {
	currentState := ControllerState(c.controllerState.Load())
	if currentState == ControllerStateStopped || currentState == ControllerStateStopping {
		return nil
	}

	if !c.controllerState.CompareAndSwap(uint32(currentState), uint32(ControllerStateStopping)) {
		return &ErrInvalidState{Expected: currentState, Actual: ControllerState(c.controllerState.Load())}
	}

	c.logger.Info("stopping overlay controller",
		"node_id", c.config.NodeID)

	// Signal shutdown
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})

	// Wait for background tasks with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All tasks stopped
	case <-ctx.Done():
		c.controllerState.Store(uint32(ControllerStateError))
		return &ErrShutdownFailed{NodeID: c.config.NodeID, Phase: "wait-tasks", Cause: ctx.Err()}
	}

	// Cleanup components
	if err := c.cleanupComponents(ctx); err != nil {
		c.controllerState.Store(uint32(ControllerStateError))
		return &ErrShutdownFailed{NodeID: c.config.NodeID, Phase: "component-cleanup", Cause: err}
	}

	c.controllerState.Store(uint32(ControllerStateStopped))

	c.logger.Info("overlay controller stopped",
		"node_id", c.config.NodeID)

	return nil
}

// initializeComponents initializes all sub-components.
func (c *Controller) initializeComponents(ctx context.Context) error {
	// Register local VTEP
	localVTEP := &VTEPInfo{
		NodeID:      c.config.NodeID,
		IP:          c.config.VTEPIP,
		Healthy:     true,
		LastSeen:    time.Now(),
		EVPNEnabled: c.config.EnableEVPN,
	}

	if err := c.state.AddVTEP(ctx, localVTEP); err != nil {
		return err
	}

	return nil
}

// cleanupComponents cleans up all sub-components.
func (c *Controller) cleanupComponents(ctx context.Context) error {
	// Clear state
	return c.state.Clear(ctx)
}

// startBackgroundTasks starts background maintenance tasks.
func (c *Controller) startBackgroundTasks(ctx context.Context) {
	// Get stopCh under lock for safe access
	c.mu.RLock()
	stopCh := c.stopCh
	c.mu.RUnlock()

	// Health check task
	c.wg.Add(1)
	go c.healthCheckLoop(stopCh)

	// MAC expiration task
	c.wg.Add(1)
	go c.macExpirationLoop(stopCh)
}

// healthCheckLoop periodically performs health checks.
func (c *Controller) healthCheckLoop(stopCh <-chan struct{}) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.performHealthCheck()
		}
	}
}

// performHealthCheck performs a health check on all components.
func (c *Controller) performHealthCheck() {
	// Check VTEP manager health by verifying it's started
	if c.vtepManager != nil {
		if !c.vtepManager.IsStarted() {
			c.logger.Warn("VTEP manager is not started")
		}
	}

	// Check OVS client connectivity
	if c.ovsClient != nil {
		if !c.ovsClient.IsConnected() {
			c.logger.Warn("OVS client is not connected")
		}
	}

	// Check OpenFlow client connectivity
	if c.ofClient != nil {
		if !c.ofClient.IsConnected() {
			c.logger.Warn("OpenFlow client is not connected")
		}
	}

	c.logger.Debug("health check completed")
}

// macExpirationLoop periodically expires old MAC entries.
func (c *Controller) macExpirationLoop(stopCh <-chan struct{}) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.MACExpiration / 2)
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			c.expireMACs()
		}
	}
}

// expireMACs removes expired MAC entries.
func (c *Controller) expireMACs() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	expired, err := c.state.ExpireMACs(ctx)
	if err != nil {
		c.logger.Warn("failed to expire MACs",
			"error", err)
		return
	}

	if len(expired) > 0 {
		c.logger.Debug("expired MAC entries",
			"count", len(expired))
	}
}

// GetState returns the current overlay state.
func (c *Controller) GetState() *State {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ctx := context.Background()

	vteps, _ := c.state.ListVTEPs(ctx)
	tunnels, _ := c.state.ListTunnels(ctx)
	macs, _ := c.state.ListAllRemoteMACs(ctx)
	vnis, _ := c.state.ListVNIs(ctx)

	state := &State{
		NodeID:          c.config.NodeID,
		VTEPIP:          c.config.VTEPIP,
		ControllerState: ControllerState(c.controllerState.Load()),
		VTEPs:           vteps,
		Tunnels:         tunnels,
		RemoteMACs:      macs,
		VNIs:            vnis,
		StartedAt:       c.startedAt,
		LastHealthCheck: time.Now(),
	}

	if c.gateway != nil {
		state.GatewayMode = c.gateway.GetActiveModes()
	}

	return state
}

// AddVNI creates a new VNI on the overlay.
func (c *Controller) AddVNI(ctx context.Context, vniConfig *VNIConfig) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	if vniConfig == nil {
		return ErrVNINotFound
	}

	if err := vniConfig.Validate(); err != nil {
		return err
	}

	c.logger.Info("adding VNI",
		"vni", vniConfig.VNI,
		"vlan", vniConfig.VLAN)

	vniInfo := &VNIInfo{
		VNI:       vniConfig.VNI,
		VLAN:      vniConfig.VLAN,
		CreatedAt: time.Now(),
	}

	if err := c.state.AddVNI(ctx, vniInfo); err != nil {
		return &ErrVNIOperationFailed{VNI: vniConfig.VNI, Operation: "add", Cause: err}
	}

	// Advertise IMET if enabled
	if c.config.EnableEVPN && vniConfig.AdvertiseIMET && c.evpnManager != nil {
		if err := c.advertiseIMET(ctx, vniConfig.VNI); err != nil {
			c.logger.Warn("failed to advertise IMET",
				"vni", vniConfig.VNI,
				"error", err)
		} else {
			vniInfo.IMETAdvertised = true
			_ = c.state.UpdateVNI(ctx, vniInfo)
		}
	}

	c.logger.Info("VNI added successfully",
		"vni", vniConfig.VNI)

	return nil
}

// RemoveVNI removes a VNI from the overlay.
func (c *Controller) RemoveVNI(ctx context.Context, vni uint32) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	c.logger.Info("removing VNI",
		"vni", vni)

	// Get VNI info for cleanup
	vniInfo, err := c.state.GetVNI(ctx, vni)
	if err != nil {
		return &ErrVNIOperationFailed{VNI: vni, Operation: "remove", Cause: err}
	}

	// Withdraw IMET if advertised
	if vniInfo.IMETAdvertised && c.evpnManager != nil {
		if err := c.withdrawIMET(ctx, vni); err != nil {
			c.logger.Warn("failed to withdraw IMET",
				"vni", vni,
				"error", err)
		}
	}

	// Remove VNI (this also removes associated MACs)
	if err := c.state.RemoveVNI(ctx, vni); err != nil {
		return &ErrVNIOperationFailed{VNI: vni, Operation: "remove", Cause: err}
	}

	c.logger.Info("VNI removed successfully",
		"vni", vni)

	return nil
}

// GetVNI retrieves information about a VNI.
func (c *Controller) GetVNI(ctx context.Context, vni uint32) (*VNIInfo, error) {
	if !c.IsRunning() {
		return nil, ErrControllerNotRunning
	}

	return c.state.GetVNI(ctx, vni)
}

// ListVNIs returns all configured VNIs.
func (c *Controller) ListVNIs(ctx context.Context) ([]VNIInfo, error) {
	if !c.IsRunning() {
		return nil, ErrControllerNotRunning
	}

	return c.state.ListVNIs(ctx)
}

// LearnMAC learns a MAC address from a remote VTEP.
func (c *Controller) LearnMAC(ctx context.Context, mac net.HardwareAddr, vni uint32, remoteVTEP netip.Addr) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	if mac == nil {
		return &ErrInvalidMAC{Reason: "MAC address is nil"}
	}

	if !remoteVTEP.IsValid() {
		return &ErrInvalidIP{IP: remoteVTEP, Reason: "remote VTEP IP is invalid"}
	}

	// Validate VNI exists
	if _, err := c.state.GetVNI(ctx, vni); err != nil {
		return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: ErrVNINotFound}
	}

	entry := &RemoteMACEntry{
		MAC:        mac,
		VNI:        vni,
		RemoteVTEP: remoteVTEP,
		LearnedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(c.config.MACExpiration),
		Source:     "datapath",
	}

	// Try to add, or update if exists
	if err := c.state.AddRemoteMAC(ctx, entry); err != nil {
		if err == ErrMACAlreadyExists {
			// Update existing entry
			existing, getErr := c.state.GetRemoteMAC(ctx, vni, mac)
			if getErr != nil {
				return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: getErr}
			}
			existing.RemoteVTEP = remoteVTEP
			existing.LearnedAt = time.Now()
			existing.ExpiresAt = time.Now().Add(c.config.MACExpiration)
			if updateErr := c.state.UpdateRemoteMAC(ctx, existing); updateErr != nil {
				return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: updateErr}
			}
		} else {
			return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: err}
		}
	}

	c.logger.Debug("learned MAC",
		"mac", mac,
		"vni", vni,
		"remote_vtep", remoteVTEP)

	return nil
}

// LearnMACWithIP learns a MAC address with associated IP from EVPN.
func (c *Controller) LearnMACWithIP(ctx context.Context, mac net.HardwareAddr, ip netip.Addr, vni uint32, remoteVTEP netip.Addr) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	if mac == nil {
		return &ErrInvalidMAC{Reason: "MAC address is nil"}
	}

	if !ip.IsValid() {
		return &ErrInvalidIP{IP: ip, Reason: "IP is invalid"}
	}

	// Validate VNI exists
	if _, err := c.state.GetVNI(ctx, vni); err != nil {
		return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: ErrVNINotFound}
	}

	entry := &RemoteMACEntry{
		MAC:        mac,
		VNI:        vni,
		RemoteVTEP: remoteVTEP,
		IP:         ip,
		LearnedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(c.config.MACExpiration),
		Source:     "evpn",
	}

	// Try to add, or update if exists
	if err := c.state.AddRemoteMAC(ctx, entry); err != nil {
		if err == ErrMACAlreadyExists {
			existing, getErr := c.state.GetRemoteMAC(ctx, vni, mac)
			if getErr != nil {
				return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: getErr}
			}
			existing.RemoteVTEP = remoteVTEP
			existing.IP = ip
			existing.LearnedAt = time.Now()
			existing.ExpiresAt = time.Now().Add(c.config.MACExpiration)
			existing.Source = "evpn"
			if updateErr := c.state.UpdateRemoteMAC(ctx, existing); updateErr != nil {
				return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: updateErr}
			}
		} else {
			return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "learn", Cause: err}
		}
	}

	c.logger.Debug("learned MAC/IP from EVPN",
		"mac", mac,
		"ip", ip,
		"vni", vni,
		"remote_vtep", remoteVTEP)

	return nil
}

// ForgetMAC removes a learned MAC address.
func (c *Controller) ForgetMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	if mac == nil {
		return &ErrInvalidMAC{Reason: "MAC address is nil"}
	}

	if err := c.state.RemoveRemoteMAC(ctx, vni, mac); err != nil {
		return &ErrMACOperationFailed{MAC: mac, VNI: vni, Operation: "forget", Cause: err}
	}

	c.logger.Debug("forgot MAC",
		"mac", mac,
		"vni", vni)

	return nil
}

// GetRemoteMAC retrieves a remote MAC entry.
func (c *Controller) GetRemoteMAC(ctx context.Context, vni uint32, mac net.HardwareAddr) (*RemoteMACEntry, error) {
	if !c.IsRunning() {
		return nil, ErrControllerNotRunning
	}

	return c.state.GetRemoteMAC(ctx, vni, mac)
}

// GetRemoteMACs returns all learned remote MACs for a VNI.
func (c *Controller) GetRemoteMACs(ctx context.Context, vni uint32) ([]RemoteMACEntry, error) {
	if !c.IsRunning() {
		return nil, ErrControllerNotRunning
	}

	return c.state.ListRemoteMACsByVNI(ctx, vni)
}

// AddVTEP adds a remote VTEP endpoint.
func (c *Controller) AddVTEP(ctx context.Context, vtep *VTEPInfo) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	if vtep == nil {
		return ErrVTEPNotFound
	}

	c.logger.Info("adding VTEP",
		"node_id", vtep.NodeID,
		"ip", vtep.IP)

	vtep.LastSeen = time.Now()

	if err := c.state.AddVTEP(ctx, vtep); err != nil {
		return &ErrVTEPOperationFailed{VTEP: vtep.IP, Operation: "add", Cause: err}
	}

	c.logger.Info("VTEP added successfully",
		"node_id", vtep.NodeID,
		"ip", vtep.IP)

	return nil
}

// RemoveVTEP removes a remote VTEP endpoint.
func (c *Controller) RemoveVTEP(ctx context.Context, ip netip.Addr) error {
	if !c.IsRunning() {
		return ErrControllerNotRunning
	}

	c.logger.Info("removing VTEP",
		"ip", ip)

	if err := c.state.RemoveVTEP(ctx, ip); err != nil {
		return &ErrVTEPOperationFailed{VTEP: ip, Operation: "remove", Cause: err}
	}

	c.logger.Info("VTEP removed successfully",
		"ip", ip)

	return nil
}

// GetVTEP retrieves a VTEP by IP.
func (c *Controller) GetVTEP(ctx context.Context, ip netip.Addr) (*VTEPInfo, error) {
	if !c.IsRunning() {
		return nil, ErrControllerNotRunning
	}

	return c.state.GetVTEP(ctx, ip)
}

// ListVTEPs returns all known VTEPs.
func (c *Controller) ListVTEPs(ctx context.Context) ([]VTEPInfo, error) {
	if !c.IsRunning() {
		return nil, ErrControllerNotRunning
	}

	return c.state.ListVTEPs(ctx)
}

// advertiseIMET advertises an IMET route for a VNI.
func (c *Controller) advertiseIMET(ctx context.Context, vni uint32) error {
	if c.evpnManager == nil {
		return &ErrComponentNotInitialized{Component: "EVPNManager"}
	}

	// Implementation would call evpnManager.AdvertiseIMET()
	// For now, just log the action
	c.logger.Debug("would advertise IMET",
		"vni", vni)

	return nil
}

// withdrawIMET withdraws an IMET route for a VNI.
func (c *Controller) withdrawIMET(ctx context.Context, vni uint32) error {
	if c.evpnManager == nil {
		return &ErrComponentNotInitialized{Component: "EVPNManager"}
	}

	// Implementation would call evpnManager.WithdrawIMET()
	c.logger.Debug("would withdraw IMET",
		"vni", vni)

	return nil
}

// IsRunning returns true if the controller is running.
func (c *Controller) IsRunning() bool {
	state := ControllerState(c.controllerState.Load())
	return state == ControllerStateRunning
}

// IsOperational returns true if the controller is operational.
func (c *Controller) IsOperational() bool {
	state := ControllerState(c.controllerState.Load())
	return state.IsOperational()
}

// GetControllerState returns the current controller state.
func (c *Controller) GetControllerState() ControllerState {
	return ControllerState(c.controllerState.Load())
}

// GetConfig returns the controller configuration.
func (c *Controller) GetConfig() *Config {
	return c.config
}

// Uptime returns how long the controller has been running.
func (c *Controller) Uptime() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.IsOperational() || c.startedAt.IsZero() {
		return 0
	}
	return time.Since(c.startedAt)
}
