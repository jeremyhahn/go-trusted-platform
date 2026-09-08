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

package policy

import (
	"context"
	"crypto/x509"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Engine implements the PolicyEngine interface
type Engine struct {
	mu              sync.RWMutex
	logger          *slog.Logger
	stateMachine    *PortStateMachine
	flowController  FlowController
	portController  OVSPortController
	extractor       PolicyExtractor
	validator       CertificateValidator
	ruleGenerator   *RuleGenerator
	bridgeName      string
	monitor         *CertificateMonitor
	zoneFlowManager *ZoneFlowManager // optional; enables zone-keyed flow installation
	quarantineZone  zone.Zone        // the zone that must never be applied without zone enforcement
}

// Config configures the policy engine
type Config struct {
	// BridgeName is the OVS bridge to manage
	BridgeName string

	// FlowController manages OpenFlow rules
	FlowController FlowController

	// PortController manages OVS port operations (VLAN, state)
	// If nil, uses FlowController if it implements OVSPortController
	PortController OVSPortController

	// Logger for the policy engine (uses slog.Default() if nil)
	Logger *slog.Logger

	// PolicyExtractor extracts policy from certificates
	PolicyExtractor PolicyExtractor

	// CertificateValidator validates certificates
	CertificateValidator CertificateValidator

	// EnableMonitoring enables certificate lifecycle monitoring
	EnableMonitoring bool

	// MonitorConfig configures the certificate monitor
	MonitorConfig MonitorConfig

	// ZoneFlowManager, when non-nil, enables zone-keyed flow installation.
	// When a PortPolicy carries a non-empty Zone, ApplyPolicy delegates VLAN
	// resolution and flow installation to the ZoneFlowManager instead of
	// calling SetPortVLAN + GenerateAuthorizationRules directly.
	ZoneFlowManager *ZoneFlowManager

	// Terminal is the action the engine's per-port allow rules end in; see
	// zoneflows.Terminal (#567).
	Terminal zoneflows.Terminal

	// Zones is the resolved zone set, used to identify the quarantine zone
	// (LifecycleRoleQuarantine). When nil, the default quarantine zone name
	// is used. A policy declaring the quarantine zone is refused when no
	// ZoneFlowManager is configured: the VLAN-direct fallback cannot
	// enforce isolation, so it must not silently authorize the port.
	Zones []zone.ZoneConfig
}

// PolicyEngine defines the interface for the policy engine
type PolicyEngine interface {
	// Port state management
	SetPortState(portID string, state PortState) error
	GetPortState(portID string) (PortState, error)
	GetPortInfo(portID string) (*PortInfo, error)

	// Policy management
	ApplyPolicy(portID string, policy *PortPolicy) error
	RemovePolicy(portID string) error
	GetPolicy(portID string) (*PortPolicy, error)

	// VLAN management
	SetPortVLAN(portID string, vlan uint16) error
	GetPortVLAN(portID string) (uint16, error)

	// Port operations
	BlockPort(portID string) error
	UnblockPort(portID string) error
	GetOFPort(portID string) (int32, error)

	// Certificate-based operations
	AuthenticatePort(portID string, cert *x509.Certificate) error
	OnCertificateExpired(portID string) error
	OnCertificateRevoked(portID string) error

	// Lifecycle
	GetMonitor() *CertificateMonitor
}

// NewEngine creates a new policy engine
func NewEngine(config Config) (*Engine, error) {
	if config.BridgeName == "" {
		return nil, &MessageError{Msg: "bridge name is required"}
	}

	if config.FlowController == nil {
		return nil, &MessageError{Msg: "flow controller is required"}
	}

	// Use defaults if not provided
	if config.PolicyExtractor == nil {
		config.PolicyExtractor = NewX509PolicyExtractor()
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Determine port controller
	portController := config.PortController
	if portController == nil {
		// Try to use FlowController if it implements OVSPortController
		if pc, ok := config.FlowController.(OVSPortController); ok {
			portController = pc
		} else {
			return nil, &MessageError{Msg: "port controller is required (FlowController must implement OVSPortController)"}
		}
	}

	quarantineZone := zone.ZoneQuarantine
	if qz, err := zone.ZoneForRole(config.Zones, zone.LifecycleRoleQuarantine); err == nil {
		quarantineZone = qz
	}

	engine := &Engine{
		logger:          logger,
		stateMachine:    NewPortStateMachine(),
		flowController:  config.FlowController,
		portController:  portController,
		extractor:       config.PolicyExtractor,
		validator:       config.CertificateValidator,
		ruleGenerator:   newRuleGeneratorWithTerminal(config.Terminal),
		bridgeName:      config.BridgeName,
		zoneFlowManager: config.ZoneFlowManager,
		quarantineZone:  quarantineZone,
	}

	// Setup monitoring if enabled
	if config.EnableMonitoring {
		engine.monitor = NewCertificateMonitor(engine, config.MonitorConfig)
	}

	return engine, nil
}

// SetPortState transitions a port to a new state
func (e *Engine) SetPortState(portID string, state PortState) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Get current state for potential rollback
	previousState, previousStateErr := e.stateMachine.GetState(portID)
	portExisted := previousStateErr == nil

	// Update state machine
	if err := e.stateMachine.SetState(portID, state); err != nil {
		return err
	}

	// Helper function to rollback state on flow installation failure
	rollbackState := func() {
		if portExisted {
			if rollbackErr := e.stateMachine.SetState(portID, previousState); rollbackErr != nil {
				e.logger.Warn("failed to rollback port state", "portID", portID, "error", rollbackErr)
			}
		} else {
			// Port didn't exist before, remove it
			if removeErr := e.stateMachine.RemovePort(portID); removeErr != nil {
				e.logger.Warn("failed to remove port during rollback", "portID", portID, "error", removeErr)
			}
		}
	}

	// Install appropriate flows based on state
	switch state {
	case PortStateUnconnected:
		// No flows for unconnected ports
		return nil

	case PortStateProvisioning:
		// No specific flows during provisioning
		return nil

	case PortStateEnrolled:
		// Device is enrolled but awaiting activation, no flow changes needed
		return nil

	case PortStateUnauthorized:
		if err := e.installUnauthorizedFlows(portID); err != nil {
			rollbackState()
			return err
		}
		return nil

	case PortStateAuthenticating:
		// No flow changes during authentication
		return nil

	case PortStateAuthorized:
		// Flows are installed when policy is applied
		return nil

	case PortStateQuarantined:
		// Quarantined ports get restricted flows (could be implemented later)
		return nil

	case PortStateBlocked:
		if err := e.installBlockedFlows(portID); err != nil {
			rollbackState()
			return err
		}
		return nil

	default:
		return ErrInvalidState
	}
}

// GetPortState returns the current state of a port
func (e *Engine) GetPortState(portID string) (PortState, error) {
	return e.stateMachine.GetState(portID)
}

// GetPortInfo returns detailed information about a port
func (e *Engine) GetPortInfo(portID string) (*PortInfo, error) {
	return e.stateMachine.GetInfo(portID)
}

// SetPortVLAN sets the VLAN tag for a port using OVSDB
func (e *Engine) SetPortVLAN(portID string, vlan uint16) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	if vlan < 1 || vlan > 4094 {
		return ErrInvalidVLAN
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Use port controller to set VLAN via OVSDB
	ctx := context.Background()
	if err := e.portController.SetPortVLAN(ctx, portID, int64(vlan)); err != nil {
		return &WrappedError{Msg: "failed to set port VLAN", Err: err}
	}

	e.logger.Info("set port VLAN",
		slog.String("port_id", portID),
		slog.Int("vlan", int(vlan)))

	return nil
}

// GetPortVLAN retrieves the VLAN assignment for a port from its policy
func (e *Engine) GetPortVLAN(portID string) (uint16, error) {
	if portID == "" {
		return 0, ErrInvalidPortID
	}

	policy, err := e.GetPolicy(portID)
	if err != nil {
		return 0, err
	}

	return policy.VLAN, nil
}

// BlockPort blocks a port by setting it to blocked state
func (e *Engine) BlockPort(portID string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	return e.SetPortState(portID, PortStateBlocked)
}

// UnblockPort unblocks a port by removing block flows and setting port to up
func (e *Engine) UnblockPort(portID string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Remove flows
	if err := e.removeFlows(portID); err != nil {
		return err
	}

	// Set port admin state to UP via OVSDB
	ctx := context.Background()
	if err := e.portController.SetPortState(ctx, portID, ovs.PortStateUp); err != nil {
		e.logger.Warn("failed to set port admin state to up",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
		// Don't fail the entire operation if OVSDB state change fails
	}

	// Transition to provisioning state
	if err := e.stateMachine.SetState(portID, PortStateProvisioning); err != nil {
		return err
	}

	e.logger.Info("unblocked port",
		slog.String("port_id", portID))

	return nil
}

// GetOFPort retrieves the OpenFlow port number for a port
func (e *Engine) GetOFPort(portID string) (int32, error) {
	if portID == "" {
		return 0, ErrInvalidPortID
	}

	ctx := context.Background()
	ofPort, err := e.portController.GetOFPort(ctx, portID)
	if err != nil {
		return 0, &WrappedError{Msg: "failed to get OF port", Err: err}
	}

	return ofPort, nil
}

// ApplyPolicy applies a security policy to a port
func (e *Engine) ApplyPolicy(portID string, policy *PortPolicy) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	if policy == nil {
		return ErrInvalidPolicy
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Validate policy
	if err := e.validatePolicy(policy); err != nil {
		return err
	}

	// A quarantine policy is only enforceable through the zone flow path.
	// Refuse before any state or datapath change rather than letting the
	// VLAN-direct fallback authorize the port.
	if err := e.requireZoneEnforcement(portID, policy); err != nil {
		return err
	}

	// Get current state to determine valid transitions
	currentState, err := e.stateMachine.GetState(portID)

	// Handle state transitions based on current state
	// Following 802.1X state machine: unconnected -> provisioning -> authenticating -> authorized
	// OR: unconnected -> provisioning -> enrolled -> authorized (with manual activation)
	switch {
	case err != nil:
		// Port doesn't exist (unconnected state), transition through provisioning
		if err := e.stateMachine.SetState(portID, PortStateProvisioning); err != nil {
			return err
		}
		if err := e.stateMachine.SetState(portID, PortStateAuthenticating); err != nil {
			return err
		}
	case currentState == PortStateUnauthorized || currentState == PortStateProvisioning:
		// Transition to authenticating from unauthorized or provisioning
		if err := e.stateMachine.SetState(portID, PortStateAuthenticating); err != nil {
			return err
		}
	case currentState == PortStateEnrolled:
		// Transition from enrolled to authenticating before authorization
		if err := e.stateMachine.SetState(portID, PortStateAuthenticating); err != nil {
			// Enrolled can go directly to Authorized, try that
			if err := e.stateMachine.SetState(portID, PortStateAuthorized); err != nil {
				return err
			}
			// If we successfully transitioned to Authorized, store policy and install flows
			goto applyPolicy
		}
	}

applyPolicy:
	// Store policy in state machine
	if err := e.stateMachine.SetPolicy(portID, policy); err != nil {
		return err
	}

	// When a zone is declared, delegate VLAN resolution + flow installation to
	// the ZoneFlowManager. When no ZoneFlowManager is configured, fall through
	// to the VLAN-direct path.
	if policy.Zone != "" && e.zoneFlowManager != nil {
		ctx := context.Background()
		if err := e.zoneFlowManager.ApplyZoneFlows(ctx, portID, policy.Zone); err != nil {
			_ = e.stateMachine.SetPolicy(portID, nil)
			_ = e.stateMachine.SetState(portID, PortStateUnauthorized)
			return &WrappedError{Msg: "engine: apply zone flows", Err: err}
		}
		// Populate VLAN on the policy from the resolved value so GetPortVLAN works.
		if v, err := e.zoneFlowManager.GetPortVLAN(portID); err == nil {
			policy.VLAN = v
		}
	} else if policy.VLAN > 0 {
		// Legacy VLAN-direct path: set VLAN via OVSDB first.
		ctx := context.Background()
		if err := e.portController.SetPortVLAN(ctx, portID, int64(policy.VLAN)); err != nil {
			// Rollback policy on VLAN configuration failure
			_ = e.stateMachine.SetPolicy(portID, nil)
			_ = e.stateMachine.SetState(portID, PortStateProvisioning)
			_ = e.stateMachine.SetState(portID, PortStateUnauthorized)
			return &WrappedError{Msg: "failed to set port VLAN", Err: err}
		}

		// Generate and install flows
		if err := e.installPolicyFlows(portID, policy); err != nil {
			// Rollback policy and VLAN on failure
			ctx := context.Background()
			_ = e.portController.SetPortVLAN(ctx, portID, 0)
			_ = e.stateMachine.SetPolicy(portID, nil)
			_ = e.stateMachine.SetState(portID, PortStateProvisioning)
			_ = e.stateMachine.SetState(portID, PortStateUnauthorized)
			return err
		}
	}

	// Get current state again to see if we already transitioned to Authorized
	currentState, err = e.stateMachine.GetState(portID)
	if err != nil {
		return err
	}

	// Only transition to authorized if we're not already there
	if currentState != PortStateAuthorized {
		// Transition to authorized state
		if err := e.stateMachine.SetState(portID, PortStateAuthorized); err != nil {
			// Rollback flows, VLAN, and policy on failure
			_ = e.removeFlows(portID)
			ctx := context.Background()
			_ = e.portController.SetPortVLAN(ctx, portID, 0)
			_ = e.stateMachine.SetPolicy(portID, nil)
			_ = e.stateMachine.SetState(portID, PortStateProvisioning)
			_ = e.stateMachine.SetState(portID, PortStateUnauthorized)
			return err
		}
	}

	e.logger.Info("applied policy to port",
		slog.String("port_id", portID),
		slog.String("tenant_id", policy.TenantID),
		slog.String("zone", string(policy.Zone)),
		slog.Int("vlan", int(policy.VLAN)),
		slog.Int("acl_count", len(policy.ACLs)))

	return nil
}

// RemovePolicy removes the policy from a port
func (e *Engine) RemovePolicy(portID string) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Remove flows
	if err := e.removeFlows(portID); err != nil {
		return err
	}

	// Also clean up zone flow manager state when configured.
	if e.zoneFlowManager != nil {
		if err := e.zoneFlowManager.RemoveFlows(portID); err != nil {
			e.logger.Warn("failed to remove zone flows",
				slog.String("port_id", portID),
				slog.String("error", err.Error()))
		}
	}

	// Remove VLAN assignment
	ctx := context.Background()
	if err := e.portController.SetPortVLAN(ctx, portID, 0); err != nil {
		e.logger.Warn("failed to clear port VLAN",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	// Remove policy from state machine
	if err := e.stateMachine.SetPolicy(portID, nil); err != nil {
		return err
	}

	// Get current state to determine proper transition
	currentState, err := e.stateMachine.GetState(portID)
	if err != nil {
		return err
	}

	// Transition based on current state
	// From authorized -> unauthorized requires going through proper transitions
	if currentState == PortStateAuthorized {
		if err := e.stateMachine.SetState(portID, PortStateUnauthorized); err != nil {
			return err
		}
	}

	e.logger.Info("removed policy from port",
		slog.String("port_id", portID))

	return nil
}

// GetPolicy returns the policy for a port
func (e *Engine) GetPolicy(portID string) (*PortPolicy, error) {
	info, err := e.stateMachine.GetInfo(portID)
	if err != nil {
		return nil, err
	}

	if info.Policy == nil {
		return nil, ErrPolicyNotFound
	}

	return info.Policy, nil
}

// AuthenticatePort authenticates a port using a certificate
func (e *Engine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	if portID == "" {
		return ErrInvalidPortID
	}

	if cert == nil {
		return ErrInvalidCertificate
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Get current state
	currentState, err := e.stateMachine.GetState(portID)
	if err != nil {
		// Port doesn't exist, need to go through provisioning first
		if err := e.stateMachine.SetState(portID, PortStateProvisioning); err != nil {
			return err
		}
		currentState = PortStateProvisioning
	}

	// Transition to authenticating state (valid from provisioning, enrolled, or unauthorized)
	if currentState == PortStateProvisioning || currentState == PortStateEnrolled || currentState == PortStateUnauthorized {
		if err := e.stateMachine.SetState(portID, PortStateAuthenticating); err != nil {
			return err
		}
	}

	// Increment auth attempts
	if err := e.stateMachine.IncrementAuthAttempts(portID); err != nil {
		e.logger.Warn("failed to increment auth attempts",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
	}

	// Validate certificate if validator is configured
	if e.validator != nil {
		if err := e.validator.ValidateCertificate(cert); err != nil {
			if recordErr := e.stateMachine.RecordError(portID, err); recordErr != nil {
				e.logger.Warn("failed to record error in state machine",
					slog.String("port_id", portID),
					slog.String("error", recordErr.Error()))
			}
			if stateErr := e.stateMachine.SetState(portID, PortStateUnauthorized); stateErr != nil {
				e.logger.Warn("failed to set port state to unauthorized",
					slog.String("port_id", portID),
					slog.String("error", stateErr.Error()))
			}
			return &WrappedError{Msg: "certificate validation failed", Err: err}
		}
	}

	// Extract policy from certificate
	policy, err := e.extractor.ExtractPolicy(cert)
	if err != nil {
		if recordErr := e.stateMachine.RecordError(portID, err); recordErr != nil {
			e.logger.Warn("failed to record error in state machine",
				slog.String("port_id", portID),
				slog.String("error", recordErr.Error()))
		}
		if stateErr := e.stateMachine.SetState(portID, PortStateUnauthorized); stateErr != nil {
			e.logger.Warn("failed to set port state to unauthorized",
				slog.String("port_id", portID),
				slog.String("error", stateErr.Error()))
		}
		return &WrappedError{Msg: "policy extraction failed", Err: err}
	}

	// Apply policy
	if err := e.applyPolicyInternal(portID, policy); err != nil {
		if recordErr := e.stateMachine.RecordError(portID, err); recordErr != nil {
			e.logger.Warn("failed to record error in state machine",
				slog.String("port_id", portID),
				slog.String("error", recordErr.Error()))
		}
		if stateErr := e.stateMachine.SetState(portID, PortStateUnauthorized); stateErr != nil {
			e.logger.Warn("failed to set port state to unauthorized",
				slog.String("port_id", portID),
				slog.String("error", stateErr.Error()))
		}
		return &WrappedError{Msg: "policy application failed", Err: err}
	}

	return nil
}

// OnCertificateExpired handles certificate expiry events
func (e *Engine) OnCertificateExpired(portID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Remove existing flows
	if err := e.removeFlows(portID); err != nil {
		return err
	}

	// Install blocked flows
	if err := e.installBlockedFlows(portID); err != nil {
		return err
	}

	// Transition to blocked state
	if err := e.stateMachine.SetState(portID, PortStateBlocked); err != nil {
		return err
	}

	e.logger.Warn("certificate expired, port blocked",
		slog.String("port_id", portID))

	return nil
}

// OnCertificateRevoked handles certificate revocation events
func (e *Engine) OnCertificateRevoked(portID string) error {
	return e.OnCertificateExpired(portID) // Same handling as expiry
}

// GetMonitor returns the certificate monitor
func (e *Engine) GetMonitor() *CertificateMonitor {
	return e.monitor
}

// validatePolicy validates a policy specification
func (e *Engine) validatePolicy(policy *PortPolicy) error {
	if policy.TenantID == "" {
		return ErrMissingTenantID
	}

	// When a zone is set the VLAN is resolved at apply time; skip VLAN validation.
	if policy.Zone == "" && (policy.VLAN < 1 || policy.VLAN > 4094) {
		return ErrInvalidVLAN
	}

	// Validate ACL rules
	for _, acl := range policy.ACLs {
		if acl.Priority < 0 {
			return ErrInvalidACL
		}
	}

	return nil
}

// requireZoneEnforcement refuses a policy that declares the quarantine zone
// when no ZoneFlowManager is configured. The VLAN-direct fallback applies
// PortPolicy.VLAN without zone isolation, so honoring such a policy would
// silently degrade a quarantine into an authorized port.
func (e *Engine) requireZoneEnforcement(portID string, policy *PortPolicy) error {
	if policy.Zone == "" || policy.Zone != e.quarantineZone || e.zoneFlowManager != nil {
		return nil
	}
	err := ErrZoneEnforcementUnavailable{PortID: portID, Zone: policy.Zone}
	e.logger.Error("refusing quarantine policy without zone flow enforcement",
		slog.String("port_id", portID),
		slog.String("zone", string(policy.Zone)),
		slog.String("error", err.Error()))
	return err
}

// applyPolicyInternal applies policy without acquiring the lock
func (e *Engine) applyPolicyInternal(portID string, policy *PortPolicy) error {
	// Validate policy
	if err := e.validatePolicy(policy); err != nil {
		return err
	}

	// A quarantine policy is only enforceable through the zone flow path.
	if err := e.requireZoneEnforcement(portID, policy); err != nil {
		return err
	}

	// Store policy
	if err := e.stateMachine.SetPolicy(portID, policy); err != nil {
		return err
	}

	// Zone path: delegate to ZoneFlowManager when zone is set.
	if policy.Zone != "" && e.zoneFlowManager != nil {
		ctx := context.Background()
		if err := e.zoneFlowManager.ApplyZoneFlows(ctx, portID, policy.Zone); err != nil {
			_ = e.stateMachine.SetPolicy(portID, nil)
			return &WrappedError{Msg: "engine: apply zone flows", Err: err}
		}
		if v, err := e.zoneFlowManager.GetPortVLAN(portID); err == nil {
			policy.VLAN = v
		}
	} else if policy.VLAN > 0 {
		// Legacy VLAN-direct path
		ctx := context.Background()
		if err := e.portController.SetPortVLAN(ctx, portID, int64(policy.VLAN)); err != nil {
			_ = e.stateMachine.SetPolicy(portID, nil)
			return &WrappedError{Msg: "failed to set port VLAN", Err: err}
		}

		// Install flows
		if err := e.installPolicyFlows(portID, policy); err != nil {
			ctx := context.Background()
			_ = e.portController.SetPortVLAN(ctx, portID, 0)
			_ = e.stateMachine.SetPolicy(portID, nil)
			return err
		}
	}

	// Transition to authorized
	if err := e.stateMachine.SetState(portID, PortStateAuthorized); err != nil {
		_ = e.removeFlows(portID)
		ctx := context.Background()
		_ = e.portController.SetPortVLAN(ctx, portID, 0)
		_ = e.stateMachine.SetPolicy(portID, nil)
		return err
	}

	return nil
}

// installPolicyFlows installs OpenFlow rules for a policy
func (e *Engine) installPolicyFlows(portID string, policy *PortPolicy) error {
	rules, err := e.ruleGenerator.GenerateAuthorizationRules(portID, policy)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		if err := e.flowController.InstallFlow(
			e.bridgeName,
			rule.Priority,
			rule.Match,
			rule.Actions,
		); err != nil {
			// Attempt to clean up on error
			_ = e.removeFlows(portID)
			return &SentinelCauseError{Sentinel: ErrFlowInstallFailed, Cause: err}
		}
	}

	e.logger.Debug("installed policy flows",
		slog.String("port_id", portID),
		slog.Int("flow_count", len(rules)))

	return nil
}

// installUnauthorizedFlows installs flows for unauthorized ports
func (e *Engine) installUnauthorizedFlows(portID string) error {
	rules := e.ruleGenerator.GenerateUnauthorizedRules(portID)

	for _, rule := range rules {
		if err := e.flowController.InstallFlow(
			e.bridgeName,
			rule.Priority,
			rule.Match,
			rule.Actions,
		); err != nil {
			return &SentinelCauseError{Sentinel: ErrFlowInstallFailed, Cause: err}
		}
	}

	e.logger.Debug("installed unauthorized flows",
		slog.String("port_id", portID),
		slog.Int("flow_count", len(rules)))

	return nil
}

// installBlockedFlows installs flows to block a port
// This method uses both OpenFlow DROP rules AND OVSDB admin_state for defense in depth
func (e *Engine) installBlockedFlows(portID string) error {
	// Install DROP rules via OpenFlow
	rules := e.ruleGenerator.GenerateBlockRules(portID)

	for _, rule := range rules {
		if err := e.flowController.InstallFlow(
			e.bridgeName,
			rule.Priority,
			rule.Match,
			rule.Actions,
		); err != nil {
			return &SentinelCauseError{Sentinel: ErrFlowInstallFailed, Cause: err}
		}
	}

	// Additionally, set port admin state to DOWN via OVSDB for defense in depth
	ctx := context.Background()
	if err := e.portController.SetPortState(ctx, portID, ovs.PortStateDown); err != nil {
		e.logger.Warn("failed to set port admin state to down",
			slog.String("port_id", portID),
			slog.String("error", err.Error()))
		// Don't fail the entire operation if OVSDB state change fails
		// The DROP rules are the primary blocking mechanism
	}

	e.logger.Info("installed blocked flows",
		slog.String("port_id", portID),
		slog.Int("flow_count", len(rules)))

	return nil
}

// removeFlows removes all flows for a port
func (e *Engine) removeFlows(portID string) error {
	if err := e.flowController.DeleteFlowsByPort(e.bridgeName, portID); err != nil {
		return &SentinelCauseError{Sentinel: ErrFlowDeleteFailed, Cause: err}
	}

	e.logger.Debug("removed flows for port",
		slog.String("port_id", portID))

	return nil
}
