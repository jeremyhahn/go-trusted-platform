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

package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// FlowRuleType represents the type of flow rule.
type FlowRuleType string

// Flow rule type constants.
const (
	FlowRuleTypeQuarantine FlowRuleType = "quarantine"
	FlowRuleTypeProduction FlowRuleType = "production"
	FlowRuleTypeDrop       FlowRuleType = "drop"
	FlowRuleTypeRedirect   FlowRuleType = "redirect"
	FlowRuleTypeRateLimit  FlowRuleType = "rate_limit"
	FlowRuleTypeMonitor    FlowRuleType = "monitor"
)

// String returns the string representation of FlowRuleType.
func (t FlowRuleType) String() string {
	return string(t)
}

// IsValid returns true if the flow rule type is valid.
func (t FlowRuleType) IsValid() bool {
	switch t {
	case FlowRuleTypeQuarantine, FlowRuleTypeProduction, FlowRuleTypeDrop,
		FlowRuleTypeRedirect, FlowRuleTypeRateLimit, FlowRuleTypeMonitor:
		return true
	default:
		return false
	}
}

// FlowRule represents an OpenFlow rule.
type FlowRule struct {
	// ID is the unique identifier for this rule.
	ID string

	// PortID is the port this rule applies to.
	PortID string

	// Type is the type of flow rule.
	Type FlowRuleType

	// Priority is the rule priority (higher = more important).
	Priority uint16

	// VLAN is the VLAN ID for this rule.
	VLAN uint16

	// Match contains the match criteria.
	Match *FlowMatch

	// Actions contains the actions to apply.
	Actions []FlowAction

	// CreatedAt is when the rule was created.
	CreatedAt time.Time

	// ExpiresAt is when the rule expires (zero = never).
	ExpiresAt time.Time

	// Metadata contains additional rule metadata.
	Metadata map[string]string
}

// IsExpired returns true if the rule has expired.
func (r *FlowRule) IsExpired() bool {
	if r.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(r.ExpiresAt)
}

// FlowMatch contains OpenFlow match criteria.
type FlowMatch struct {
	// InPort is the input port number.
	InPort uint32

	// EthSrc is the source MAC address.
	EthSrc string

	// EthDst is the destination MAC address.
	EthDst string

	// EthType is the Ethernet type.
	EthType uint16

	// VLANID is the VLAN ID to match.
	VLANID uint16

	// IPSrc is the source IP address/prefix.
	IPSrc string

	// IPDst is the destination IP address/prefix.
	IPDst string

	// IPProto is the IP protocol number.
	IPProto uint8

	// SrcPort is the source TCP/UDP port.
	SrcPort uint16

	// DstPort is the destination TCP/UDP port.
	DstPort uint16
}

// FlowActionType represents the type of flow action.
type FlowActionType string

// Flow action type constants.
const (
	FlowActionTypeOutput     FlowActionType = "output"
	FlowActionTypeDrop       FlowActionType = "drop"
	FlowActionTypeSetVLAN    FlowActionType = "set_vlan"
	FlowActionTypeStripVLAN  FlowActionType = "strip_vlan"
	FlowActionTypeSetField   FlowActionType = "set_field"
	FlowActionTypeController FlowActionType = "controller"
	FlowActionTypeFlood      FlowActionType = "flood"
)

// FlowAction represents an OpenFlow action.
type FlowAction struct {
	// Type is the action type.
	Type FlowActionType

	// Port is the output port for output actions.
	Port uint32

	// VLAN is the VLAN ID for VLAN actions.
	VLAN uint16

	// Field is the field name for set_field actions.
	Field string

	// Value is the value for set_field actions.
	Value string
}

// FlowManager manages OpenFlow rules.
type FlowManager interface {
	// Initialize sets up the flow manager.
	Initialize(ctx context.Context, config *FlowConfig) error

	// InstallQuarantineRules installs quarantine rules for a port.
	InstallQuarantineRules(ctx context.Context, portID string, vlan uint16) error

	// InstallProductionRules installs production rules for a port.
	InstallProductionRules(ctx context.Context, portID string, vlan uint16) error

	// RemoveRules removes all rules for a port.
	RemoveRules(ctx context.Context, portID string) error

	// GetRules returns all rules for a port.
	GetRules(ctx context.Context, portID string) ([]*FlowRule, error)

	// InstallRule installs a custom flow rule.
	InstallRule(ctx context.Context, rule *FlowRule) error

	// RemoveRule removes a specific flow rule.
	RemoveRule(ctx context.Context, ruleID string) error

	// TransitionVLAN atomically transitions a port from one VLAN to another.
	TransitionVLAN(ctx context.Context, portID string, fromVLAN uint16, toVLAN uint16) error

	// Close releases resources.
	Close() error
}

// FlowConfig contains configuration for the flow manager.
type FlowConfig struct {
	// BridgeName is the OVS bridge name.
	BridgeName string

	// ControllerAddress is the OpenFlow controller address.
	ControllerAddress string

	// DefaultPriority is the default rule priority.
	DefaultPriority uint16

	// QuarantinePriority is the priority for quarantine rules.
	QuarantinePriority uint16

	// ProductionPriority is the priority for production rules.
	ProductionPriority uint16

	// RuleTimeout is the default timeout for rules (0 = no timeout).
	RuleTimeout time.Duration
}

// Validate validates the FlowConfig fields.
func (c *FlowConfig) Validate() error {
	if c.BridgeName == "" {
		return ErrInvalidConfig{Field: "BridgeName", Reason: "bridge name cannot be empty"}
	}
	if c.DefaultPriority == 0 {
		c.DefaultPriority = 100
	}
	if c.QuarantinePriority == 0 {
		c.QuarantinePriority = 200
	}
	if c.ProductionPriority == 0 {
		c.ProductionPriority = 300
	}
	return nil
}

// ruleIDList wraps a slice to make it comparable for sync.Map operations.
// Since slices are not comparable in Go, we use a pointer wrapper.
type ruleIDList struct {
	ids []string
}

// flowManager is the concrete implementation of FlowManager.
type flowManager struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *FlowConfig
	rules       sync.Map // map[string]*FlowRule (ruleID -> rule)
	portRules   sync.Map // map[string]*ruleIDList (portID -> ruleIDs)
	controller  FlowController
	logger      *slog.Logger
}

// FlowController provides the actual OpenFlow operations.
// This interface allows for different implementations (OVS, hardware switches, etc.)
type FlowController interface {
	// AddFlow adds a flow rule to the switch.
	AddFlow(ctx context.Context, bridge string, rule *FlowRule) error

	// DeleteFlow removes a flow rule from the switch.
	DeleteFlow(ctx context.Context, bridge string, ruleID string) error

	// ModifyFlow modifies an existing flow rule.
	ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error

	// GetFlows returns all flows for a bridge.
	GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error)

	// SetPortVLAN sets the VLAN tag for a port.
	SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error
}

// FlowManagerOption configures a flow manager.
type FlowManagerOption func(*flowManager)

// WithFlowManagerLogger sets the logger for the flow manager.
func WithFlowManagerLogger(logger *slog.Logger) FlowManagerOption {
	return func(f *flowManager) {
		f.logger = logger
	}
}

// WithFlowController sets the flow controller for the flow manager.
func WithFlowController(controller FlowController) FlowManagerOption {
	return func(f *flowManager) {
		f.controller = controller
	}
}

// NewFlowManager creates a new flow manager.
func NewFlowManager(opts ...FlowManagerOption) FlowManager {
	f := &flowManager{}

	for _, opt := range opts {
		opt(f)
	}

	if f.logger == nil {
		f.logger = slog.Default()
	}

	return f
}

// Initialize sets up the flow manager.
func (f *flowManager) Initialize(ctx context.Context, config *FlowConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if f.initialized.Load() {
		return ErrInvalidConfig{Reason: "flow manager already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	if err := config.Validate(); err != nil {
		return err
	}

	f.config = config
	f.initialized.Store(true)

	f.logger.Info("flow manager initialized",
		"bridge", config.BridgeName,
		"controller", config.ControllerAddress,
	)

	return nil
}

// InstallQuarantineRules installs quarantine rules for a port.
func (f *flowManager) InstallQuarantineRules(ctx context.Context, portID string, vlan uint16) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "InstallQuarantineRules"}
	default:
	}

	if !f.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if f.closed.Load() {
		return ErrServiceNotInitialized{}
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	// Create quarantine ingress rule
	ingressRule := &FlowRule{
		ID:       generateRuleID(portID, "quarantine", "ingress"),
		PortID:   portID,
		Type:     FlowRuleTypeQuarantine,
		Priority: f.config.QuarantinePriority,
		VLAN:     vlan,
		Match: &FlowMatch{
			VLANID: vlan,
		},
		Actions: []FlowAction{
			{Type: FlowActionTypeSetVLAN, VLAN: vlan},
			{Type: FlowActionTypeController},
		},
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]string{"direction": "ingress"},
	}

	// Create quarantine egress rule (limited access)
	egressRule := &FlowRule{
		ID:       generateRuleID(portID, "quarantine", "egress"),
		PortID:   portID,
		Type:     FlowRuleTypeQuarantine,
		Priority: f.config.QuarantinePriority,
		VLAN:     vlan,
		Match: &FlowMatch{
			VLANID: vlan,
		},
		Actions: []FlowAction{
			{Type: FlowActionTypeSetVLAN, VLAN: vlan},
			{Type: FlowActionTypeOutput},
		},
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]string{"direction": "egress"},
	}

	// Install rules
	if err := f.InstallRule(ctx, ingressRule); err != nil {
		return err
	}

	if err := f.InstallRule(ctx, egressRule); err != nil {
		// Rollback ingress rule
		_ = f.RemoveRule(ctx, ingressRule.ID)
		return err
	}

	// Set port VLAN if controller is available
	if f.controller != nil {
		if err := f.controller.SetPortVLAN(ctx, f.config.BridgeName, portID, vlan); err != nil {
			f.logger.Warn("failed to set port VLAN",
				"port_id", portID,
				"vlan", vlan,
				"error", err,
			)
		}
	}

	f.logger.Info("installed quarantine rules",
		"port_id", portID,
		"vlan", vlan,
	)

	return nil
}

// InstallProductionRules installs production rules for a port.
func (f *flowManager) InstallProductionRules(ctx context.Context, portID string, vlan uint16) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "InstallProductionRules"}
	default:
	}

	if !f.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if f.closed.Load() {
		return ErrServiceNotInitialized{}
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	// Create production ingress rule
	ingressRule := &FlowRule{
		ID:       generateRuleID(portID, "production", "ingress"),
		PortID:   portID,
		Type:     FlowRuleTypeProduction,
		Priority: f.config.ProductionPriority,
		VLAN:     vlan,
		Match: &FlowMatch{
			VLANID: vlan,
		},
		Actions: []FlowAction{
			{Type: FlowActionTypeSetVLAN, VLAN: vlan},
			{Type: FlowActionTypeFlood},
		},
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]string{"direction": "ingress"},
	}

	// Create production egress rule (full access)
	egressRule := &FlowRule{
		ID:       generateRuleID(portID, "production", "egress"),
		PortID:   portID,
		Type:     FlowRuleTypeProduction,
		Priority: f.config.ProductionPriority,
		VLAN:     vlan,
		Match: &FlowMatch{
			VLANID: vlan,
		},
		Actions: []FlowAction{
			{Type: FlowActionTypeSetVLAN, VLAN: vlan},
			{Type: FlowActionTypeOutput},
		},
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]string{"direction": "egress"},
	}

	// Install rules
	if err := f.InstallRule(ctx, ingressRule); err != nil {
		return err
	}

	if err := f.InstallRule(ctx, egressRule); err != nil {
		// Rollback ingress rule
		_ = f.RemoveRule(ctx, ingressRule.ID)
		return err
	}

	// Set port VLAN if controller is available
	if f.controller != nil {
		if err := f.controller.SetPortVLAN(ctx, f.config.BridgeName, portID, vlan); err != nil {
			f.logger.Warn("failed to set port VLAN",
				"port_id", portID,
				"vlan", vlan,
				"error", err,
			)
		}
	}

	f.logger.Info("installed production rules",
		"port_id", portID,
		"vlan", vlan,
	)

	return nil
}

// RemoveRules removes all rules for a port.
func (f *flowManager) RemoveRules(ctx context.Context, portID string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "RemoveRules"}
	default:
	}

	if !f.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	// Get rule IDs for this port
	ruleListVal, ok := f.portRules.Load(portID)
	if !ok {
		return nil // No rules to remove
	}

	ruleList := ruleListVal.(*ruleIDList)
	var errors []error

	for _, ruleID := range ruleList.ids {
		if err := f.RemoveRule(ctx, ruleID); err != nil {
			errors = append(errors, err)
		}
	}

	// Clear port rules mapping
	f.portRules.Delete(portID)

	if len(errors) > 0 {
		return ErrFlowRule{
			PortID:    portID,
			Operation: "RemoveRules",
			Reason:    "some rules failed to remove",
		}
	}

	f.logger.Info("removed all rules for port",
		"port_id", portID,
		"rule_count", len(ruleList.ids),
	)

	return nil
}

// GetRules returns all rules for a port.
func (f *flowManager) GetRules(ctx context.Context, portID string) ([]*FlowRule, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetRules"}
	default:
	}

	if !f.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if portID == "" {
		return nil, ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	ruleListVal, ok := f.portRules.Load(portID)
	if !ok {
		return []*FlowRule{}, nil
	}

	ruleList := ruleListVal.(*ruleIDList)
	rules := make([]*FlowRule, 0, len(ruleList.ids))

	for _, ruleID := range ruleList.ids {
		if ruleVal, ok := f.rules.Load(ruleID); ok {
			rules = append(rules, ruleVal.(*FlowRule))
		}
	}

	return rules, nil
}

// InstallRule installs a custom flow rule.
func (f *flowManager) InstallRule(ctx context.Context, rule *FlowRule) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "InstallRule"}
	default:
	}

	if !f.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if f.closed.Load() {
		return ErrServiceNotInitialized{}
	}

	if rule == nil {
		return ErrInvalidConfig{Reason: "rule cannot be nil"}
	}

	if rule.ID == "" {
		return ErrInvalidConfig{Field: "ID", Reason: "rule ID cannot be empty"}
	}

	// Add to controller if available
	if f.controller != nil {
		if err := f.controller.AddFlow(ctx, f.config.BridgeName, rule); err != nil {
			return ErrFlowRule{
				PortID:    rule.PortID,
				RuleID:    rule.ID,
				Operation: "InstallRule",
				Reason:    "failed to add flow",
				Cause:     err,
			}
		}
	}

	// Store rule
	f.rules.Store(rule.ID, rule)

	// Update port rules mapping
	f.addPortRule(rule.PortID, rule.ID)

	f.logger.Debug("installed flow rule",
		"rule_id", rule.ID,
		"port_id", rule.PortID,
		"type", rule.Type,
		"priority", rule.Priority,
	)

	return nil
}

// RemoveRule removes a specific flow rule.
func (f *flowManager) RemoveRule(ctx context.Context, ruleID string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "RemoveRule"}
	default:
	}

	if !f.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if ruleID == "" {
		return ErrInvalidConfig{Field: "ruleID", Reason: "rule ID cannot be empty"}
	}

	// Get rule to find port ID
	ruleVal, ok := f.rules.Load(ruleID)
	if !ok {
		return nil // Rule not found, nothing to do
	}

	rule := ruleVal.(*FlowRule)

	// Remove from controller if available
	if f.controller != nil {
		if err := f.controller.DeleteFlow(ctx, f.config.BridgeName, ruleID); err != nil {
			return ErrFlowRule{
				PortID:    rule.PortID,
				RuleID:    ruleID,
				Operation: "RemoveRule",
				Reason:    "failed to delete flow",
				Cause:     err,
			}
		}
	}

	// Remove from storage
	f.rules.Delete(ruleID)
	f.removePortRule(rule.PortID, ruleID)

	f.logger.Debug("removed flow rule",
		"rule_id", ruleID,
		"port_id", rule.PortID,
	)

	return nil
}

// TransitionVLAN atomically transitions a port from one VLAN to another.
func (f *flowManager) TransitionVLAN(ctx context.Context, portID string, fromVLAN uint16, toVLAN uint16) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "TransitionVLAN"}
	default:
	}

	if !f.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if f.closed.Load() {
		return ErrServiceNotInitialized{}
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	if fromVLAN == toVLAN {
		return nil // No transition needed
	}

	f.logger.Info("transitioning VLAN",
		"port_id", portID,
		"from_vlan", fromVLAN,
		"to_vlan", toVLAN,
	)

	// Determine rule types based on VLAN
	var installFunc func(context.Context, string, uint16) error
	if toVLAN == f.config.QuarantinePriority {
		installFunc = f.InstallQuarantineRules
	} else {
		installFunc = f.InstallProductionRules
	}

	// Install new rules first (make-before-break)
	if err := installFunc(ctx, portID, toVLAN); err != nil {
		return ErrVLANFailed{
			PortID:   portID,
			FromVLAN: fromVLAN,
			ToVLAN:   toVLAN,
			Reason:   "failed to install new rules",
			Cause:    err,
		}
	}

	// Remove old rules
	// Note: We keep the new rules even if old rule removal fails
	// to ensure the port remains accessible
	oldRules, _ := f.GetRules(ctx, portID)
	for _, rule := range oldRules {
		if rule.VLAN == fromVLAN {
			if err := f.RemoveRule(ctx, rule.ID); err != nil {
				f.logger.Warn("failed to remove old rule during VLAN transition",
					"rule_id", rule.ID,
					"error", err,
				)
			}
		}
	}

	f.logger.Info("VLAN transition complete",
		"port_id", portID,
		"from_vlan", fromVLAN,
		"to_vlan", toVLAN,
	)

	return nil
}

// Close releases resources.
func (f *flowManager) Close() error {
	if f.closed.Swap(true) {
		return nil
	}

	f.logger.Info("flow manager closed")
	return nil
}

// addPortRule adds a rule ID to the port's rule list using lock-free CAS pattern.
func (f *flowManager) addPortRule(portID string, ruleID string) {
	for {
		existing, loaded := f.portRules.Load(portID)

		var currentList *ruleIDList
		if loaded && existing != nil {
			currentList = existing.(*ruleIDList)
			// Check if already exists
			for _, id := range currentList.ids {
				if id == ruleID {
					return
				}
			}
		}

		// Create new list with the added rule ID
		var newIDs []string
		if currentList != nil {
			newIDs = make([]string, len(currentList.ids), len(currentList.ids)+1)
			copy(newIDs, currentList.ids)
		}
		newIDs = append(newIDs, ruleID)
		newList := &ruleIDList{ids: newIDs}

		if !loaded {
			// Key doesn't exist - use LoadOrStore to atomically insert
			_, wasLoaded := f.portRules.LoadOrStore(portID, newList)
			if !wasLoaded {
				// Successfully stored new list
				return
			}
			// Someone else stored first, retry from the beginning
			continue
		}

		// Key exists - use CompareAndSwap with pointer comparison
		if f.portRules.CompareAndSwap(portID, existing, newList) {
			return
		}
		// CAS failed, retry from the beginning
	}
}

// removePortRule removes a rule ID from the port's rule list using lock-free CAS pattern.
func (f *flowManager) removePortRule(portID string, ruleID string) {
	for {
		existing, ok := f.portRules.Load(portID)
		if !ok {
			return
		}

		currentList := existing.(*ruleIDList)
		newIDs := make([]string, 0, len(currentList.ids))
		found := false
		for _, id := range currentList.ids {
			if id != ruleID {
				newIDs = append(newIDs, id)
			} else {
				found = true
			}
		}

		if !found {
			// Rule not in list
			return
		}

		newList := &ruleIDList{ids: newIDs}
		if f.portRules.CompareAndSwap(portID, existing, newList) {
			return
		}
		// CAS failed, retry
	}
}

// generateRuleID generates a unique rule ID.
func generateRuleID(portID string, ruleType string, direction string) string {
	data := portID + ruleType + direction + time.Now().Format(time.RFC3339Nano)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}
