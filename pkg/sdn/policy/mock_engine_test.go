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
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// StatefulMockPolicyEngine is a stateful mock implementation of PolicyEngine for testing
// This differs from MockPolicyEngine which uses testify mocks
type StatefulMockPolicyEngine struct {
	mu           sync.RWMutex
	portStates   map[string]PortState
	portPolicies map[string]*PortPolicy
	portPhases   map[string]NetworkPhase
	flowRules    map[string][]FlowRule
}

// NetworkPhase represents network access phases for testing
type NetworkPhase int

const (
	NetworkPhaseProvisioning NetworkPhase = iota
	NetworkPhaseProduction
	NetworkPhaseQuarantine
	NetworkPhaseBlocked
)

// NewStatefulMockPolicyEngine creates a new stateful mock policy engine
func NewStatefulMockPolicyEngine() *StatefulMockPolicyEngine {
	return &StatefulMockPolicyEngine{
		portStates:   make(map[string]PortState),
		portPolicies: make(map[string]*PortPolicy),
		portPhases:   make(map[string]NetworkPhase),
		flowRules:    make(map[string][]FlowRule),
	}
}

// ApplyPolicy applies a port policy
func (m *StatefulMockPolicyEngine) ApplyPolicy(portID string, policy *PortPolicy) error {
	if policy == nil {
		return &MessageError{Msg: "policy cannot be nil"}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Store policy
	m.portPolicies[portID] = policy

	// Convert policy to flow rules
	rules := m.policyToFlowRules(portID, policy)
	m.flowRules[portID] = rules

	// Transition to authorized state when production policy is applied
	if policy.VLAN > 100 { // Production VLAN
		m.portStates[portID] = PortStateAuthorized
		m.portPhases[portID] = NetworkPhaseProduction
	}

	return nil
}

// GetPortPolicy retrieves the policy for a port
func (m *StatefulMockPolicyEngine) GetPortPolicy(portID string) (*PortPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, ok := m.portPolicies[portID]
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("no policy found for port %s", portID)}
	}

	return policy, nil
}

// SetPortState sets the state of a port
func (m *StatefulMockPolicyEngine) SetPortState(portID string, state PortState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.portStates[portID] = state

	// Update phase based on state
	switch state {
	case PortStateProvisioning:
		m.portPhases[portID] = NetworkPhaseProvisioning
	case PortStateAuthorized:
		m.portPhases[portID] = NetworkPhaseProduction
	case PortStateQuarantined:
		m.portPhases[portID] = NetworkPhaseQuarantine
	case PortStateBlocked:
		m.portPhases[portID] = NetworkPhaseBlocked
	}

	return nil
}

// GetPortState retrieves the current state of a port
func (m *StatefulMockPolicyEngine) GetPortState(portID string) (PortState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.portStates[portID]
	if !ok {
		return PortStateUnconnected, &MessageError{Msg: fmt.Sprintf("port %s not found", portID)}
	}

	return state, nil
}

// GetPortPhase retrieves the current network phase of a port
func (m *StatefulMockPolicyEngine) GetPortPhase(portID string) (NetworkPhase, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	phase, ok := m.portPhases[portID]
	if !ok {
		return NetworkPhaseProvisioning, &MessageError{Msg: fmt.Sprintf("port %s not found", portID)}
	}

	return phase, nil
}

// RemovePolicy removes the policy from a port
func (m *StatefulMockPolicyEngine) RemovePolicy(portID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.portPolicies, portID)
	delete(m.flowRules, portID)

	return nil
}

// GetFlowRules retrieves the flow rules for a port
func (m *StatefulMockPolicyEngine) GetFlowRules(portID string) ([]FlowRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rules, ok := m.flowRules[portID]
	if !ok {
		return nil, &MessageError{Msg: fmt.Sprintf("no flow rules found for port %s", portID)}
	}

	return rules, nil
}

// QuarantinePort moves a port to quarantine
func (m *StatefulMockPolicyEngine) QuarantinePort(portID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.portStates[portID] = PortStateQuarantined
	m.portPhases[portID] = NetworkPhaseQuarantine

	// Create quarantine policy
	policy := &PortPolicy{
		VLAN:     999, // Quarantine VLAN
		IssuedAt: time.Now(),
		Metadata: map[string]string{
			"quarantine_reason": reason,
		},
	}
	m.portPolicies[portID] = policy

	return nil
}

// BlockPort completely blocks a port
func (m *StatefulMockPolicyEngine) BlockPort(portID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.portStates[portID] = PortStateBlocked
	m.portPhases[portID] = NetworkPhaseBlocked

	// Remove all flow rules
	delete(m.flowRules, portID)

	// Create block policy
	policy := &PortPolicy{
		VLAN:     0, // No VLAN
		IssuedAt: time.Now(),
		Metadata: map[string]string{
			"block_reason": reason,
		},
	}
	m.portPolicies[portID] = policy

	return nil
}

// ValidateCertificate validates a certificate against revocation lists
func (m *StatefulMockPolicyEngine) ValidateCertificate(cert *x509.Certificate) error {
	// Mock implementation - always valid
	// In real implementation, would check CRL/OCSP
	return nil
}

// policyToFlowRules converts a PortPolicy to OpenFlow rules
func (m *StatefulMockPolicyEngine) policyToFlowRules(portID string, policy *PortPolicy) []FlowRule {
	var rules []FlowRule

	// Add VLAN tagging rule
	if policy.VLAN > 0 {
		rules = append(rules, FlowRule{
			Priority: 1000,
			Match:    fmt.Sprintf("in_port=%s", portID),
			Actions:  fmt.Sprintf("mod_vlan_vid:%d,NORMAL", policy.VLAN),
		})
	}

	// Add ACL rules
	for _, acl := range policy.ACLs {
		rules = append(rules, FlowRule{
			Priority: acl.Priority,
			Match:    acl.Match.InPort, // Use the InPort field from the FlowMatch
			Actions:  string(acl.Action.Type),
		})
	}

	return rules
}

// Note: FlowRule, FlowMatch, FlowAction, FlowActionType are defined in types.go and rules.go
