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
	"crypto/x509"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// NetworkAuthService provides certificate-based network port authentication
// with VLAN transitions, attestation integration, and OPA policy evaluation.
type NetworkAuthService interface {
	// Initialize sets up the authentication service.
	Initialize(ctx context.Context, config *AuthConfig) error

	// Authenticate performs full authentication for a port.
	// Flow: mTLS -> extract OIDs -> attest -> OPA evaluate -> OpenFlow rules -> VLAN transition
	Authenticate(ctx context.Context, request *PortAuthRequest) (*AuthResult, error)

	// Reattest performs re-attestation for an already authenticated port.
	Reattest(ctx context.Context, portID string, nonce []byte) (*AuthResult, error)

	// Revoke revokes authentication for a port and moves it to quarantine.
	Revoke(ctx context.Context, portID string, reason string) error

	// GetPortState returns the current state of a port.
	GetPortState(ctx context.Context, portID string) (*PortState, error)

	// GetAllPorts returns all tracked port states.
	GetAllPorts(ctx context.Context) ([]*PortState, error)

	// Close releases resources held by the service.
	Close() error
}

// AttestationVerifier verifies TPM attestation for devices.
type AttestationVerifier interface {
	// Verify verifies the attestation for a device.
	Verify(ctx context.Context, deviceID string, nonce []byte, expectedPCRs map[int][]byte) (bool, error)
}

// networkAuthService is the concrete implementation of NetworkAuthService.
type networkAuthService struct {
	initialized atomic.Bool
	closed      atomic.Bool
	config      *AuthConfig
	portStates  sync.Map // map[string]*PortState
	certPool    *x509.CertPool

	policyExtractor      PolicyExtractor
	opaEvaluator         OPAEvaluator
	opaEvaluatorExternal bool // true if OPA evaluator was externally provided
	flowManager          FlowManager
	flowManagerExternal  bool // true if flow manager was externally provided
	attestVerifier       AttestationVerifier
	logger               *slog.Logger
}

// NetworkAuthServiceOption configures a network authentication service.
type NetworkAuthServiceOption func(*networkAuthService)

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) NetworkAuthServiceOption {
	return func(s *networkAuthService) {
		s.logger = logger
	}
}

// WithPolicyExtractor sets the policy extractor for the service.
func WithPolicyExtractor(extractor PolicyExtractor) NetworkAuthServiceOption {
	return func(s *networkAuthService) {
		s.policyExtractor = extractor
	}
}

// WithOPAEvaluator sets the OPA evaluator for the service.
// When provided, the evaluator should already be initialized.
func WithOPAEvaluator(evaluator OPAEvaluator) NetworkAuthServiceOption {
	return func(s *networkAuthService) {
		s.opaEvaluator = evaluator
		s.opaEvaluatorExternal = true
	}
}

// WithFlowManager sets the flow manager for the service.
// When provided, the manager should already be initialized.
func WithFlowManager(manager FlowManager) NetworkAuthServiceOption {
	return func(s *networkAuthService) {
		s.flowManager = manager
		s.flowManagerExternal = true
	}
}

// WithAttestationVerifier sets the attestation verifier for the service.
func WithAttestationVerifier(verifier AttestationVerifier) NetworkAuthServiceOption {
	return func(s *networkAuthService) {
		s.attestVerifier = verifier
	}
}

// NewNetworkAuthService creates a new network authentication service.
func NewNetworkAuthService(opts ...NetworkAuthServiceOption) NetworkAuthService {
	s := &networkAuthService{}

	for _, opt := range opts {
		opt(s)
	}

	if s.logger == nil {
		s.logger = slog.Default()
	}

	return s
}

// Initialize sets up the authentication service.
func (s *networkAuthService) Initialize(ctx context.Context, config *AuthConfig) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Initialize"}
	default:
	}

	if s.initialized.Load() {
		return ErrInvalidConfig{Reason: "service already initialized"}
	}

	if config == nil {
		return ErrInvalidConfig{Reason: "configuration cannot be nil"}
	}

	// Validate config, but skip OPA endpoint validation if external evaluator provided
	if err := s.validateConfig(config); err != nil {
		return err
	}

	// Build trusted CA certificate pool
	s.certPool = x509.NewCertPool()
	for _, cert := range config.TrustedCAs {
		s.certPool.AddCert(cert)
	}

	// Initialize policy extractor if not provided
	if s.policyExtractor == nil {
		s.policyExtractor = NewPolicyExtractor(
			WithPolicyExtractorLogger(s.logger),
		)
	}

	// Initialize OPA evaluator if policy evaluation is required
	if config.RequirePolicyEvaluation {
		if s.opaEvaluator == nil {
			s.opaEvaluator = NewOPAEvaluator(
				WithOPAEvaluatorLogger(s.logger),
			)
			// Only initialize if we created it ourselves
			if err := s.opaEvaluator.Initialize(ctx, config.OPAEndpoint, config.OPAPolicyPath); err != nil {
				return err
			}
		}
		// If externally provided, skip initialization - it should already be initialized
	}

	// Initialize flow manager if not provided
	if s.flowManager == nil {
		s.flowManager = NewFlowManager(
			WithFlowManagerLogger(s.logger),
		)
		flowConfig := &FlowConfig{
			BridgeName:        config.BridgeName,
			ControllerAddress: config.ControllerAddress,
		}
		if err := s.flowManager.Initialize(ctx, flowConfig); err != nil {
			return err
		}
	}
	// If externally provided, skip initialization - it should already be initialized

	s.config = config
	s.initialized.Store(true)

	s.logger.Info("network authentication service initialized",
		"quarantine_vlan", config.QuarantineVLAN,
		"production_vlan", config.ProductionVLAN,
		"require_attestation", config.RequireAttestation,
		"require_policy_evaluation", config.RequirePolicyEvaluation,
	)

	return nil
}

// validateConfig validates the configuration, accounting for externally provided components.
func (s *networkAuthService) validateConfig(c *AuthConfig) error {
	if c.QuarantineVLAN == 0 {
		return ErrInvalidConfig{Field: "QuarantineVLAN", Reason: "quarantine VLAN cannot be zero"}
	}
	if c.ProductionVLAN == 0 {
		return ErrInvalidConfig{Field: "ProductionVLAN", Reason: "production VLAN cannot be zero"}
	}
	if c.QuarantineVLAN == c.ProductionVLAN {
		return ErrInvalidConfig{
			Field:  "ProductionVLAN",
			Reason: "production VLAN cannot be the same as quarantine VLAN",
		}
	}
	if c.BridgeName == "" {
		return ErrInvalidConfig{Field: "BridgeName", Reason: "bridge name cannot be empty"}
	}
	// Only require OPA endpoint if policy evaluation is enabled AND no external evaluator provided
	if c.RequirePolicyEvaluation && c.OPAEndpoint == "" && !s.opaEvaluatorExternal {
		return ErrInvalidConfig{
			Field:  "OPAEndpoint",
			Reason: "OPA endpoint required when policy evaluation is enabled",
		}
	}
	if c.SessionTimeout < 0 {
		return ErrInvalidConfig{Field: "SessionTimeout", Reason: "session timeout cannot be negative"}
	}
	if c.Reattest != nil {
		if err := c.Reattest.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Authenticate performs full authentication for a port.
func (s *networkAuthService) Authenticate(ctx context.Context, request *PortAuthRequest) (*AuthResult, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "Authenticate"}
	default:
	}

	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if s.closed.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if request == nil {
		return nil, ErrInvalidConfig{Reason: "request cannot be nil"}
	}

	if err := request.Validate(); err != nil {
		return nil, err
	}

	result := &AuthResult{
		PortID:    request.PortID,
		State:     AuthStateQuarantine,
		VLAN:      s.config.QuarantineVLAN,
		Timestamp: time.Now().UTC(),
		SessionID: generateSessionID(),
	}

	// Apply timeout if specified
	if request.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, request.Timeout)
		defer cancel()
	}

	// Step 1: Validate certificate
	if err := s.validateCertificate(ctx, request.Certificate, request.CertificateChain); err != nil {
		result.AddError("certificate validation failed: " + err.Error())
		s.updatePortState(request.PortID, result, nil)
		return result, ErrCertInvalid{
			Subject: request.Certificate.Subject.String(),
			Reason:  "validation failed",
			Cause:   err,
		}
	}

	// Step 2: Extract policy OIDs
	policyInfo, err := s.policyExtractor.ExtractPolicyInfo(ctx, request.Certificate)
	if err != nil {
		result.AddError("policy extraction failed: " + err.Error())
		s.updatePortState(request.PortID, result, nil)
		return result, ErrAuthFailed{
			PortID: request.PortID,
			Reason: "failed to extract policy info",
			Cause:  err,
		}
	}
	result.PolicyOIDs = policyInfo.OIDs
	result.DeviceID = policyInfo.DeviceID

	// Validate required OIDs
	if len(s.config.RequiredOIDs) > 0 {
		if err := s.policyExtractor.ValidateRequiredOIDs(ctx, request.Certificate, s.config.RequiredOIDs); err != nil {
			result.AddError("missing required OIDs: " + err.Error())
			s.updatePortState(request.PortID, result, policyInfo)
			return result, err
		}
	}

	// Step 3: Perform attestation if required
	if s.config.RequireAttestation {
		if s.attestVerifier == nil {
			result.AddError("attestation required but no verifier configured")
			s.updatePortState(request.PortID, result, policyInfo)
			return result, ErrAttestFailed{
				DeviceID: result.DeviceID,
				Reason:   "no attestation verifier configured",
			}
		}

		verified, err := s.attestVerifier.Verify(ctx, result.DeviceID, request.Nonce, request.ExpectedPCRs)
		if err != nil {
			result.AddError("attestation failed: " + err.Error())
			s.updatePortState(request.PortID, result, policyInfo)
			return result, ErrAttestFailed{
				DeviceID: result.DeviceID,
				Reason:   "verification failed",
				Cause:    err,
			}
		}
		result.AttestationVerified = verified

		if !verified {
			result.AddError("attestation verification returned false")
			s.updatePortState(request.PortID, result, policyInfo)
			return result, ErrAttestFailed{
				DeviceID: result.DeviceID,
				Reason:   "attestation not verified",
			}
		}
	} else {
		// Skip attestation
		result.AttestationVerified = true
	}

	// Step 4: Evaluate OPA policy if required
	if s.config.RequirePolicyEvaluation {
		opaInput := &OPAInput{
			DeviceID:            result.DeviceID,
			PortID:              request.PortID,
			PolicyOIDs:          OIDsToStrings(policyInfo.OIDs),
			CertificateSubject:  policyInfo.CertificateSubject,
			CertificateIssuer:   policyInfo.CertificateIssuer,
			AttestationVerified: result.AttestationVerified,
			RequestedVLAN:       request.RequestedVLAN,
			AdditionalClaims:    request.AdditionalClaims,
			Timestamp:           time.Now().UTC(),
		}

		opaResult, err := s.opaEvaluator.Evaluate(ctx, opaInput)
		if err != nil {
			result.AddError("OPA evaluation failed: " + err.Error())
			s.updatePortState(request.PortID, result, policyInfo)
			return result, ErrPolicyViolation{
				PortID: request.PortID,
				Reason: "OPA evaluation error",
			}
		}

		result.PolicyEvaluated = true
		result.PolicyDecision = opaResult.Allow

		if !opaResult.Allow {
			result.AddError("policy denied access")
			for _, reason := range opaResult.Reasons {
				result.AddError("policy reason: " + reason)
			}
			s.updatePortState(request.PortID, result, policyInfo)
			return result, ErrPolicyViolation{
				PortID:  request.PortID,
				Reason:  "access denied by policy",
				Details: opaResult.Reasons,
			}
		}

		// Use assigned VLAN from policy if specified
		if opaResult.AssignedVLAN != 0 {
			result.VLAN = opaResult.AssignedVLAN
		} else {
			result.VLAN = s.config.ProductionVLAN
		}
	} else {
		// Skip policy evaluation
		result.PolicyEvaluated = true
		result.PolicyDecision = true
		result.VLAN = s.config.ProductionVLAN
	}

	// Step 5: Install OpenFlow rules and transition to production VLAN
	if err := s.flowManager.RemoveRules(ctx, request.PortID); err != nil {
		s.logger.Warn("failed to remove existing rules",
			"port_id", request.PortID,
			"error", err,
		)
	}

	if err := s.flowManager.InstallProductionRules(ctx, request.PortID, result.VLAN); err != nil {
		result.AddError("failed to install production rules: " + err.Error())
		// Attempt to install quarantine rules as fallback
		if qErr := s.flowManager.InstallQuarantineRules(ctx, request.PortID, s.config.QuarantineVLAN); qErr != nil {
			s.logger.Error("failed to install fallback quarantine rules",
				"port_id", request.PortID,
				"error", qErr,
			)
		}
		s.updatePortState(request.PortID, result, policyInfo)
		return result, ErrVLANFailed{
			PortID:   request.PortID,
			FromVLAN: s.config.QuarantineVLAN,
			ToVLAN:   result.VLAN,
			Reason:   "failed to install production rules",
			Cause:    err,
		}
	}

	result.FlowRulesInstalled = true
	result.State = AuthStateAuthorized

	// Set expiration if session timeout is configured
	if s.config.SessionTimeout > 0 {
		result.ExpiresAt = time.Now().Add(s.config.SessionTimeout)
	}

	// Update port state
	s.updatePortState(request.PortID, result, policyInfo)

	s.logger.Info("authentication successful",
		"port_id", request.PortID,
		"device_id", result.DeviceID,
		"vlan", result.VLAN,
		"session_id", result.SessionID,
	)

	return result, nil
}

// Reattest performs re-attestation for an already authenticated port.
func (s *networkAuthService) Reattest(ctx context.Context, portID string, nonce []byte) (*AuthResult, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "Reattest"}
	default:
	}

	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if s.closed.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if portID == "" {
		return nil, ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	// Get current port state
	stateVal, ok := s.portStates.Load(portID)
	if !ok {
		return nil, ErrPortNotFound{PortID: portID}
	}

	state := stateVal.(*PortState)
	if state.AuthState != AuthStateAuthorized {
		return nil, ErrStateTransition{
			PortID:    portID,
			FromState: state.AuthState,
			ToState:   AuthStateAuthorized,
			Reason:    "can only re-attest authorized ports",
		}
	}

	result := &AuthResult{
		PortID:    portID,
		State:     state.AuthState,
		VLAN:      state.VLAN,
		DeviceID:  state.DeviceID,
		SessionID: state.SessionID,
		Timestamp: time.Now().UTC(),
	}

	// Perform attestation
	if s.attestVerifier == nil {
		return nil, ErrAttestFailed{
			DeviceID: state.DeviceID,
			Reason:   "no attestation verifier configured",
		}
	}

	verified, err := s.attestVerifier.Verify(ctx, state.DeviceID, nonce, nil)
	if err != nil {
		result.AddError("re-attestation failed: " + err.Error())

		// Handle failure based on configuration
		if s.config.Reattest != nil && s.config.Reattest.QuarantineOnFailure {
			state.FailureCount++
			if state.FailureCount >= s.config.Reattest.MaxFailures {
				// Move to quarantine
				if rErr := s.Revoke(ctx, portID, "re-attestation failure limit exceeded"); rErr != nil {
					s.logger.Error("failed to revoke port after re-attestation failure",
						"port_id", portID,
						"error", rErr,
					)
				}
				result.State = AuthStateQuarantine
				result.VLAN = s.config.QuarantineVLAN
			}
		}

		return result, ErrAttestFailed{
			DeviceID: state.DeviceID,
			Reason:   "re-attestation verification failed",
			Cause:    err,
		}
	}

	result.AttestationVerified = verified
	if !verified {
		result.AddError("re-attestation verification returned false")
		state.FailureCount++

		if s.config.Reattest != nil && s.config.Reattest.QuarantineOnFailure {
			if state.FailureCount >= s.config.Reattest.MaxFailures {
				if rErr := s.Revoke(ctx, portID, "re-attestation failure limit exceeded"); rErr != nil {
					s.logger.Error("failed to revoke port after re-attestation failure",
						"port_id", portID,
						"error", rErr,
					)
				}
				result.State = AuthStateQuarantine
				result.VLAN = s.config.QuarantineVLAN
			}
		}

		return result, ErrAttestFailed{
			DeviceID: state.DeviceID,
			Reason:   "re-attestation not verified",
		}
	}

	// Reset failure count and update timestamp
	state.FailureCount = 0
	state.LastReattestAt = time.Now().UTC()
	s.portStates.Store(portID, state)

	s.logger.Info("re-attestation successful",
		"port_id", portID,
		"device_id", state.DeviceID,
	)

	return result, nil
}

// Revoke revokes authentication for a port and moves it to quarantine.
func (s *networkAuthService) Revoke(ctx context.Context, portID string, reason string) error {
	select {
	case <-ctx.Done():
		return ErrContextCanceled{Operation: "Revoke"}
	default:
	}

	if !s.initialized.Load() {
		return ErrServiceNotInitialized{}
	}

	if s.closed.Load() {
		return ErrServiceNotInitialized{}
	}

	if portID == "" {
		return ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	// Get current state
	stateVal, ok := s.portStates.Load(portID)
	if !ok {
		return ErrPortNotFound{PortID: portID}
	}

	state := stateVal.(*PortState)
	oldVLAN := state.VLAN

	// Remove production rules
	if err := s.flowManager.RemoveRules(ctx, portID); err != nil {
		s.logger.Warn("failed to remove production rules during revocation",
			"port_id", portID,
			"error", err,
		)
	}

	// Install quarantine rules
	if err := s.flowManager.InstallQuarantineRules(ctx, portID, s.config.QuarantineVLAN); err != nil {
		return ErrVLANFailed{
			PortID:   portID,
			FromVLAN: oldVLAN,
			ToVLAN:   s.config.QuarantineVLAN,
			Reason:   "failed to install quarantine rules during revocation",
			Cause:    err,
		}
	}

	// Update state
	state.AuthState = AuthStateRevoked
	state.VLAN = s.config.QuarantineVLAN
	state.Metadata["revoke_reason"] = reason
	state.Metadata["revoked_at"] = time.Now().UTC().Format(time.RFC3339)
	s.portStates.Store(portID, state)

	s.logger.Info("port revoked",
		"port_id", portID,
		"reason", reason,
		"from_vlan", oldVLAN,
		"to_vlan", s.config.QuarantineVLAN,
	)

	return nil
}

// GetPortState returns the current state of a port.
func (s *networkAuthService) GetPortState(ctx context.Context, portID string) (*PortState, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetPortState"}
	default:
	}

	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	if portID == "" {
		return nil, ErrInvalidConfig{Field: "portID", Reason: "port ID cannot be empty"}
	}

	stateVal, ok := s.portStates.Load(portID)
	if !ok {
		return nil, ErrPortNotFound{PortID: portID}
	}

	return stateVal.(*PortState), nil
}

// GetAllPorts returns all tracked port states.
func (s *networkAuthService) GetAllPorts(ctx context.Context) ([]*PortState, error) {
	select {
	case <-ctx.Done():
		return nil, ErrContextCanceled{Operation: "GetAllPorts"}
	default:
	}

	if !s.initialized.Load() {
		return nil, ErrServiceNotInitialized{}
	}

	var ports []*PortState
	s.portStates.Range(func(key, value interface{}) bool {
		ports = append(ports, value.(*PortState))
		return true
	})

	return ports, nil
}

// Close releases resources held by the service.
func (s *networkAuthService) Close() error {
	if s.closed.Swap(true) {
		return nil
	}

	if s.opaEvaluator != nil {
		if err := s.opaEvaluator.Close(); err != nil {
			s.logger.Warn("failed to close OPA evaluator", "error", err)
		}
	}

	if s.flowManager != nil {
		if err := s.flowManager.Close(); err != nil {
			s.logger.Warn("failed to close flow manager", "error", err)
		}
	}

	s.logger.Info("network authentication service closed")
	return nil
}

// validateCertificate validates the client certificate.
func (s *networkAuthService) validateCertificate(
	ctx context.Context,
	cert *x509.Certificate,
	chain []*x509.Certificate,
) error {
	if cert == nil {
		return ErrCertInvalid{Reason: "certificate is nil"}
	}

	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertInvalid{
			Subject: cert.Subject.String(),
			Reason:  "certificate not yet valid",
		}
	}
	if now.After(cert.NotAfter) {
		return ErrCertInvalid{
			Subject: cert.Subject.String(),
			Reason:  "certificate has expired",
		}
	}

	// Skip chain validation if no trusted CAs configured
	if len(s.config.TrustedCAs) == 0 {
		return nil
	}

	// Build intermediate pool
	intermediatePool := x509.NewCertPool()
	for _, intermediateCert := range chain {
		intermediatePool.AddCert(intermediateCert)
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         s.certPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := cert.Verify(opts); err != nil {
		return ErrCertInvalid{
			Subject: cert.Subject.String(),
			Reason:  "certificate chain verification failed",
			Cause:   err,
		}
	}

	return nil
}

// updatePortState updates the port state based on authentication result.
func (s *networkAuthService) updatePortState(portID string, result *AuthResult, policyInfo *PolicyInfo) {
	state := &PortState{
		PortID:          portID,
		AuthState:       result.State,
		VLAN:            result.VLAN,
		SessionID:       result.SessionID,
		DeviceID:        result.DeviceID,
		AuthenticatedAt: result.Timestamp,
		ExpiresAt:       result.ExpiresAt,
		PolicyInfo:      policyInfo,
		Metadata:        make(map[string]string),
	}

	if result.HasErrors() {
		state.Metadata["last_error"] = result.Errors[len(result.Errors)-1]
	}

	s.portStates.Store(portID, state)
}

// generateSessionID generates a unique session ID.
func generateSessionID() string {
	return uuid.NewString()
}
