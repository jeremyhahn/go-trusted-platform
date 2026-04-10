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

package container

import (
	"context"
	"sync/atomic"
	"time"
)

// PolicyDecisionMode controls enforcement behavior for policy evaluation.
type PolicyDecisionMode string

const (
	// PolicyModeEnforce blocks operations when policy denies.
	PolicyModeEnforce PolicyDecisionMode = "enforce"

	// PolicyModeAudit logs policy denials but allows operations.
	PolicyModeAudit PolicyDecisionMode = "audit"

	// PolicyModeDisabled skips policy evaluation entirely.
	PolicyModeDisabled PolicyDecisionMode = "disabled"
)

// IsValid returns true if the policy decision mode is valid.
func (m PolicyDecisionMode) IsValid() bool {
	switch m {
	case PolicyModeEnforce, PolicyModeAudit, PolicyModeDisabled:
		return true
	default:
		return false
	}
}

// String returns the string representation of PolicyDecisionMode.
func (m PolicyDecisionMode) String() string {
	return string(m)
}

// PolicyConfig defines policy sources and evaluation behavior.
type PolicyConfig struct {
	// EnableBuiltinPolicies enables the built-in security policies.
	// Default is true.
	EnableBuiltinPolicies bool `json:"enable_builtin_policies" yaml:"enable_builtin_policies"`

	// CustomPolicyDir is the directory containing custom .rego policy files.
	// If empty, no custom policies are loaded from disk.
	CustomPolicyDir string `json:"custom_policy_dir,omitempty" yaml:"custom_policy_dir,omitempty"`

	// PolicyBundleURL is the URL of a remote OPA policy bundle.
	// If empty, no remote bundle is fetched.
	PolicyBundleURL string `json:"policy_bundle_url,omitempty" yaml:"policy_bundle_url,omitempty"`

	// DecisionMode controls how policy decisions affect container operations.
	// Default is PolicyModeEnforce.
	DecisionMode PolicyDecisionMode `json:"decision_mode,omitempty" yaml:"decision_mode,omitempty"`
}

// Validate validates the PolicyConfig.
func (c *PolicyConfig) Validate() error {
	if c.DecisionMode != "" && !c.DecisionMode.IsValid() {
		return ErrInvalidPolicyConfig
	}
	return nil
}

// GetDecisionMode returns the effective decision mode, defaulting to enforce.
func (c *PolicyConfig) GetDecisionMode() PolicyDecisionMode {
	if c.DecisionMode == "" {
		return PolicyModeEnforce
	}
	return c.DecisionMode
}

// DeviceProfileInfo contains device profile information for policy evaluation.
type DeviceProfileInfo struct {
	// Name is the device profile name.
	Name string `json:"name"`

	// TrustedRegistries are registries allowed by the profile.
	TrustedRegistries []string `json:"trusted_registries,omitempty"`

	// AllowPrivileged indicates if privileged containers are allowed.
	AllowPrivileged bool `json:"allow_privileged"`

	// RequireSignedImages indicates if image signatures are required.
	RequireSignedImages bool `json:"require_signed_images"`

	// MaxMemoryLimit is the maximum memory limit allowed in bytes.
	MaxMemoryLimit int64 `json:"max_memory_limit,omitempty"`

	// MaxCPULimit is the maximum CPU limit allowed (cores).
	MaxCPULimit float64 `json:"max_cpu_limit,omitempty"`
}

// UserContext contains user information for RBAC policies.
type UserContext struct {
	// User is the username.
	User string `json:"user"`

	// Groups are the user's groups.
	Groups []string `json:"groups,omitempty"`

	// Namespace is the operational namespace.
	Namespace string `json:"namespace,omitempty"`

	// Roles are assigned roles.
	Roles []string `json:"roles,omitempty"`
}

// ResourceLimitsInfo contains resource limit information for policy evaluation.
type ResourceLimitsInfo struct {
	// MemoryLimit is the memory limit in bytes.
	MemoryLimit int64 `json:"memory_limit"`

	// CPULimit is the CPU limit as a decimal (1.0 = 1 core).
	CPULimit float64 `json:"cpu_limit"`

	// PidsLimit is the maximum number of processes.
	PidsLimit int64 `json:"pids_limit"`

	// HasMemoryLimit indicates if a memory limit is set.
	HasMemoryLimit bool `json:"has_memory_limit"`

	// HasCPULimit indicates if a CPU limit is set.
	HasCPULimit bool `json:"has_cpu_limit"`
}

// ContainerPolicySpec contains container specification for policy evaluation.
type ContainerPolicySpec struct {
	// Name is the container name.
	Name string `json:"name"`

	// Privileged indicates if the container runs in privileged mode.
	Privileged bool `json:"privileged"`

	// AllowPrivileged indicates if privileged mode is explicitly approved.
	AllowPrivileged bool `json:"allow_privileged"`

	// User is the user the container runs as.
	User string `json:"user,omitempty"`

	// Capabilities contains capability configuration.
	Capabilities CapabilityConfig `json:"capabilities,omitempty"`

	// Resources contains resource limits.
	Resources ResourceLimitsInfo `json:"resources"`

	// ReadOnlyRootfs indicates if the root filesystem is read-only.
	ReadOnlyRootfs bool `json:"read_only_rootfs"`

	// Mounts are the container's mounts.
	Mounts []MountConfig `json:"mounts,omitempty"`
}

// NetworkPolicyInfo contains network configuration for policy evaluation.
type NetworkPolicyInfo struct {
	// Mode is the network mode.
	Mode string `json:"mode"`

	// Ports are exposed port mappings.
	Ports []PortMapping `json:"ports,omitempty"`

	// HostNetwork indicates if host networking is used.
	HostNetwork bool `json:"host_network"`

	// SecurityGroups are applied security groups.
	SecurityGroups []string `json:"security_groups,omitempty"`
}

// OPAPolicyInput is the input structure for OPA policy evaluation.
// This extends the basic PolicyInput with additional fields for policy evaluation.
type OPAPolicyInput struct {
	// Container contains the container specification.
	Container ContainerPolicySpec `json:"container"`

	// Image contains image information.
	Image OPAImageInfo `json:"image"`

	// Network contains network configuration.
	Network NetworkPolicyInfo `json:"network"`

	// DeviceProfile contains device profile information.
	DeviceProfile *DeviceProfileInfo `json:"device_profile,omitempty"`

	// User contains user context for RBAC.
	User *UserContext `json:"user,omitempty"`

	// Namespace is the operational namespace.
	Namespace string `json:"namespace,omitempty"`
}

// OPAImageInfo contains image information for OPA policy evaluation.
type OPAImageInfo struct {
	// Registry is the registry host (e.g., "docker.io").
	Registry string `json:"registry"`

	// Repository is the image repository (e.g., "library/alpine").
	Repository string `json:"repository"`

	// Tag is the image tag (e.g., "latest", "3.18").
	Tag string `json:"tag"`

	// Digest is the image digest (SHA-256).
	Digest string `json:"digest,omitempty"`

	// Labels are image labels.
	Labels map[string]string `json:"labels,omitempty"`

	// Signature contains signature verification details.
	Signature *OPASignatureInfo `json:"signature,omitempty"`
}

// OPASignatureInfo contains image signature verification details for OPA.
type OPASignatureInfo struct {
	// Verified indicates if the signature was successfully verified.
	Verified bool `json:"verified"`

	// SignerID is the identity of the signer.
	SignerID string `json:"signer_id,omitempty"`

	// Algorithm is the signature algorithm used.
	Algorithm string `json:"algorithm,omitempty"`

	// Timestamp is when the signature was created.
	Timestamp string `json:"timestamp,omitempty"`

	// CertificateChain contains the certificate chain used for verification.
	CertificateChain []string `json:"certificate_chain,omitempty"`
}

// OPAPolicyDecision represents the result of OPA policy evaluation.
type OPAPolicyDecision struct {
	// Allow indicates if the operation is allowed.
	Allow bool `json:"allow"`

	// Denied contains the list of denial reasons.
	Denied []string `json:"denied,omitempty"`

	// Warnings contains non-blocking warning messages.
	Warnings []string `json:"warnings,omitempty"`
}

// ToLegacyDecision converts to the legacy PolicyDecision type.
func (d *OPAPolicyDecision) ToLegacyDecision(policyName string, input interface{}) *PolicyDecision {
	return &PolicyDecision{
		Allowed:    d.Allow,
		Reasons:    d.Denied,
		Warnings:   d.Warnings,
		PolicyName: policyName,
		Timestamp:  time.Now(),
		Input:      input,
	}
}

// ContainerPolicyEvaluator implements policy evaluation using OPA.
type ContainerPolicyEvaluator struct {
	config PolicyConfig
	loader *PolicyLoader
	engine *OPAEngine
	closed atomic.Bool
}

// NewContainerPolicyEvaluator creates a new policy evaluator with the given configuration.
func NewContainerPolicyEvaluator(config PolicyConfig) (*ContainerPolicyEvaluator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	loader := NewPolicyLoader(config)

	engine, err := NewOPAEngine()
	if err != nil {
		return nil, err
	}

	evaluator := &ContainerPolicyEvaluator{
		config: config,
		loader: loader,
		engine: engine,
	}

	return evaluator, nil
}

// LoadPolicies loads all policies from configured sources.
// This must be called before Evaluate.
func (e *ContainerPolicyEvaluator) LoadPolicies(ctx context.Context) error {
	if e.closed.Load() {
		return ErrOrchestratorClosed
	}

	bundle, err := e.loader.LoadPolicies(ctx)
	if err != nil {
		return err
	}

	return e.engine.LoadBundle(ctx, bundle)
}

// Evaluate evaluates the loaded policies against the provided input.
// Returns an OPAPolicyDecision with allow/deny status and any denial reasons.
func (e *ContainerPolicyEvaluator) Evaluate(ctx context.Context, input OPAPolicyInput) (*OPAPolicyDecision, error) {
	if e.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	// Check if policy is disabled
	if e.config.GetDecisionMode() == PolicyModeDisabled {
		return &OPAPolicyDecision{Allow: true}, nil
	}

	// Evaluate policies
	decision, err := e.engine.Evaluate(ctx, input)
	if err != nil {
		return nil, err
	}

	return decision, nil
}

// EvaluateLegacy evaluates policies using the legacy PolicyInput type.
// This method is provided for compatibility with the PolicyEvaluator interface.
func (e *ContainerPolicyEvaluator) EvaluateLegacy(ctx context.Context, policyName string, input *PolicyInput) (*PolicyDecision, error) {
	if e.closed.Load() {
		return nil, ErrOrchestratorClosed
	}

	// Convert legacy input to OPA input
	opaInput := e.convertLegacyInput(input)

	// Evaluate
	decision, err := e.Evaluate(ctx, opaInput)
	if err != nil {
		return nil, err
	}

	return decision.ToLegacyDecision(policyName, input), nil
}

// convertLegacyInput converts a legacy PolicyInput to OPAPolicyInput.
func (e *ContainerPolicyEvaluator) convertLegacyInput(input *PolicyInput) OPAPolicyInput {
	if input == nil {
		return OPAPolicyInput{}
	}

	opaInput := OPAPolicyInput{
		Namespace: input.Namespace,
	}

	// Convert container spec
	if input.Container != nil {
		opaInput.Container = ContainerPolicySpec{
			Name:       input.Container.Name,
			Privileged: input.Container.Privileged,
			User:       input.Container.User,
			Capabilities: CapabilityConfig{
				Add:  input.Container.Capabilities.Add,
				Drop: input.Container.Capabilities.Drop,
			},
		}
	}

	// Convert image info
	if input.Image != nil {
		opaInput.Image = OPAImageInfo{
			Registry:   input.Image.Registry,
			Repository: input.Image.Repository,
			Tag:        input.Image.Tag,
			Digest:     input.Image.Digest,
			Labels:     input.Image.Labels,
		}

		if input.Signature != nil {
			opaInput.Image.Signature = &OPASignatureInfo{
				Verified: input.Signature.Verified,
				SignerID: input.Signature.Signer,
			}
		}
	}

	// Convert network config
	if input.Network != nil {
		opaInput.Network = NetworkPolicyInfo{
			Mode:        string(input.Network.Mode),
			HostNetwork: input.Network.Mode == NetworkModeHost,
		}
	}

	// Convert user context
	if input.User != "" || len(input.Groups) > 0 {
		opaInput.User = &UserContext{
			User:      input.User,
			Groups:    input.Groups,
			Namespace: input.Namespace,
		}
	}

	return opaInput
}

// ShouldBlock returns true if the policy decision should block the operation.
// This takes into account the DecisionMode setting.
func (e *ContainerPolicyEvaluator) ShouldBlock(decision *OPAPolicyDecision) bool {
	if decision.Allow {
		return false
	}

	switch e.config.GetDecisionMode() {
	case PolicyModeEnforce:
		return true
	case PolicyModeAudit:
		return false
	case PolicyModeDisabled:
		return false
	default:
		return true
	}
}

// GetConfig returns the policy configuration.
func (e *ContainerPolicyEvaluator) GetConfig() PolicyConfig {
	return e.config
}

// Close releases resources held by the evaluator.
func (e *ContainerPolicyEvaluator) Close() error {
	if e.closed.Swap(true) {
		return nil
	}

	if e.engine != nil {
		return e.engine.Close()
	}

	return nil
}
