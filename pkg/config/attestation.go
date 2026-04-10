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

package config

import (
	"fmt"
	"time"
)

// Valid PCR bank algorithms.
const (
	PCRBankSHA1   = "sha1"
	PCRBankSHA256 = "sha256"
	PCRBankSHA384 = "sha384"
	PCRBankSHA512 = "sha512"
)

// Valid policy engine types.
const (
	PolicyEngineOPA  = "opa"
	PolicyEngineRego = "rego"
)

// Valid default actions.
const (
	DefaultActionAllow = "allow"
	DefaultActionDeny  = "deny"
)

// PCR index limits.
const (
	MinPCRIndex = 0
	MaxPCRIndex = 23
)

// Default values for workload configuration.
const (
	DefaultWorkloadPCR     = 14
	DefaultWorkloadPCRBank = PCRBankSHA256
	DefaultPushInterval    = "5m"
	DefaultPolicyEngine    = PolicyEngineOPA
	DefaultPolicyAction    = DefaultActionDeny
)

// ErrInvalidPCR is returned when the PCR index is out of range.
type ErrInvalidPCR struct {
	Index int
	Min   int
	Max   int
}

func (e ErrInvalidPCR) Error() string {
	return fmt.Sprintf("invalid PCR index %d: must be between %d and %d", e.Index, e.Min, e.Max)
}

// ErrInvalidPCRBank is returned when the PCR bank algorithm is invalid.
type ErrInvalidPCRBank struct {
	Bank         string
	AllowedBanks []string
}

func (e ErrInvalidPCRBank) Error() string {
	return fmt.Sprintf("invalid PCR bank %q: must be one of %v", e.Bank, e.AllowedBanks)
}

// ErrInvalidPolicyEngine is returned when the policy engine type is invalid.
type ErrInvalidPolicyEngine struct {
	Engine         string
	AllowedEngines []string
}

func (e ErrInvalidPolicyEngine) Error() string {
	return fmt.Sprintf("invalid policy engine %q: must be one of %v", e.Engine, e.AllowedEngines)
}

// ErrInvalidDefaultAction is returned when the default action is invalid.
type ErrInvalidDefaultAction struct {
	Action         string
	AllowedActions []string
}

func (e ErrInvalidDefaultAction) Error() string {
	return fmt.Sprintf("invalid default action %q: must be one of %v", e.Action, e.AllowedActions)
}

// ErrInvalidPushInterval is returned when the push interval is invalid.
type ErrInvalidPushInterval struct {
	Interval string
	Reason   string
}

func (e ErrInvalidPushInterval) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid push interval %q: %s", e.Interval, e.Reason)
	}
	return fmt.Sprintf("invalid push interval %q", e.Interval)
}

// ErrEmptyPolicyDir is returned when policy is enabled but policy directory is empty.
type ErrEmptyPolicyDir struct{}

func (e ErrEmptyPolicyDir) Error() string {
	return "policy directory must be specified when policy engine is configured"
}

// WorkloadConfig contains settings for workload attestation measurements.
type WorkloadConfig struct {
	Enabled             bool   `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	PCR                 int    `yaml:"pcr" json:"pcr" mapstructure:"pcr"`
	PCRBank             string `yaml:"pcr-bank" json:"pcr_bank" mapstructure:"pcr-bank"`
	IncludeImageDigest  bool   `yaml:"include-image-digest" json:"include_image_digest" mapstructure:"include-image-digest"`
	IncludeContainerID  bool   `yaml:"include-container-id" json:"include_container_id" mapstructure:"include-container-id"`
	IncludeWorkloadType bool   `yaml:"include-workload-type" json:"include_workload_type" mapstructure:"include-workload-type"`
}

// GetWorkloadPCR returns the configured WorkloadPCR index, or the default if not set.
// This is the PCR used for workload attestation (containers, VMs).
func (w *WorkloadConfig) GetWorkloadPCR() int {
	if w == nil || w.PCR == 0 {
		return DefaultWorkloadPCR
	}
	return w.PCR
}

// GetWorkloadPCRBank returns the configured WorkloadPCR bank algorithm, or the default if not set.
func (w *WorkloadConfig) GetWorkloadPCRBank() string {
	if w == nil || w.PCRBank == "" {
		return DefaultWorkloadPCRBank
	}
	return w.PCRBank
}

// Validate validates the workload configuration.
func (w *WorkloadConfig) Validate() error {
	if !w.Enabled {
		return nil
	}

	if w.PCR < MinPCRIndex || w.PCR > MaxPCRIndex {
		return ErrInvalidPCR{
			Index: w.PCR,
			Min:   MinPCRIndex,
			Max:   MaxPCRIndex,
		}
	}

	validBanks := []string{PCRBankSHA1, PCRBankSHA256, PCRBankSHA384, PCRBankSHA512}
	if !isValidPCRBank(w.PCRBank) {
		return ErrInvalidPCRBank{
			Bank:         w.PCRBank,
			AllowedBanks: validBanks,
		}
	}

	return nil
}

// ManifestConfig contains settings for workload manifest generation and distribution.
type ManifestConfig struct {
	IncludeVMs        bool     `yaml:"include-vms" json:"include_vms" mapstructure:"include-vms"`
	IncludeContainers bool     `yaml:"include-containers" json:"include_containers" mapstructure:"include-containers"`
	PushEnabled       bool     `yaml:"push-enabled" json:"push_enabled" mapstructure:"push-enabled"`
	PushInterval      string   `yaml:"push-interval" json:"push_interval" mapstructure:"push-interval"`
	PushTargets       []string `yaml:"push-targets" json:"push_targets" mapstructure:"push-targets"`
}

// Validate validates the manifest configuration.
func (m *ManifestConfig) Validate() error {
	if !m.PushEnabled {
		return nil
	}

	if m.PushInterval != "" {
		_, err := time.ParseDuration(m.PushInterval)
		if err != nil {
			return ErrInvalidPushInterval{
				Interval: m.PushInterval,
				Reason:   err.Error(),
			}
		}
	}

	return nil
}

// PolicyConfig contains settings for attestation policy evaluation.
type PolicyConfig struct {
	Engine        string `yaml:"engine" json:"engine" mapstructure:"engine"`
	PolicyDir     string `yaml:"policy-dir" json:"policy_dir" mapstructure:"policy-dir"`
	DefaultAction string `yaml:"default-action" json:"default_action" mapstructure:"default-action"`
}

// Validate validates the policy configuration.
func (p *PolicyConfig) Validate() error {
	if p.Engine == "" && p.PolicyDir == "" && p.DefaultAction == "" {
		return nil
	}

	if p.Engine != "" {
		validEngines := []string{PolicyEngineOPA, PolicyEngineRego}
		if !isValidPolicyEngine(p.Engine) {
			return ErrInvalidPolicyEngine{
				Engine:         p.Engine,
				AllowedEngines: validEngines,
			}
		}
	}

	if p.Engine != "" && p.PolicyDir == "" {
		return ErrEmptyPolicyDir{}
	}

	if p.DefaultAction != "" {
		validActions := []string{DefaultActionAllow, DefaultActionDeny}
		if !isValidDefaultAction(p.DefaultAction) {
			return ErrInvalidDefaultAction{
				Action:         p.DefaultAction,
				AllowedActions: validActions,
			}
		}
	}

	return nil
}

// Attestation contains the attestation configuration.
type Attestation struct {
	AllowAttestorSelfCA bool     `yaml:"allow-attestor-self-ca" json:"allow_attestor_self_ca" mapstructure:"allow-attestor-self-ca"`
	AllowOpenEnrollment bool     `yaml:"allow-open-enrollment" json:"allow-open-enrollment" mapstructure:"allow-open-enrollment"`
	AllowedVerifiers    []string `yaml:"allowed-verifiers" json:"allowed_verifiers" mapstructure:"allowed-verifiers"`
	InsecurePort        int      `yaml:"insecure-port" json:"insecure_port" mapstructure:"insecure-port"`
	TLSPort             int      `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	QuotePCRs           []int32  `yaml:"quote-pcrs" json:"quote-pcrs" mapstructure:"quote-pcrs"`

	Workload *WorkloadConfig `yaml:"workload" json:"workload" mapstructure:"workload"`
	Manifest *ManifestConfig `yaml:"manifest" json:"manifest" mapstructure:"manifest"`
	Policy   *PolicyConfig   `yaml:"policy" json:"policy" mapstructure:"policy"`
}

// Validate validates the attestation configuration.
func (a *Attestation) Validate() error {
	if a.Workload != nil {
		if err := a.Workload.Validate(); err != nil {
			return err
		}
	}

	if a.Manifest != nil {
		if err := a.Manifest.Validate(); err != nil {
			return err
		}
	}

	if a.Policy != nil {
		if err := a.Policy.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// DefaultWorkloadConfig returns a WorkloadConfig with sensible defaults.
func DefaultWorkloadConfig() *WorkloadConfig {
	return &WorkloadConfig{
		Enabled:             false,
		PCR:                 DefaultWorkloadPCR,
		PCRBank:             DefaultWorkloadPCRBank,
		IncludeImageDigest:  true,
		IncludeContainerID:  true,
		IncludeWorkloadType: true,
	}
}

// DefaultManifestConfig returns a ManifestConfig with sensible defaults.
func DefaultManifestConfig() *ManifestConfig {
	return &ManifestConfig{
		IncludeVMs:        true,
		IncludeContainers: true,
		PushEnabled:       false,
		PushInterval:      DefaultPushInterval,
		PushTargets:       []string{},
	}
}

// DefaultPolicyConfig returns a PolicyConfig with sensible defaults.
func DefaultPolicyConfig() *PolicyConfig {
	return &PolicyConfig{
		Engine:        DefaultPolicyEngine,
		PolicyDir:     "/etc/trusted-platform/policies",
		DefaultAction: DefaultPolicyAction,
	}
}

// isValidPCRBank checks if the PCR bank algorithm is valid.
func isValidPCRBank(bank string) bool {
	switch bank {
	case PCRBankSHA1, PCRBankSHA256, PCRBankSHA384, PCRBankSHA512:
		return true
	default:
		return false
	}
}

// isValidPolicyEngine checks if the policy engine type is valid.
func isValidPolicyEngine(engine string) bool {
	switch engine {
	case PolicyEngineOPA, PolicyEngineRego:
		return true
	default:
		return false
	}
}

// isValidDefaultAction checks if the default action is valid.
func isValidDefaultAction(action string) bool {
	switch action {
	case DefaultActionAllow, DefaultActionDeny:
		return true
	default:
		return false
	}
}
