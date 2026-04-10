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
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestAttestationDefaults(t *testing.T) {
	attestation := &Attestation{}

	assert.False(t, attestation.AllowAttestorSelfCA)
	assert.False(t, attestation.AllowOpenEnrollment)
	assert.Nil(t, attestation.AllowedVerifiers)
	assert.Equal(t, 0, attestation.InsecurePort)
	assert.Equal(t, 0, attestation.TLSPort)
	assert.Nil(t, attestation.QuotePCRs)
	assert.Nil(t, attestation.Workload)
	assert.Nil(t, attestation.Manifest)
	assert.Nil(t, attestation.Policy)
}

func TestAttestationYAMLMarshal(t *testing.T) {
	tests := []struct {
		name        string
		attestation *Attestation
		wantErr     bool
	}{
		{
			name: "complete configuration",
			attestation: &Attestation{
				AllowAttestorSelfCA: true,
				AllowOpenEnrollment: true,
				AllowedVerifiers:    []string{"verifier1.example.com", "verifier2.example.com"},
				InsecurePort:        8080,
				TLSPort:             8443,
				QuotePCRs:           []int32{0, 1, 2, 3, 7},
			},
			wantErr: false,
		},
		{
			name: "minimal configuration",
			attestation: &Attestation{
				TLSPort: 8443,
			},
			wantErr: false,
		},
		{
			name:        "empty configuration",
			attestation: &Attestation{},
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := yaml.Marshal(tt.attestation)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Verify we can unmarshal it back
			var unmarshaled Attestation
			err = yaml.Unmarshal(data, &unmarshaled)
			require.NoError(t, err)

			assert.Equal(t, tt.attestation.AllowAttestorSelfCA, unmarshaled.AllowAttestorSelfCA)
			assert.Equal(t, tt.attestation.AllowOpenEnrollment, unmarshaled.AllowOpenEnrollment)
			// Note: YAML unmarshaling converts nil slices to empty slices
			if tt.attestation.AllowedVerifiers != nil {
				assert.Equal(t, tt.attestation.AllowedVerifiers, unmarshaled.AllowedVerifiers)
			}
			assert.Equal(t, tt.attestation.InsecurePort, unmarshaled.InsecurePort)
			assert.Equal(t, tt.attestation.TLSPort, unmarshaled.TLSPort)
			// Note: YAML unmarshaling converts nil slices to empty slices
			if tt.attestation.QuotePCRs != nil {
				assert.Equal(t, tt.attestation.QuotePCRs, unmarshaled.QuotePCRs)
			}
		})
	}
}

func TestAttestationYAMLUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		want     *Attestation
		wantErr  bool
		errMatch string
	}{
		{
			name: "complete YAML configuration",
			yaml: `
allow-attestor-self-ca: true
allow-open-enrollment: true
allowed-verifiers:
  - verifier1.example.com
  - verifier2.example.com
insecure-port: 8080
tls-port: 8443
quote-pcrs:
  - 0
  - 1
  - 2
  - 3
  - 7
`,
			want: &Attestation{
				AllowAttestorSelfCA: true,
				AllowOpenEnrollment: true,
				AllowedVerifiers:    []string{"verifier1.example.com", "verifier2.example.com"},
				InsecurePort:        8080,
				TLSPort:             8443,
				QuotePCRs:           []int32{0, 1, 2, 3, 7},
			},
			wantErr: false,
		},
		{
			name: "minimal YAML configuration",
			yaml: `
tls-port: 8443
`,
			want: &Attestation{
				TLSPort: 8443,
			},
			wantErr: false,
		},
		{
			name:    "empty YAML",
			yaml:    `{}`,
			want:    &Attestation{},
			wantErr: false,
		},
		{
			name: "invalid YAML",
			yaml: `
allow-attestor-self-ca: not-a-boolean
`,
			want:     nil,
			wantErr:  true,
			errMatch: "cannot unmarshal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Attestation
			err := yaml.Unmarshal([]byte(tt.yaml), &got)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMatch != "" {
					assert.Contains(t, err.Error(), tt.errMatch)
				}
				return
			}

			require.NoError(t, err)
			if tt.want != nil {
				assert.Equal(t, tt.want.AllowAttestorSelfCA, got.AllowAttestorSelfCA)
				assert.Equal(t, tt.want.AllowOpenEnrollment, got.AllowOpenEnrollment)
				assert.Equal(t, tt.want.AllowedVerifiers, got.AllowedVerifiers)
				assert.Equal(t, tt.want.InsecurePort, got.InsecurePort)
				assert.Equal(t, tt.want.TLSPort, got.TLSPort)
				assert.Equal(t, tt.want.QuotePCRs, got.QuotePCRs)
			}
		})
	}
}

func TestAttestationJSONMarshal(t *testing.T) {
	attestation := &Attestation{
		AllowAttestorSelfCA: true,
		AllowOpenEnrollment: true,
		AllowedVerifiers:    []string{"verifier1.example.com", "verifier2.example.com"},
		InsecurePort:        8080,
		TLSPort:             8443,
		QuotePCRs:           []int32{0, 1, 2, 3, 7},
	}

	data, err := json.Marshal(attestation)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify we can unmarshal it back
	var unmarshaled Attestation
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, attestation.AllowAttestorSelfCA, unmarshaled.AllowAttestorSelfCA)
	assert.Equal(t, attestation.AllowOpenEnrollment, unmarshaled.AllowOpenEnrollment)
	assert.Equal(t, attestation.AllowedVerifiers, unmarshaled.AllowedVerifiers)
	assert.Equal(t, attestation.InsecurePort, unmarshaled.InsecurePort)
	assert.Equal(t, attestation.TLSPort, unmarshaled.TLSPort)
	assert.Equal(t, attestation.QuotePCRs, unmarshaled.QuotePCRs)
}

func TestAttestationJSONUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    *Attestation
		wantErr bool
	}{
		{
			name: "complete JSON configuration",
			json: `{
				"allow_attestor_self_ca": true,
				"allow-open-enrollment": true,
				"allowed_verifiers": ["verifier1.example.com", "verifier2.example.com"],
				"insecure_port": 8080,
				"tls_port": 8443,
				"quote-pcrs": [0, 1, 2, 3, 7]
			}`,
			want: &Attestation{
				AllowAttestorSelfCA: true,
				AllowOpenEnrollment: true,
				AllowedVerifiers:    []string{"verifier1.example.com", "verifier2.example.com"},
				InsecurePort:        8080,
				TLSPort:             8443,
				QuotePCRs:           []int32{0, 1, 2, 3, 7},
			},
			wantErr: false,
		},
		{
			name:    "empty JSON object",
			json:    `{}`,
			want:    &Attestation{},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			json:    `{invalid}`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Attestation
			err := json.Unmarshal([]byte(tt.json), &got)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.want != nil {
				assert.Equal(t, tt.want.AllowAttestorSelfCA, got.AllowAttestorSelfCA)
				assert.Equal(t, tt.want.AllowOpenEnrollment, got.AllowOpenEnrollment)
				assert.Equal(t, tt.want.AllowedVerifiers, got.AllowedVerifiers)
				assert.Equal(t, tt.want.InsecurePort, got.InsecurePort)
				assert.Equal(t, tt.want.TLSPort, got.TLSPort)
				assert.Equal(t, tt.want.QuotePCRs, got.QuotePCRs)
			}
		})
	}
}

func TestAttestationPCRConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		quotePCRs []int32
		wantLen   int
	}{
		{
			name:      "standard PCRs",
			quotePCRs: []int32{0, 1, 2, 3, 7},
			wantLen:   5,
		},
		{
			name:      "extended PCRs",
			quotePCRs: []int32{0, 1, 2, 3, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			wantLen:   13,
		},
		{
			name:      "single PCR",
			quotePCRs: []int32{7},
			wantLen:   1,
		},
		{
			name:      "empty PCRs",
			quotePCRs: []int32{},
			wantLen:   0,
		},
		{
			name:      "nil PCRs",
			quotePCRs: nil,
			wantLen:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := &Attestation{
				QuotePCRs: tt.quotePCRs,
			}

			if tt.quotePCRs == nil {
				assert.Nil(t, attestation.QuotePCRs)
			} else {
				assert.Len(t, attestation.QuotePCRs, tt.wantLen)
			}
		})
	}
}

func TestAttestationVerifiersList(t *testing.T) {
	tests := []struct {
		name             string
		allowedVerifiers []string
		wantLen          int
	}{
		{
			name:             "multiple verifiers",
			allowedVerifiers: []string{"verifier1.example.com", "verifier2.example.com", "verifier3.example.com"},
			wantLen:          3,
		},
		{
			name:             "single verifier",
			allowedVerifiers: []string{"verifier.example.com"},
			wantLen:          1,
		},
		{
			name:             "empty verifiers",
			allowedVerifiers: []string{},
			wantLen:          0,
		},
		{
			name:             "nil verifiers",
			allowedVerifiers: nil,
			wantLen:          0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := &Attestation{
				AllowedVerifiers: tt.allowedVerifiers,
			}

			if tt.allowedVerifiers == nil {
				assert.Nil(t, attestation.AllowedVerifiers)
			} else {
				assert.Len(t, attestation.AllowedVerifiers, tt.wantLen)
			}
		})
	}
}

func TestAttestationPortConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		insecurePort int
		tlsPort      int
		wantErr      bool
	}{
		{
			name:         "standard ports",
			insecurePort: 8080,
			tlsPort:      8443,
			wantErr:      false,
		},
		{
			name:         "custom ports",
			insecurePort: 9090,
			tlsPort:      9443,
			wantErr:      false,
		},
		{
			name:         "only TLS port",
			insecurePort: 0,
			tlsPort:      8443,
			wantErr:      false,
		},
		{
			name:         "only insecure port",
			insecurePort: 8080,
			tlsPort:      0,
			wantErr:      false,
		},
		{
			name:         "no ports configured",
			insecurePort: 0,
			tlsPort:      0,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := &Attestation{
				InsecurePort: tt.insecurePort,
				TLSPort:      tt.tlsPort,
			}

			assert.Equal(t, tt.insecurePort, attestation.InsecurePort)
			assert.Equal(t, tt.tlsPort, attestation.TLSPort)
		})
	}
}

// Tests for WorkloadConfig

func TestWorkloadConfigDefaults(t *testing.T) {
	cfg := DefaultWorkloadConfig()

	assert.False(t, cfg.Enabled)
	assert.Equal(t, DefaultWorkloadPCR, cfg.PCR)
	assert.Equal(t, DefaultWorkloadPCRBank, cfg.PCRBank)
	assert.True(t, cfg.IncludeImageDigest)
	assert.True(t, cfg.IncludeContainerID)
	assert.True(t, cfg.IncludeWorkloadType)
}

func TestWorkloadConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *WorkloadConfig
		wantErr bool
		errType error
	}{
		{
			name: "valid configuration",
			config: &WorkloadConfig{
				Enabled:             true,
				PCR:                 14,
				PCRBank:             PCRBankSHA256,
				IncludeImageDigest:  true,
				IncludeContainerID:  true,
				IncludeWorkloadType: true,
			},
			wantErr: false,
		},
		{
			name: "disabled configuration skips validation",
			config: &WorkloadConfig{
				Enabled: false,
				PCR:     -1, // Invalid but should not cause error when disabled
				PCRBank: "invalid",
			},
			wantErr: false,
		},
		{
			name: "valid minimum PCR",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     MinPCRIndex,
				PCRBank: PCRBankSHA256,
			},
			wantErr: false,
		},
		{
			name: "valid maximum PCR",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     MaxPCRIndex,
				PCRBank: PCRBankSHA256,
			},
			wantErr: false,
		},
		{
			name: "invalid PCR below minimum",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     -1,
				PCRBank: PCRBankSHA256,
			},
			wantErr: true,
			errType: ErrInvalidPCR{},
		},
		{
			name: "invalid PCR above maximum",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     24,
				PCRBank: PCRBankSHA256,
			},
			wantErr: true,
			errType: ErrInvalidPCR{},
		},
		{
			name: "valid sha1 bank",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     14,
				PCRBank: PCRBankSHA1,
			},
			wantErr: false,
		},
		{
			name: "valid sha384 bank",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     14,
				PCRBank: PCRBankSHA384,
			},
			wantErr: false,
		},
		{
			name: "valid sha512 bank",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     14,
				PCRBank: PCRBankSHA512,
			},
			wantErr: false,
		},
		{
			name: "invalid PCR bank",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     14,
				PCRBank: "md5",
			},
			wantErr: true,
			errType: ErrInvalidPCRBank{},
		},
		{
			name: "empty PCR bank",
			config: &WorkloadConfig{
				Enabled: true,
				PCR:     14,
				PCRBank: "",
			},
			wantErr: true,
			errType: ErrInvalidPCRBank{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestWorkloadConfigYAMLRoundTrip(t *testing.T) {
	original := &WorkloadConfig{
		Enabled:             true,
		PCR:                 14,
		PCRBank:             PCRBankSHA256,
		IncludeImageDigest:  true,
		IncludeContainerID:  true,
		IncludeWorkloadType: true,
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var unmarshaled WorkloadConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Enabled, unmarshaled.Enabled)
	assert.Equal(t, original.PCR, unmarshaled.PCR)
	assert.Equal(t, original.PCRBank, unmarshaled.PCRBank)
	assert.Equal(t, original.IncludeImageDigest, unmarshaled.IncludeImageDigest)
	assert.Equal(t, original.IncludeContainerID, unmarshaled.IncludeContainerID)
	assert.Equal(t, original.IncludeWorkloadType, unmarshaled.IncludeWorkloadType)
}

func TestWorkloadConfigJSONRoundTrip(t *testing.T) {
	original := &WorkloadConfig{
		Enabled:             true,
		PCR:                 14,
		PCRBank:             PCRBankSHA256,
		IncludeImageDigest:  true,
		IncludeContainerID:  true,
		IncludeWorkloadType: true,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled WorkloadConfig
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Enabled, unmarshaled.Enabled)
	assert.Equal(t, original.PCR, unmarshaled.PCR)
	assert.Equal(t, original.PCRBank, unmarshaled.PCRBank)
	assert.Equal(t, original.IncludeImageDigest, unmarshaled.IncludeImageDigest)
	assert.Equal(t, original.IncludeContainerID, unmarshaled.IncludeContainerID)
	assert.Equal(t, original.IncludeWorkloadType, unmarshaled.IncludeWorkloadType)
}

// Tests for ManifestConfig

func TestManifestConfigDefaults(t *testing.T) {
	cfg := DefaultManifestConfig()

	assert.True(t, cfg.IncludeVMs)
	assert.True(t, cfg.IncludeContainers)
	assert.False(t, cfg.PushEnabled)
	assert.Equal(t, DefaultPushInterval, cfg.PushInterval)
	assert.Empty(t, cfg.PushTargets)
}

func TestManifestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ManifestConfig
		wantErr bool
		errType error
	}{
		{
			name: "valid configuration",
			config: &ManifestConfig{
				IncludeVMs:        true,
				IncludeContainers: true,
				PushEnabled:       true,
				PushInterval:      "5m",
				PushTargets:       []string{"https://example.com/manifests"},
			},
			wantErr: false,
		},
		{
			name: "push disabled skips validation",
			config: &ManifestConfig{
				PushEnabled:  false,
				PushInterval: "invalid",
			},
			wantErr: false,
		},
		{
			name: "valid push interval seconds",
			config: &ManifestConfig{
				PushEnabled:  true,
				PushInterval: "30s",
			},
			wantErr: false,
		},
		{
			name: "valid push interval hours",
			config: &ManifestConfig{
				PushEnabled:  true,
				PushInterval: "1h",
			},
			wantErr: false,
		},
		{
			name: "valid push interval complex",
			config: &ManifestConfig{
				PushEnabled:  true,
				PushInterval: "1h30m45s",
			},
			wantErr: false,
		},
		{
			name: "invalid push interval",
			config: &ManifestConfig{
				PushEnabled:  true,
				PushInterval: "invalid",
			},
			wantErr: true,
			errType: ErrInvalidPushInterval{},
		},
		{
			name: "empty push interval valid",
			config: &ManifestConfig{
				PushEnabled:  true,
				PushInterval: "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestManifestConfigYAMLRoundTrip(t *testing.T) {
	original := &ManifestConfig{
		IncludeVMs:        true,
		IncludeContainers: true,
		PushEnabled:       true,
		PushInterval:      "10m",
		PushTargets:       []string{"https://target1.com", "https://target2.com"},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var unmarshaled ManifestConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.IncludeVMs, unmarshaled.IncludeVMs)
	assert.Equal(t, original.IncludeContainers, unmarshaled.IncludeContainers)
	assert.Equal(t, original.PushEnabled, unmarshaled.PushEnabled)
	assert.Equal(t, original.PushInterval, unmarshaled.PushInterval)
	assert.Equal(t, original.PushTargets, unmarshaled.PushTargets)
}

func TestManifestConfigJSONRoundTrip(t *testing.T) {
	original := &ManifestConfig{
		IncludeVMs:        true,
		IncludeContainers: true,
		PushEnabled:       true,
		PushInterval:      "10m",
		PushTargets:       []string{"https://target1.com", "https://target2.com"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled ManifestConfig
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.IncludeVMs, unmarshaled.IncludeVMs)
	assert.Equal(t, original.IncludeContainers, unmarshaled.IncludeContainers)
	assert.Equal(t, original.PushEnabled, unmarshaled.PushEnabled)
	assert.Equal(t, original.PushInterval, unmarshaled.PushInterval)
	assert.Equal(t, original.PushTargets, unmarshaled.PushTargets)
}

// Tests for PolicyConfig

func TestPolicyConfigDefaults(t *testing.T) {
	cfg := DefaultPolicyConfig()

	assert.Equal(t, DefaultPolicyEngine, cfg.Engine)
	assert.Equal(t, "/etc/trusted-platform/policies", cfg.PolicyDir)
	assert.Equal(t, DefaultPolicyAction, cfg.DefaultAction)
}

func TestPolicyConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *PolicyConfig
		wantErr bool
		errType error
	}{
		{
			name: "valid opa configuration",
			config: &PolicyConfig{
				Engine:        PolicyEngineOPA,
				PolicyDir:     "/etc/policies",
				DefaultAction: DefaultActionDeny,
			},
			wantErr: false,
		},
		{
			name: "valid rego configuration",
			config: &PolicyConfig{
				Engine:        PolicyEngineRego,
				PolicyDir:     "/etc/policies",
				DefaultAction: DefaultActionAllow,
			},
			wantErr: false,
		},
		{
			name:    "empty configuration valid",
			config:  &PolicyConfig{},
			wantErr: false,
		},
		{
			name: "invalid policy engine",
			config: &PolicyConfig{
				Engine:        "invalid",
				PolicyDir:     "/etc/policies",
				DefaultAction: DefaultActionDeny,
			},
			wantErr: true,
			errType: ErrInvalidPolicyEngine{},
		},
		{
			name: "engine set but no policy dir",
			config: &PolicyConfig{
				Engine:        PolicyEngineOPA,
				PolicyDir:     "",
				DefaultAction: DefaultActionDeny,
			},
			wantErr: true,
			errType: ErrEmptyPolicyDir{},
		},
		{
			name: "invalid default action",
			config: &PolicyConfig{
				Engine:        PolicyEngineOPA,
				PolicyDir:     "/etc/policies",
				DefaultAction: "reject",
			},
			wantErr: true,
			errType: ErrInvalidDefaultAction{},
		},
		{
			name: "only default action set",
			config: &PolicyConfig{
				DefaultAction: DefaultActionDeny,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestPolicyConfigYAMLRoundTrip(t *testing.T) {
	original := &PolicyConfig{
		Engine:        PolicyEngineOPA,
		PolicyDir:     "/etc/trusted-platform/policies",
		DefaultAction: DefaultActionDeny,
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var unmarshaled PolicyConfig
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Engine, unmarshaled.Engine)
	assert.Equal(t, original.PolicyDir, unmarshaled.PolicyDir)
	assert.Equal(t, original.DefaultAction, unmarshaled.DefaultAction)
}

func TestPolicyConfigJSONRoundTrip(t *testing.T) {
	original := &PolicyConfig{
		Engine:        PolicyEngineOPA,
		PolicyDir:     "/etc/trusted-platform/policies",
		DefaultAction: DefaultActionDeny,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled PolicyConfig
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.Engine, unmarshaled.Engine)
	assert.Equal(t, original.PolicyDir, unmarshaled.PolicyDir)
	assert.Equal(t, original.DefaultAction, unmarshaled.DefaultAction)
}

// Tests for Attestation with sub-structs

func TestAttestationValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Attestation
		wantErr bool
		errType error
	}{
		{
			name:    "nil sub-configs valid",
			config:  &Attestation{},
			wantErr: false,
		},
		{
			name: "all valid sub-configs",
			config: &Attestation{
				Workload: &WorkloadConfig{
					Enabled: true,
					PCR:     14,
					PCRBank: PCRBankSHA256,
				},
				Manifest: &ManifestConfig{
					PushEnabled:  true,
					PushInterval: "5m",
				},
				Policy: &PolicyConfig{
					Engine:        PolicyEngineOPA,
					PolicyDir:     "/etc/policies",
					DefaultAction: DefaultActionDeny,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid workload config",
			config: &Attestation{
				Workload: &WorkloadConfig{
					Enabled: true,
					PCR:     -1,
					PCRBank: PCRBankSHA256,
				},
			},
			wantErr: true,
			errType: ErrInvalidPCR{},
		},
		{
			name: "invalid manifest config",
			config: &Attestation{
				Manifest: &ManifestConfig{
					PushEnabled:  true,
					PushInterval: "invalid",
				},
			},
			wantErr: true,
			errType: ErrInvalidPushInterval{},
		},
		{
			name: "invalid policy config",
			config: &Attestation{
				Policy: &PolicyConfig{
					Engine:    PolicyEngineOPA,
					PolicyDir: "",
				},
			},
			wantErr: true,
			errType: ErrEmptyPolicyDir{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.IsType(t, tt.errType, err)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestAttestationWithSubConfigsYAMLRoundTrip(t *testing.T) {
	original := &Attestation{
		AllowAttestorSelfCA: false,
		TLSPort:             8443,
		QuotePCRs:           []int32{0, 1, 2, 7, 14},
		Workload: &WorkloadConfig{
			Enabled:             true,
			PCR:                 14,
			PCRBank:             PCRBankSHA256,
			IncludeImageDigest:  true,
			IncludeContainerID:  true,
			IncludeWorkloadType: true,
		},
		Manifest: &ManifestConfig{
			IncludeVMs:        true,
			IncludeContainers: true,
			PushEnabled:       false,
			PushInterval:      "5m",
			PushTargets:       []string{},
		},
		Policy: &PolicyConfig{
			Engine:        PolicyEngineOPA,
			PolicyDir:     "/etc/trusted-platform/policies",
			DefaultAction: DefaultActionDeny,
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var unmarshaled Attestation
	err = yaml.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.AllowAttestorSelfCA, unmarshaled.AllowAttestorSelfCA)
	assert.Equal(t, original.TLSPort, unmarshaled.TLSPort)
	assert.Equal(t, original.QuotePCRs, unmarshaled.QuotePCRs)

	require.NotNil(t, unmarshaled.Workload)
	assert.Equal(t, original.Workload.Enabled, unmarshaled.Workload.Enabled)
	assert.Equal(t, original.Workload.PCR, unmarshaled.Workload.PCR)
	assert.Equal(t, original.Workload.PCRBank, unmarshaled.Workload.PCRBank)

	require.NotNil(t, unmarshaled.Manifest)
	assert.Equal(t, original.Manifest.IncludeVMs, unmarshaled.Manifest.IncludeVMs)
	assert.Equal(t, original.Manifest.PushEnabled, unmarshaled.Manifest.PushEnabled)

	require.NotNil(t, unmarshaled.Policy)
	assert.Equal(t, original.Policy.Engine, unmarshaled.Policy.Engine)
	assert.Equal(t, original.Policy.PolicyDir, unmarshaled.Policy.PolicyDir)
}

func TestAttestationWithSubConfigsJSONRoundTrip(t *testing.T) {
	original := &Attestation{
		AllowAttestorSelfCA: false,
		TLSPort:             8443,
		QuotePCRs:           []int32{0, 1, 2, 7, 14},
		Workload: &WorkloadConfig{
			Enabled:             true,
			PCR:                 14,
			PCRBank:             PCRBankSHA256,
			IncludeImageDigest:  true,
			IncludeContainerID:  true,
			IncludeWorkloadType: true,
		},
		Manifest: &ManifestConfig{
			IncludeVMs:        true,
			IncludeContainers: true,
			PushEnabled:       false,
			PushInterval:      "5m",
			PushTargets:       []string{},
		},
		Policy: &PolicyConfig{
			Engine:        PolicyEngineOPA,
			PolicyDir:     "/etc/trusted-platform/policies",
			DefaultAction: DefaultActionDeny,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var unmarshaled Attestation
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, original.AllowAttestorSelfCA, unmarshaled.AllowAttestorSelfCA)
	assert.Equal(t, original.TLSPort, unmarshaled.TLSPort)
	assert.Equal(t, original.QuotePCRs, unmarshaled.QuotePCRs)

	require.NotNil(t, unmarshaled.Workload)
	assert.Equal(t, original.Workload.Enabled, unmarshaled.Workload.Enabled)
	assert.Equal(t, original.Workload.PCR, unmarshaled.Workload.PCR)
	assert.Equal(t, original.Workload.PCRBank, unmarshaled.Workload.PCRBank)

	require.NotNil(t, unmarshaled.Manifest)
	assert.Equal(t, original.Manifest.IncludeVMs, unmarshaled.Manifest.IncludeVMs)
	assert.Equal(t, original.Manifest.PushEnabled, unmarshaled.Manifest.PushEnabled)

	require.NotNil(t, unmarshaled.Policy)
	assert.Equal(t, original.Policy.Engine, unmarshaled.Policy.Engine)
	assert.Equal(t, original.Policy.PolicyDir, unmarshaled.Policy.PolicyDir)
}

func TestAttestationCompleteYAMLUnmarshal(t *testing.T) {
	yamlContent := `
allow-attestor-self-ca: false
tls-port: 8443
quote-pcrs:
  - 0
  - 1
  - 2
  - 7
  - 14

workload:
  enabled: true
  pcr: 14
  pcr-bank: sha256
  include-image-digest: true
  include-container-id: true
  include-workload-type: true

manifest:
  include-vms: true
  include-containers: true
  push-enabled: false
  push-interval: "5m"
  push-targets: []

policy:
  engine: "opa"
  policy-dir: "/etc/trusted-platform/policies"
  default-action: "deny"
`

	var attestation Attestation
	err := yaml.Unmarshal([]byte(yamlContent), &attestation)
	require.NoError(t, err)

	// Verify top-level fields
	assert.False(t, attestation.AllowAttestorSelfCA)
	assert.Equal(t, 8443, attestation.TLSPort)
	assert.Equal(t, []int32{0, 1, 2, 7, 14}, attestation.QuotePCRs)

	// Verify workload config
	require.NotNil(t, attestation.Workload)
	assert.True(t, attestation.Workload.Enabled)
	assert.Equal(t, 14, attestation.Workload.PCR)
	assert.Equal(t, PCRBankSHA256, attestation.Workload.PCRBank)
	assert.True(t, attestation.Workload.IncludeImageDigest)
	assert.True(t, attestation.Workload.IncludeContainerID)
	assert.True(t, attestation.Workload.IncludeWorkloadType)

	// Verify manifest config
	require.NotNil(t, attestation.Manifest)
	assert.True(t, attestation.Manifest.IncludeVMs)
	assert.True(t, attestation.Manifest.IncludeContainers)
	assert.False(t, attestation.Manifest.PushEnabled)
	assert.Equal(t, "5m", attestation.Manifest.PushInterval)
	assert.Empty(t, attestation.Manifest.PushTargets)

	// Verify policy config
	require.NotNil(t, attestation.Policy)
	assert.Equal(t, PolicyEngineOPA, attestation.Policy.Engine)
	assert.Equal(t, "/etc/trusted-platform/policies", attestation.Policy.PolicyDir)
	assert.Equal(t, DefaultActionDeny, attestation.Policy.DefaultAction)

	// Verify validation passes
	err = attestation.Validate()
	require.NoError(t, err)
}

// Tests for error types

func TestErrInvalidPCR(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidPCR
		expected string
	}{
		{
			name:     "with values",
			err:      ErrInvalidPCR{Index: 25, Min: 0, Max: 23},
			expected: "invalid PCR index 25: must be between 0 and 23",
		},
		{
			name:     "negative index",
			err:      ErrInvalidPCR{Index: -1, Min: 0, Max: 23},
			expected: "invalid PCR index -1: must be between 0 and 23",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidPCRBank(t *testing.T) {
	err := ErrInvalidPCRBank{
		Bank:         "md5",
		AllowedBanks: []string{"sha1", "sha256", "sha384", "sha512"},
	}
	expected := `invalid PCR bank "md5": must be one of [sha1 sha256 sha384 sha512]`
	assert.Equal(t, expected, err.Error())
}

func TestErrInvalidPolicyEngine(t *testing.T) {
	err := ErrInvalidPolicyEngine{
		Engine:         "unknown",
		AllowedEngines: []string{"opa", "rego"},
	}
	expected := `invalid policy engine "unknown": must be one of [opa rego]`
	assert.Equal(t, expected, err.Error())
}

func TestErrInvalidDefaultAction(t *testing.T) {
	err := ErrInvalidDefaultAction{
		Action:         "reject",
		AllowedActions: []string{"allow", "deny"},
	}
	expected := `invalid default action "reject": must be one of [allow deny]`
	assert.Equal(t, expected, err.Error())
}

func TestErrInvalidPushInterval(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrInvalidPushInterval
		expected string
	}{
		{
			name:     "with reason",
			err:      ErrInvalidPushInterval{Interval: "invalid", Reason: "time: invalid duration"},
			expected: `invalid push interval "invalid": time: invalid duration`,
		},
		{
			name:     "without reason",
			err:      ErrInvalidPushInterval{Interval: "invalid"},
			expected: `invalid push interval "invalid"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrEmptyPolicyDir(t *testing.T) {
	err := ErrEmptyPolicyDir{}
	expected := "policy directory must be specified when policy engine is configured"
	assert.Equal(t, expected, err.Error())
}

func TestErrorsImplementError(t *testing.T) {
	// Verify all error types implement the error interface
	var _ error = ErrInvalidPCR{}
	var _ error = ErrInvalidPCRBank{}
	var _ error = ErrInvalidPolicyEngine{}
	var _ error = ErrInvalidDefaultAction{}
	var _ error = ErrInvalidPushInterval{}
	var _ error = ErrEmptyPolicyDir{}
}

func TestErrorsCanBeUsedWithErrorsIs(t *testing.T) {
	// Verify errors can be detected with errors.Is
	err1 := ErrInvalidPCR{Index: 25, Min: 0, Max: 23}
	err2 := ErrInvalidPCR{Index: 30, Min: 0, Max: 23}

	// Same type errors are not equal unless they have same values
	assert.False(t, errors.Is(err1, err2))

	// Same error is equal to itself
	assert.True(t, errors.Is(err1, err1))
}

// Tests for constants

func TestConstants(t *testing.T) {
	t.Run("PCR bank constants", func(t *testing.T) {
		assert.Equal(t, "sha1", PCRBankSHA1)
		assert.Equal(t, "sha256", PCRBankSHA256)
		assert.Equal(t, "sha384", PCRBankSHA384)
		assert.Equal(t, "sha512", PCRBankSHA512)
	})

	t.Run("policy engine constants", func(t *testing.T) {
		assert.Equal(t, "opa", PolicyEngineOPA)
		assert.Equal(t, "rego", PolicyEngineRego)
	})

	t.Run("default action constants", func(t *testing.T) {
		assert.Equal(t, "allow", DefaultActionAllow)
		assert.Equal(t, "deny", DefaultActionDeny)
	})

	t.Run("PCR index limits", func(t *testing.T) {
		assert.Equal(t, 0, MinPCRIndex)
		assert.Equal(t, 23, MaxPCRIndex)
	})

	t.Run("default values", func(t *testing.T) {
		assert.Equal(t, 14, DefaultWorkloadPCR)
		assert.Equal(t, "sha256", DefaultWorkloadPCRBank)
		assert.Equal(t, "5m", DefaultPushInterval)
		assert.Equal(t, "opa", DefaultPolicyEngine)
		assert.Equal(t, "deny", DefaultPolicyAction)
	})
}

func TestGetWorkloadPCR(t *testing.T) {
	tests := []struct {
		name   string
		config *WorkloadConfig
		want   int
	}{
		{
			name:   "nil config returns default",
			config: nil,
			want:   DefaultWorkloadPCR,
		},
		{
			name:   "zero PCR returns default",
			config: &WorkloadConfig{PCR: 0},
			want:   DefaultWorkloadPCR,
		},
		{
			name:   "custom PCR returns configured value",
			config: &WorkloadConfig{PCR: 10},
			want:   10,
		},
		{
			name:   "max PCR returns configured value",
			config: &WorkloadConfig{PCR: MaxPCRIndex},
			want:   MaxPCRIndex,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetWorkloadPCR()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetWorkloadPCRBank(t *testing.T) {
	tests := []struct {
		name   string
		config *WorkloadConfig
		want   string
	}{
		{
			name:   "nil config returns default",
			config: nil,
			want:   DefaultWorkloadPCRBank,
		},
		{
			name:   "empty bank returns default",
			config: &WorkloadConfig{PCRBank: ""},
			want:   DefaultWorkloadPCRBank,
		},
		{
			name:   "sha1 bank returns configured value",
			config: &WorkloadConfig{PCRBank: PCRBankSHA1},
			want:   PCRBankSHA1,
		},
		{
			name:   "sha384 bank returns configured value",
			config: &WorkloadConfig{PCRBank: PCRBankSHA384},
			want:   PCRBankSHA384,
		},
		{
			name:   "sha512 bank returns configured value",
			config: &WorkloadConfig{PCRBank: PCRBankSHA512},
			want:   PCRBankSHA512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetWorkloadPCRBank()
			assert.Equal(t, tt.want, got)
		})
	}
}
