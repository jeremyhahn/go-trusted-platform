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
	"bytes"
	"testing"

	"github.com/spf13/viper"
)

func TestValidateConfigYAML_Empty(t *testing.T) {
	if issues := ValidateConfigYAML(nil); len(issues) == 0 {
		t.Error("expected issues for nil body")
	}
	if issues := ValidateConfigYAML([]byte("")); len(issues) == 0 {
		t.Error("expected issues for empty body")
	}
}

func TestValidateConfigYAML_BadYAML(t *testing.T) {
	if issues := ValidateConfigYAML([]byte("this: is: not: yaml")); len(issues) == 0 {
		t.Error("expected issues for malformed yaml")
	}
}

func TestValidateConfigYAML_NotAMap(t *testing.T) {
	// A YAML scalar at the top level is valid YAML but not a config
	// document. Should be rejected.
	issues := ValidateConfigYAML([]byte("42\n"))
	if len(issues) == 0 {
		t.Error("expected issues for top-level scalar")
	}
}

func TestValidateConfigYAML_Valid(t *testing.T) {
	good := []byte(`
tpm:
  device: /dev/tpm0
  family: 2.0
ca:
  identity:
    - subject:
        common-name: Trusted Platform Root CA
`)
	if issues := ValidateConfigYAML(good); len(issues) != 0 {
		t.Errorf("expected no issues, got %v", issues)
	}
}

func TestLoadConfigTree_RedactsSecrets(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	yamlBody := []byte(`
ca:
  password: hunter2
  identity:
    - subject:
        common-name: Trusted Platform Root CA
tpm:
  pin: 12345678
network:
  port: 8443
`)
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewReader(yamlBody)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	tree := LoadConfigTree(true)
	if !tree.SecretsHidden {
		t.Error("expected SecretsHidden=true")
	}
	if len(tree.RedactedKeys) == 0 {
		t.Error("expected at least one redacted key")
	}
	ca := tree.Tree["ca"].(map[string]interface{})
	if ca["password"] != secretRedacted {
		t.Errorf("ca.password not redacted: %v", ca["password"])
	}
	tpm := tree.Tree["tpm"].(map[string]interface{})
	if tpm["pin"] != secretRedacted {
		t.Errorf("tpm.pin not redacted: %v", tpm["pin"])
	}
	// Non-secret leaves untouched.
	net := tree.Tree["network"].(map[string]interface{})
	if net["port"] == secretRedacted {
		t.Error("network.port should not be redacted")
	}
}

func TestLoadConfigTree_RawWithoutRedaction(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	yamlBody := []byte("ca:\n  password: hunter2\n")
	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewReader(yamlBody)); err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	tree := LoadConfigTree(false)
	if tree.SecretsHidden {
		t.Error("expected SecretsHidden=false when redact=false")
	}
	ca := tree.Tree["ca"].(map[string]interface{})
	if ca["password"] != "hunter2" {
		t.Errorf("password not preserved: %v", ca["password"])
	}
}

func TestIsSecretKey(t *testing.T) {
	secrets := []string{"password", "PASSWORD", "api_key", "Token", "client_secret", "pin"}
	for _, k := range secrets {
		if !isSecretKey(k) {
			t.Errorf("%q should be detected as a secret key", k)
		}
	}
	nonSecrets := []string{"hostname", "port", "subject", "common-name", "device"}
	for _, k := range nonSecrets {
		if isSecretKey(k) {
			t.Errorf("%q should NOT be detected as a secret key", k)
		}
	}
}
