// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package mcp

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// deviceToolProperties returns the input-schema properties of a registered
// tool, failing the test when the tool is not advertised.
func deviceToolProperties(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
	for _, tool := range registry.ListTools() {
		if tool.Name != name {
			continue
		}
		props, ok := tool.InputSchema["properties"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s: input schema has no properties map", name)
		}
		return props
	}
	t.Fatalf("tool %q is not registered", name)
	return nil
}

// TestDeviceRegister_SchemaCarriesAttestCert pins that wherever the MCP device
// schemas carry attest_pub they carry attest_cert beside it (#404). Only
// device_register does: the enrollment set is server-owned on update
// (docs/device/api.md §3.3).
func TestDeviceRegister_SchemaCarriesAttestCert(t *testing.T) {
	for _, name := range []string{"device_register"} {
		props := deviceToolProperties(t, name)
		if _, ok := props["attest_pub"]; !ok {
			t.Fatalf("%s: attest_pub missing; the mirror premise no longer holds", name)
		}
		cert, ok := props["attest_cert"].(map[string]interface{})
		if !ok {
			t.Fatalf("%s: attest_cert missing from the schema", name)
		}
		if cert["type"] != "string" {
			t.Fatalf("%s: attest_cert must be a string, got %v", name, cert["type"])
		}
		if desc, _ := cert["description"].(string); desc == "" {
			t.Fatalf("%s: attest_cert needs a description for the model", name)
		}
	}
}

// TestDeviceRegister_AttestCertNotRequired proves the certificate is optional
// on create: the CA issues it at enrollment, and a manual registration
// without one must still be expressible (it is then denied at attest time,
// never faked).
func TestDeviceRegister_AttestCertNotRequired(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
	for _, tool := range registry.ListTools() {
		if tool.Name != "device_register" {
			continue
		}
		required, ok := tool.InputSchema["required"].([]string)
		if !ok {
			t.Fatal("device_register: input schema has no required list")
		}
		for _, r := range required {
			if r == "attest_cert" {
				t.Fatal("attest_cert must not be a required field on device_register")
			}
		}
		return
	}
	t.Fatal("device_register is not registered")
}
