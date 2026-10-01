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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v2"
)

func TestDeepMergeYAML_ScalarOverride(t *testing.T) {
	base := []byte(`
hostname: node-01
domain: example.com
port: 8080
`)
	overrides := []byte(`
hostname: node-02
domain: override.com
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	if result["hostname"] != "node-02" {
		t.Errorf("expected hostname=node-02, got %v", result["hostname"])
	}
	if result["domain"] != "override.com" {
		t.Errorf("expected domain=override.com, got %v", result["domain"])
	}
	if result["port"] != 8080 {
		t.Errorf("expected port=8080, got %v", result["port"])
	}
}

func TestDeepMergeYAML_NestedMapMerge(t *testing.T) {
	base := []byte(`
network:
  dns:
    nameservers:
      - 8.8.8.8
      - 8.8.4.4
    search: example.com
  bridges:
    br0: 10.0.0.1/24
    br1: 10.0.1.1/24
`)
	overrides := []byte(`
network:
  dns:
    nameservers:
      - 1.1.1.1
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	network, ok := toStringMap(result["network"])
	if !ok {
		t.Fatal("expected network to be a map")
	}

	// dns.nameservers should be replaced by override
	dns, ok := toStringMap(network["dns"])
	if !ok {
		t.Fatal("expected dns to be a map")
	}

	nameservers, ok := dns["nameservers"].([]interface{})
	if !ok {
		t.Fatal("expected nameservers to be a slice")
	}
	if len(nameservers) != 1 || nameservers[0] != "1.1.1.1" {
		t.Errorf("expected nameservers=[1.1.1.1], got %v", nameservers)
	}

	// dns.search should be preserved from base
	if dns["search"] != "example.com" {
		t.Errorf("expected search=example.com, got %v", dns["search"])
	}

	// bridges should be preserved from base
	bridges, ok := toStringMap(network["bridges"])
	if !ok {
		t.Fatal("expected bridges to be a map")
	}
	if bridges["br0"] != "10.0.0.1/24" {
		t.Errorf("expected br0=10.0.0.1/24, got %v", bridges["br0"])
	}
	if bridges["br1"] != "10.0.1.1/24" {
		t.Errorf("expected br1=10.0.1.1/24, got %v", bridges["br1"])
	}
}

func TestDeepMergeYAML_SliceReplacement(t *testing.T) {
	base := []byte(`
os:
  packages:
    - vim
    - curl
    - git
  locale: en_US.UTF-8
`)
	overrides := []byte(`
os:
  packages:
    - nginx
    - htop
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	osMap, ok := toStringMap(result["os"])
	if !ok {
		t.Fatal("expected os to be a map")
	}

	packages, ok := osMap["packages"].([]interface{})
	if !ok {
		t.Fatal("expected packages to be a slice")
	}
	if len(packages) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(packages))
	}
	if packages[0] != "nginx" || packages[1] != "htop" {
		t.Errorf("expected packages=[nginx, htop], got %v", packages)
	}

	// locale should be preserved
	if osMap["locale"] != "en_US.UTF-8" {
		t.Errorf("expected locale=en_US.UTF-8, got %v", osMap["locale"])
	}
}

func TestDeepMergeYAML_UnmentionedFieldsPreserved(t *testing.T) {
	base := []byte(`
server:
  host: 0.0.0.0
  port: 443
  tls: true
logging:
  level: info
  format: json
`)
	overrides := []byte(`
server:
  port: 8443
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	server, ok := toStringMap(result["server"])
	if !ok {
		t.Fatal("expected server to be a map")
	}

	if server["host"] != "0.0.0.0" {
		t.Errorf("expected host=0.0.0.0, got %v", server["host"])
	}
	if server["port"] != 8443 {
		t.Errorf("expected port=8443, got %v", server["port"])
	}
	if server["tls"] != true {
		t.Errorf("expected tls=true, got %v", server["tls"])
	}

	logging, ok := toStringMap(result["logging"])
	if !ok {
		t.Fatal("expected logging to be a map")
	}
	if logging["level"] != "info" {
		t.Errorf("expected level=info, got %v", logging["level"])
	}
	if logging["format"] != "json" {
		t.Errorf("expected format=json, got %v", logging["format"])
	}
}

func TestDeepMergeYAML_EmptyOverride(t *testing.T) {
	base := []byte(`
hostname: node-01
port: 8080
`)
	overrides := []byte(``)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	if result["hostname"] != "node-01" {
		t.Errorf("expected hostname=node-01, got %v", result["hostname"])
	}
	if result["port"] != 8080 {
		t.Errorf("expected port=8080, got %v", result["port"])
	}
}

func TestDeepMergeYAMLFiles_Success(t *testing.T) {
	dir := t.TempDir()

	basePath := filepath.Join(dir, "base.yaml")
	overridePath := filepath.Join(dir, "override.yaml")

	baseContent := []byte(`
hostname: node-01
network:
  interface: eth0
  mtu: 1500
`)
	overrideContent := []byte(`
hostname: node-02
network:
  mtu: 9000
`)

	if err := os.WriteFile(basePath, baseContent, 0644); err != nil {
		t.Fatalf("failed to write base file: %v", err)
	}
	if err := os.WriteFile(overridePath, overrideContent, 0644); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	merged, err := DeepMergeYAMLFiles(basePath, overridePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	if result["hostname"] != "node-02" {
		t.Errorf("expected hostname=node-02, got %v", result["hostname"])
	}

	network, ok := toStringMap(result["network"])
	if !ok {
		t.Fatal("expected network to be a map")
	}
	if network["interface"] != "eth0" {
		t.Errorf("expected interface=eth0, got %v", network["interface"])
	}
	if network["mtu"] != 9000 {
		t.Errorf("expected mtu=9000, got %v", network["mtu"])
	}
}

func TestDeepMergeYAMLFiles_BaseNotFound(t *testing.T) {
	dir := t.TempDir()
	overridePath := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(overridePath, []byte("key: val"), 0644); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	_, err := DeepMergeYAMLFiles(filepath.Join(dir, "nonexistent.yaml"), overridePath)
	if err == nil {
		t.Fatal("expected error for missing base file")
	}

	var readErr *ErrMergeReadFile
	if !errors.As(err, &readErr) {
		t.Fatalf("expected ErrMergeReadFile, got %T: %v", err, err)
	}
	if readErr.Path != filepath.Join(dir, "nonexistent.yaml") {
		t.Errorf("expected path in error, got %s", readErr.Path)
	}
}

func TestDeepMergeYAMLFiles_OverrideNotFound(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	if err := os.WriteFile(basePath, []byte("key: val"), 0644); err != nil {
		t.Fatalf("failed to write base file: %v", err)
	}

	_, err := DeepMergeYAMLFiles(basePath, filepath.Join(dir, "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing override file")
	}

	var readErr *ErrMergeReadFile
	if !errors.As(err, &readErr) {
		t.Fatalf("expected ErrMergeReadFile, got %T: %v", err, err)
	}
}

func TestDeepMergeYAML_InvalidBaseYAML(t *testing.T) {
	base := []byte(`{{{invalid yaml`)
	overrides := []byte(`key: value`)

	_, err := DeepMergeYAML(base, overrides)
	if err == nil {
		t.Fatal("expected error for invalid base YAML")
	}

	var unmarshalErr *ErrMergeUnmarshal
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected ErrMergeUnmarshal, got %T: %v", err, err)
	}
}

func TestDeepMergeYAML_InvalidOverrideYAML(t *testing.T) {
	base := []byte(`key: value`)
	overrides := []byte(`{{{invalid yaml`)

	_, err := DeepMergeYAML(base, overrides)
	if err == nil {
		t.Fatal("expected error for invalid override YAML")
	}

	var unmarshalErr *ErrMergeUnmarshal
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected ErrMergeUnmarshal, got %T: %v", err, err)
	}
}

func TestDeepMergeYAML_OverrideAddsNewKeys(t *testing.T) {
	base := []byte(`
existing: value
`)
	overrides := []byte(`
new_key: new_value
nested:
  deep: data
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	if result["existing"] != "value" {
		t.Errorf("expected existing=value, got %v", result["existing"])
	}
	if result["new_key"] != "new_value" {
		t.Errorf("expected new_key=new_value, got %v", result["new_key"])
	}

	nested, ok := toStringMap(result["nested"])
	if !ok {
		t.Fatal("expected nested to be a map")
	}
	if nested["deep"] != "data" {
		t.Errorf("expected deep=data, got %v", nested["deep"])
	}
}

func TestDeepMergeYAML_NilOverrideValuePreservesBase(t *testing.T) {
	base := []byte(`
keep_this: important
also_keep: critical
`)
	overrides := []byte(`
keep_this:
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	if result["keep_this"] != "important" {
		t.Errorf("expected keep_this=important, got %v", result["keep_this"])
	}
	if result["also_keep"] != "critical" {
		t.Errorf("expected also_keep=critical, got %v", result["also_keep"])
	}
}

func TestDeepMergeYAML_DeeplyNestedMerge(t *testing.T) {
	base := []byte(`
level1:
  level2:
    level3:
      keep: base_value
      replace: old_value
`)
	overrides := []byte(`
level1:
  level2:
    level3:
      replace: new_value
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	l1, ok := toStringMap(result["level1"])
	if !ok {
		t.Fatal("expected level1 to be a map")
	}
	l2, ok := toStringMap(l1["level2"])
	if !ok {
		t.Fatal("expected level2 to be a map")
	}
	l3, ok := toStringMap(l2["level3"])
	if !ok {
		t.Fatal("expected level3 to be a map")
	}

	if l3["keep"] != "base_value" {
		t.Errorf("expected keep=base_value, got %v", l3["keep"])
	}
	if l3["replace"] != "new_value" {
		t.Errorf("expected replace=new_value, got %v", l3["replace"])
	}
}

func TestDeepMergeYAML_ArrayOfObjectsMergeByName(t *testing.T) {
	base := []byte(`
network:
  interfaces:
    - name: eth0
      type: dhcp
      mtu: 1500
    - name: eth1
      type: dhcp
`)
	overrides := []byte(`
network:
  interfaces:
    - name: eth0
      type: static
      ipv4-address: 10.4.2.140/24
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	network, ok := toStringMap(result["network"])
	if !ok {
		t.Fatal("expected network to be a map")
	}

	ifaces, ok := network["interfaces"].([]interface{})
	if !ok {
		t.Fatal("expected interfaces to be a slice")
	}

	// Both interfaces should be present: eth0 (merged) and eth1 (preserved).
	if len(ifaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d: %v", len(ifaces), ifaces)
	}

	eth0, ok := toStringMap(ifaces[0])
	if !ok {
		t.Fatal("expected first interface to be a map")
	}
	if eth0["name"] != "eth0" {
		t.Errorf("expected name=eth0, got %v", eth0["name"])
	}
	if eth0["type"] != "static" {
		t.Errorf("expected type=static, got %v", eth0["type"])
	}
	if eth0["ipv4-address"] != "10.4.2.140/24" {
		t.Errorf("expected ipv4-address=10.4.2.140/24, got %v", eth0["ipv4-address"])
	}
	// mtu should be preserved from base via deep merge.
	if eth0["mtu"] != 1500 {
		t.Errorf("expected mtu=1500 preserved from base, got %v", eth0["mtu"])
	}

	eth1, ok := toStringMap(ifaces[1])
	if !ok {
		t.Fatal("expected second interface to be a map")
	}
	if eth1["name"] != "eth1" {
		t.Errorf("expected name=eth1, got %v", eth1["name"])
	}
	if eth1["type"] != "dhcp" {
		t.Errorf("expected type=dhcp, got %v", eth1["type"])
	}
}

func TestDeepMergeYAML_ArrayOfObjectsMergeByNameError(t *testing.T) {
	// Verify that a completely invalid base still returns an error.
	base := []byte(`{{{not valid`)
	overrides := []byte(`
network:
  interfaces:
    - name: eth0
      type: static
`)

	_, err := DeepMergeYAML(base, overrides)
	if err == nil {
		t.Fatal("expected error for invalid base YAML")
	}

	var unmarshalErr *ErrMergeUnmarshal
	if !errors.As(err, &unmarshalErr) {
		t.Fatalf("expected ErrMergeUnmarshal, got %T: %v", err, err)
	}
}

func TestDeepMergeYAML_ArrayOfObjectsAddNewElement(t *testing.T) {
	base := []byte(`
services:
  - name: web
    port: 80
`)
	overrides := []byte(`
services:
  - name: api
    port: 8080
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	services, ok := result["services"].([]interface{})
	if !ok {
		t.Fatal("expected services to be a slice")
	}

	// Base (web) preserved, override (api) appended.
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d: %v", len(services), services)
	}

	svc0, ok := toStringMap(services[0])
	if !ok {
		t.Fatal("expected first service to be a map")
	}
	if svc0["name"] != "web" {
		t.Errorf("expected name=web, got %v", svc0["name"])
	}

	svc1, ok := toStringMap(services[1])
	if !ok {
		t.Fatal("expected second service to be a map")
	}
	if svc1["name"] != "api" {
		t.Errorf("expected name=api, got %v", svc1["name"])
	}
	if svc1["port"] != 8080 {
		t.Errorf("expected port=8080, got %v", svc1["port"])
	}
}

func TestDeepMergeYAML_ArrayOfObjectsMergeByID(t *testing.T) {
	base := []byte(`
users:
  - id: 1
    username: admin
    role: administrator
  - id: 2
    username: viewer
    role: readonly
`)
	overrides := []byte(`
users:
  - id: 1
    username: superadmin
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	users, ok := result["users"].([]interface{})
	if !ok {
		t.Fatal("expected users to be a slice")
	}

	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}

	user0, ok := toStringMap(users[0])
	if !ok {
		t.Fatal("expected first user to be a map")
	}
	if user0["id"] != 1 {
		t.Errorf("expected id=1, got %v", user0["id"])
	}
	if user0["username"] != "superadmin" {
		t.Errorf("expected username=superadmin, got %v", user0["username"])
	}
	// role should be preserved from base.
	if user0["role"] != "administrator" {
		t.Errorf("expected role=administrator preserved from base, got %v", user0["role"])
	}

	user1, ok := toStringMap(users[1])
	if !ok {
		t.Fatal("expected second user to be a map")
	}
	if user1["username"] != "viewer" {
		t.Errorf("expected username=viewer, got %v", user1["username"])
	}
}

func TestDeepMergeYAML_ArrayOfObjectsMergeByRole(t *testing.T) {
	base := []byte(`
nodes:
  - role: control-plane
    count: 1
    flavor: small
  - role: worker
    count: 3
    flavor: medium
`)
	overrides := []byte(`
nodes:
  - role: worker
    count: 5
    flavor: large
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	nodes, ok := result["nodes"].([]interface{})
	if !ok {
		t.Fatal("expected nodes to be a slice")
	}

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	// control-plane preserved from base.
	cp, ok := toStringMap(nodes[0])
	if !ok {
		t.Fatal("expected control-plane node to be a map")
	}
	if cp["role"] != "control-plane" {
		t.Errorf("expected role=control-plane, got %v", cp["role"])
	}
	if cp["count"] != 1 {
		t.Errorf("expected count=1, got %v", cp["count"])
	}

	// worker merged with override values.
	worker, ok := toStringMap(nodes[1])
	if !ok {
		t.Fatal("expected worker node to be a map")
	}
	if worker["role"] != "worker" {
		t.Errorf("expected role=worker, got %v", worker["role"])
	}
	if worker["count"] != 5 {
		t.Errorf("expected count=5, got %v", worker["count"])
	}
	if worker["flavor"] != "large" {
		t.Errorf("expected flavor=large, got %v", worker["flavor"])
	}
}

func TestDeepMergeYAML_ArrayOfObjectsEmptyBase(t *testing.T) {
	base := []byte(`
network:
  interfaces: []
`)
	overrides := []byte(`
network:
  interfaces:
    - name: eth0
      type: static
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	network, ok := toStringMap(result["network"])
	if !ok {
		t.Fatal("expected network to be a map")
	}

	ifaces, ok := network["interfaces"].([]interface{})
	if !ok {
		t.Fatal("expected interfaces to be a slice")
	}

	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}

	eth0, ok := toStringMap(ifaces[0])
	if !ok {
		t.Fatal("expected interface to be a map")
	}
	if eth0["name"] != "eth0" {
		t.Errorf("expected name=eth0, got %v", eth0["name"])
	}
}

func TestDeepMergeYAML_ArrayOfObjectsEmptyOverride(t *testing.T) {
	base := []byte(`
network:
  interfaces:
    - name: eth0
      type: dhcp
`)
	overrides := []byte(`
network:
  interfaces: []
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	network, ok := toStringMap(result["network"])
	if !ok {
		t.Fatal("expected network to be a map")
	}

	ifaces, ok := network["interfaces"].([]interface{})
	if !ok {
		t.Fatal("expected interfaces to be a slice")
	}

	// Empty override slice: base preserved.
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface preserved from base, got %d", len(ifaces))
	}
}

func TestDeepMergeYAML_ArrayOfObjectsNoIdentityKey(t *testing.T) {
	// Arrays of maps without name/id/role keys should fall back to
	// full replacement semantics (same as scalar slices).
	base := []byte(`
routes:
  - destination: 10.0.0.0/8
    gateway: 192.168.1.1
  - destination: 172.16.0.0/12
    gateway: 192.168.1.1
`)
	overrides := []byte(`
routes:
  - destination: 0.0.0.0/0
    gateway: 10.0.0.1
`)

	merged, err := DeepMergeYAML(base, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result map[string]interface{}
	if err := yaml.Unmarshal(merged, &result); err != nil {
		t.Fatalf("failed to unmarshal merged result: %v", err)
	}

	routes, ok := result["routes"].([]interface{})
	if !ok {
		t.Fatal("expected routes to be a slice")
	}

	// No identity key: override replaces entirely.
	if len(routes) != 1 {
		t.Fatalf("expected 1 route (full replacement), got %d", len(routes))
	}

	route, ok := toStringMap(routes[0])
	if !ok {
		t.Fatal("expected route to be a map")
	}
	if route["destination"] != "0.0.0.0/0" {
		t.Errorf("expected destination=0.0.0.0/0, got %v", route["destination"])
	}
}

func TestDetectIdentityKey(t *testing.T) {
	tests := []struct {
		desc     string
		a        []interface{}
		b        []interface{}
		expected string
	}{
		{
			desc:     "name key detected",
			a:        []interface{}{map[string]interface{}{"name": "eth0"}},
			b:        []interface{}{map[string]interface{}{"name": "eth1"}},
			expected: "name",
		},
		{
			desc:     "id key detected",
			a:        []interface{}{map[string]interface{}{"id": 1}},
			b:        []interface{}{map[string]interface{}{"id": 2}},
			expected: "id",
		},
		{
			desc:     "role key detected",
			a:        []interface{}{map[string]interface{}{"role": "worker"}},
			b:        []interface{}{map[string]interface{}{"role": "control-plane"}},
			expected: "role",
		},
		{
			desc:     "no identity key",
			a:        []interface{}{map[string]interface{}{"foo": "bar"}},
			b:        []interface{}{map[string]interface{}{"baz": "qux"}},
			expected: "",
		},
		{
			desc:     "scalar slices",
			a:        []interface{}{"a", "b"},
			b:        []interface{}{"c", "d"},
			expected: "",
		},
		{
			desc:     "name takes precedence over id",
			a:        []interface{}{map[string]interface{}{"name": "x", "id": 1}},
			b:        []interface{}{map[string]interface{}{"name": "y", "id": 2}},
			expected: "name",
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			result := detectIdentityKey(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestSliceHasKey(t *testing.T) {
	tests := []struct {
		desc     string
		s        []interface{}
		key      string
		expected bool
	}{
		{
			desc:     "has key",
			s:        []interface{}{map[string]interface{}{"name": "eth0"}},
			key:      "name",
			expected: true,
		},
		{
			desc:     "missing key",
			s:        []interface{}{map[string]interface{}{"type": "dhcp"}},
			key:      "name",
			expected: false,
		},
		{
			desc:     "non-map elements",
			s:        []interface{}{"a", "b"},
			key:      "name",
			expected: false,
		},
		{
			desc:     "empty slice",
			s:        []interface{}{},
			key:      "name",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			result := sliceHasKey(tc.s, tc.key)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}
