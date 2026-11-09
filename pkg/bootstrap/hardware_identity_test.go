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

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// miniFleetIdentity is the identity the mini servers' BMCs report: firmware
// that serves a placeholder Model and names the board only in PartNumber.
// It resolves the board-specific registry entry, not the manufacturer-wide
// one, so a test built on it fails loudly if the part number is dropped
// anywhere along the path.
var miniFleetIdentity = quirks.Identity{
	Manufacturer: "Supermicro",
	Model:        "Super Server",
	PartNumber:   "SYS-5018D-FN8T-AS001",
}

// newHardwareIdentityOrchestrator builds an orchestrator over a single
// control-plane node whose role template carries no hardware keys, which is
// the shipped state: nothing populates them but the orchestrator.
func newHardwareIdentityOrchestrator(t *testing.T, overrides map[string]interface{}) *Orchestrator {
	t.Helper()

	templatePath := filepath.Join(t.TempDir(), "control-plane.yaml")
	if err := os.WriteFile(templatePath, []byte("os:\n    hostname: template-host\n"), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Templates:   map[string]string{RoleControlPlane: templatePath},
		Nodes: []NodeConfig{{
			Hostname:  "cp-01",
			Role:      RoleControlPlane,
			MACs:      []string{"aa:bb:cc:dd:ee:01"},
			Overrides: overrides,
		}},
	}

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &mockBMCFactory{client: bmc.NewMockClient()},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	return o
}

// installerConfigFrom parses resolved orchestrator YAML the way the
// installed OS does — through installer.Config, whose YAML tags are the
// only contract between the two sides.
func installerConfigFrom(t *testing.T, resolved string) *installer.Config {
	t.Helper()
	var cfg installer.Config
	if err := yaml.Unmarshal([]byte(resolved), &cfg); err != nil {
		t.Fatalf("resolved config is not a valid installer.Config: %v", err)
	}
	return &cfg
}

// TestResolveNodeConfig_QuirkParityWithBMCClient is the parity assertion
// this whole change exists for: the entry the installed OS resolves from
// the orchestrator-written config must be the entry the BMC client itself
// resolved — read off the same bmc.Client, not rebuilt from SystemInfo.
//
// It asserts equality with the BMC side AND names the expected board entry,
// so a change that made both sides resolve Default() would still fail.
func TestResolveNodeConfig_QuirkParityWithBMCClient(t *testing.T) {
	client := bmc.NewMockClient()
	client.Identity = miniFleetIdentity

	bmcIdentity, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity: %v", err)
	}
	bmcQuirk := quirks.ResolveIdentity(bmcIdentity)
	if bmcQuirk.Key != "supermicro/x10sdv" {
		t.Fatalf("BMC side resolved %q, want supermicro/x10sdv — fixture no longer exercises a board-specific entry", bmcQuirk.Key)
	}

	discovered := readHardwareIdentity(context.Background(), client, "cp-01", orchTestLogger())
	if discovered == nil {
		t.Fatal("readHardwareIdentity returned nil for a BMC that named its hardware")
	}

	o := newHardwareIdentityOrchestrator(t, nil)
	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, discovered)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}

	installerQuirk := quirks.ResolveIdentity(installerConfigFrom(t, resolved).HardwareIdentity())
	if installerQuirk.Key != bmcQuirk.Key {
		t.Errorf("installer resolved quirk %q, BMC client resolved %q — the two sides diverge", installerQuirk.Key, bmcQuirk.Key)
	}
	if installerQuirk.Key != "supermicro/x10sdv" {
		t.Errorf("installer resolved quirk %q, want supermicro/x10sdv", installerQuirk.Key)
	}
}

// TestResolveNodeConfig_QuirkParityAcrossRegistry runs the same parity
// assertion over every distinct entry the registry can name, including one
// reachable only by part-number prefix. A resolver that dropped a field, or
// a writer that emitted the wrong key, cannot pass all of these.
func TestResolveNodeConfig_QuirkParityAcrossRegistry(t *testing.T) {
	cases := []struct {
		name     string
		identity quirks.Identity
		wantKey  string
	}{
		{"board by part number", miniFleetIdentity, "supermicro/x10sdv"},
		{"board by model", quirks.Identity{Manufacturer: "Supermicro", Model: "X10SDV-TP8F"}, "supermicro/x10sdv"},
		{"manufacturer wide", quirks.Identity{Manufacturer: "Supermicro", Model: "X11SSH-F"}, "supermicro"},
		{"other vendor", quirks.Identity{Manufacturer: "Dell Inc.", Model: "PowerEdge R640"}, "dell inc."},
		{"unidentified", quirks.Identity{}, quirks.Default().Key},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := bmc.NewMockClient()
			client.Identity = tc.identity

			bmcQuirk := quirks.ResolveIdentity(mustHardwareIdentity(t, client))
			if bmcQuirk.Key != tc.wantKey {
				t.Fatalf("BMC side resolved %q, want %q", bmcQuirk.Key, tc.wantKey)
			}

			o := newHardwareIdentityOrchestrator(t, nil)
			resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane,
				readHardwareIdentity(context.Background(), client, "cp-01", orchTestLogger()))
			if err != nil {
				t.Fatalf("resolveNodeConfig: %v", err)
			}

			got := quirks.ResolveIdentity(installerConfigFrom(t, resolved).HardwareIdentity()).Key
			if got != bmcQuirk.Key {
				t.Errorf("installer resolved %q, BMC client resolved %q", got, bmcQuirk.Key)
			}
		})
	}
}

// TestResolveNodeConfig_WritesHardwareKeys pins the wire form: the three
// YAML keys installer.Config declares, spelled exactly.
func TestResolveNodeConfig_WritesHardwareKeys(t *testing.T) {
	o := newHardwareIdentityOrchestrator(t, nil)
	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, &miniFleetIdentity)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(resolved), &parsed); err != nil {
		t.Fatalf("resolved config is not valid YAML: %v", err)
	}
	for key, want := range map[string]string{
		"hardware-manufacturer": miniFleetIdentity.Manufacturer,
		"hardware-model":        miniFleetIdentity.Model,
		"hardware-part-number":  miniFleetIdentity.PartNumber,
	} {
		if got, _ := parsed[key].(string); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// TestResolveNodeConfig_UnreadableBMCLeavesKeysUnset is the negative case
// from the issue: a node whose BMC could not be read gets no hardware keys
// and the installer resolves the cross-vendor default without error.
func TestResolveNodeConfig_UnreadableBMCLeavesKeysUnset(t *testing.T) {
	noIdentityRetryDelay(t)

	client := bmc.NewMockClient()
	client.HardwareIdentityErr = bmc.ErrUnsupportedOperation{Operation: "hardware identity"}

	discovered := readHardwareIdentity(context.Background(), client, "cp-01", orchTestLogger())
	if discovered != nil {
		t.Fatalf("readHardwareIdentity returned %+v for an unreadable BMC, want nil", *discovered)
	}

	o := newHardwareIdentityOrchestrator(t, nil)
	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, discovered)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal([]byte(resolved), &parsed); err != nil {
		t.Fatalf("resolved config is not valid YAML: %v", err)
	}
	for _, key := range []string{"hardware-manufacturer", "hardware-model", "hardware-part-number"} {
		if _, ok := parsed[key]; ok {
			t.Errorf("%s present for an unreadable BMC, want absent", key)
		}
	}
	if got := quirks.ResolveIdentity(installerConfigFrom(t, resolved).HardwareIdentity()).Key; got != quirks.Default().Key {
		t.Errorf("installer resolved %q, want %q", got, quirks.Default().Key)
	}
}

// TestResolveNodeConfig_AnsweringBMCClearsStaleKeys separates the two
// failure modes. A BMC that answers but names nothing must CLEAR whatever
// the template carried: leaving a stale board name behind would send the
// installed OS to an entry the BMC side does not use — the exact divergence
// this change removes.
func TestResolveNodeConfig_AnsweringBMCClearsStaleKeys(t *testing.T) {
	stale := map[string]interface{}{
		"hardware-manufacturer": "Supermicro",
		"hardware-part-number":  "SYS-5018D-FN8T-AS001",
	}

	client := bmc.NewMockClient() // zero Identity: answered, named nothing
	discovered := readHardwareIdentity(context.Background(), client, "cp-01", orchTestLogger())
	if discovered == nil {
		t.Fatal("readHardwareIdentity returned nil for a BMC that answered")
	}

	// The stale values live in the template, not in a per-node override —
	// an override is a deliberate operator pin and is tested separately.
	o := newHardwareIdentityOrchestrator(t, nil)
	templatePath := o.config.Templates[RoleControlPlane]
	body, err := yaml.Marshal(stale)
	if err != nil {
		t.Fatalf("marshal stale keys: %v", err)
	}
	if err := os.WriteFile(templatePath, body, 0644); err != nil {
		t.Fatalf("rewrite template: %v", err)
	}

	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, discovered)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}

	cfg := installerConfigFrom(t, resolved)
	if cfg.HardwareManufacturer != "" || cfg.HardwarePartNumber != "" {
		t.Errorf("stale template identity survived: %+v", cfg.HardwareIdentity())
	}
	if got := quirks.ResolveIdentity(cfg.HardwareIdentity()).Key; got != quirks.Default().Key {
		t.Errorf("installer resolved %q, want %q — an unidentified BMC must land on the default entry both sides use", got, quirks.Default().Key)
	}
}

// TestResolveNodeConfig_OperatorOverrideBeatsDiscovery keeps the documented
// escape hatch working: the hardware keys are applied in the same slot as
// the platform globals, before the per-node override merge, so an operator
// who pins the identity for a BMC that misreports itself still wins.
func TestResolveNodeConfig_OperatorOverrideBeatsDiscovery(t *testing.T) {
	o := newHardwareIdentityOrchestrator(t, map[string]interface{}{
		"hardware-manufacturer": "Dell Inc.",
		"hardware-model":        "PowerEdge R640",
		"hardware-part-number":  "",
	})

	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, &miniFleetIdentity)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}

	if got := quirks.ResolveIdentity(installerConfigFrom(t, resolved).HardwareIdentity()).Key; got != "dell inc." {
		t.Errorf("installer resolved %q, want dell inc. (the operator's pinned identity)", got)
	}
}

// mustHardwareIdentity reads a client's identity or fails the test.
func mustHardwareIdentity(t *testing.T, client bmc.Client) quirks.Identity {
	t.Helper()
	id, err := client.HardwareIdentity(context.Background())
	if err != nil {
		t.Fatalf("HardwareIdentity: %v", err)
	}
	return id
}

// TestSeeder_BuildMergedConfig_CarriesHardwareIdentity covers the second
// delivery path. The seeded device profile is what the control plane hands
// a node on first boot; if it carried a different hardware identity than
// the per-MAC installer.yaml the orchestrator stages, which quirk entry a
// node installed against would depend on which path won the race.
func TestSeeder_BuildMergedConfig_CarriesHardwareIdentity(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "cp-template.yaml")
	if err := os.WriteFile(templatePath, []byte("os:\n  hostname: template-host\n"), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	cfg := minimalConfig()
	cfg.Templates = map[string]string{RoleControlPlane: templatePath}

	client := bmc.NewMockClient()
	client.Identity = miniFleetIdentity
	node := &DiscoveredNode{
		NodeConfig:       NodeConfig{Hostname: "cp-01", Role: RoleControlPlane},
		HardwareIdentity: readHardwareIdentity(context.Background(), client, "cp-01", orchTestLogger()),
	}

	s := NewSeeder(SeederParams{Config: cfg, Logger: orchTestLogger()})
	merged, err := s.buildMergedConfig(node)
	if err != nil {
		t.Fatalf("buildMergedConfig: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("merged config should be valid JSON: %v", err)
	}

	// The seeder writes device-schema (YAML) key spellings throughout —
	// "tenant-id", not "tenant_id" — so the hardware keys follow suit.
	seeded := quirks.Identity{
		Manufacturer: stringField(t, got, "hardware-manufacturer"),
		Model:        stringField(t, got, "hardware-model"),
		PartNumber:   stringField(t, got, "hardware-part-number"),
	}
	if seeded != miniFleetIdentity {
		t.Errorf("seeded identity = %+v, want %+v", seeded, miniFleetIdentity)
	}
	if key := quirks.ResolveIdentity(seeded).Key; key != "supermicro/x10sdv" {
		t.Errorf("seeded profile resolves %q, want supermicro/x10sdv", key)
	}
}

// stringField reads a string key from a decoded config map.
func stringField(t *testing.T, m map[string]interface{}, key string) string {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("%s missing from merged config", key)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("%s = %v (%T), want a string", key, v, v)
	}
	return s
}

// TestOrchestrator_DryRun_PreviewsHardwareIdentity checks the dry-run
// wiring end to end: the preview reads the identity off the same client a
// real run does, and the previewed config carries the keys, so an operator
// can see which registry entry a node will install against before
// committing to a 45-minute run.
func TestOrchestrator_DryRun_PreviewsHardwareIdentity(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "control-plane.yaml")
	if err := os.WriteFile(templatePath, []byte("os:\n    hostname: template-host\n"), 0644); err != nil {
		t.Fatalf("write template: %v", err)
	}

	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: "deploy-host"},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "test.local"},
		Templates:   map[string]string{RoleControlPlane: templatePath},
		Nodes: []NodeConfig{{
			Hostname:    "cp-01",
			Role:        RoleControlPlane,
			BMCAddress:  "198.51.100.103",
			BMCUser:     "admin",
			BMCPassword: "pass",
			BMCProtocol: "ipmi",
		}},
	}

	mockClient := bmc.NewMockClient()
	mockClient.Identity = miniFleetIdentity

	o, err := NewOrchestrator(OrchestratorParams{
		Config:        cfg,
		BMCFactory:    &bmc.MockClientFactory{Client: mockClient},
		Logger:        orchTestLogger(),
		HealthChecker: &mockHealthChecker{},
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	o.discoverMACs = unreachableMACDiscovery

	result, err := o.DryRun(context.Background())
	if err != nil {
		t.Fatalf("DryRun: %v", err)
	}
	if len(result.Nodes) != 1 {
		t.Fatalf("dry run returned %d nodes, want 1", len(result.Nodes))
	}

	node := result.Nodes[0]
	if node.HardwareIdentity == nil {
		t.Fatal("dry run did not read the node's hardware identity")
	}
	if *node.HardwareIdentity != miniFleetIdentity {
		t.Errorf("previewed identity = %+v, want %+v", *node.HardwareIdentity, miniFleetIdentity)
	}
	if key := quirks.ResolveIdentity(installerConfigFrom(t, node.ResolvedConfig).HardwareIdentity()).Key; key != "supermicro/x10sdv" {
		t.Errorf("previewed config resolves %q, want supermicro/x10sdv", key)
	}
}

// TestResolveNodeConfig_PartialIdentityIsStaged covers the middle ground
// between "read" and "unreadable". The IPMI path names the vendor from Get
// Device ID and can then fail reading the FRU, returning a partial identity
// alongside the error; the BMC client resolves its own quirk from exactly
// that partial value. Discarding it here would leave the installer on
// Default() while the BMC side is on the vendor entry.
func TestResolveNodeConfig_PartialIdentityIsStaged(t *testing.T) {
	noIdentityRetryDelay(t)

	partial := quirks.Identity{Manufacturer: "Supermicro"} // FRU never read

	client := bmc.NewMockClient()
	client.Identity = partial
	client.HardwareIdentityErr = bmc.ErrInventory{Cause: errors.New("fru read timeout")}

	bmcQuirk := quirks.ResolveIdentity(partial)
	if bmcQuirk.Key != "supermicro" {
		t.Fatalf("BMC side resolves %q, want supermicro — fixture is not exercising a partial identity", bmcQuirk.Key)
	}

	discovered := readHardwareIdentity(context.Background(), client, "cp-01", orchTestLogger())
	if discovered == nil {
		t.Fatal("a partial identity was discarded; the installer would fall back to default while the BMC uses the vendor entry")
	}

	o := newHardwareIdentityOrchestrator(t, nil)
	resolved, err := o.resolveNodeConfig("cp-01", RoleControlPlane, discovered)
	if err != nil {
		t.Fatalf("resolveNodeConfig: %v", err)
	}

	if got := quirks.ResolveIdentity(installerConfigFrom(t, resolved).HardwareIdentity()).Key; got != bmcQuirk.Key {
		t.Errorf("installer resolves %q, BMC client resolves %q", got, bmcQuirk.Key)
	}
}

// captureLogs returns a logger writing JSON records into buf, so a test can
// assert on what an operator would actually see.
func captureLogs(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestReadHardwareIdentity_WarnsOnIncompleteIdentity covers the silent case:
// the IPMI path reports a vendor-only identity with a NIL error when the FRU
// is definitively unavailable, so it arrives looking exactly like success.
// It is propagated — the BMC resolves its own quirk from that same value, so
// refusing would put the installer on Default() while the BMC sits on the
// vendor entry — but it must be announced, naming the fields the BMC did not
// fill and whether a board entry is reachable at all. Nothing downstream
// reports this; a fully-identified node and this one simply install against
// different quirks.
func TestReadHardwareIdentity_WarnsOnIncompleteIdentity(t *testing.T) {
	client := bmc.NewMockClient()
	client.Identity = quirks.Identity{Manufacturer: "Supermicro"} // FRU absent, nil error

	var logs bytes.Buffer
	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&logs))
	if id == nil {
		t.Fatal("a vendor-only identity was discarded; the BMC side still resolves the vendor entry from it")
	}

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &rec); err != nil {
		t.Fatalf("expected exactly one log record, got %q: %v", logs.String(), err)
	}
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN — an incomplete identity must not read as a clean resolution", rec["level"])
	}
	if got := rec["missing"]; got != "model,part-number" {
		t.Errorf("missing = %v, want \"model,part-number\"", got)
	}
	if rec["board_entry_reachable"] != false {
		t.Errorf("board_entry_reachable = %v, want false: with neither model nor part number the "+
			"manufacturer-wide entry is the best this node can resolve", rec["board_entry_reachable"])
	}
	if rec["quirk"] != "supermicro" {
		t.Errorf("quirk = %v, want supermicro", rec["quirk"])
	}
}

// TestReadHardwareIdentity_CompleteIdentityIsNotWarned keeps the warning
// meaningful: a BMC that named all three fields must not raise it, or the
// signal is noise and gets ignored on the deploy that needs it.
func TestReadHardwareIdentity_CompleteIdentityIsNotWarned(t *testing.T) {
	client := bmc.NewMockClient()
	client.Identity = miniFleetIdentity

	var logs bytes.Buffer
	if readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&logs)) == nil {
		t.Fatal("a complete identity was discarded")
	}

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &rec); err != nil {
		t.Fatalf("expected exactly one log record, got %q: %v", logs.String(), err)
	}
	if rec["level"] != "INFO" {
		t.Errorf("level = %v, want INFO for a fully-identified node", rec["level"])
	}
	if _, ok := rec["missing"]; ok {
		t.Errorf("a complete identity reported missing fields: %v", rec["missing"])
	}
}

// TestIdentityFieldsMissing names the fields in the order
// quirks.ResolveIdentity considers them, since the log is read by a human
// reconstructing why a node picked the quirk it did.
func TestIdentityFieldsMissing(t *testing.T) {
	cases := []struct {
		name string
		id   quirks.Identity
		want []string
	}{
		{"complete", miniFleetIdentity, nil},
		{"vendor only", quirks.Identity{Manufacturer: "Supermicro"}, []string{"model", "part-number"}},
		{"no part number", quirks.Identity{Manufacturer: "Supermicro", Model: "X10SDV-TP8F"}, []string{"part-number"}},
		{"nothing at all", quirks.Identity{}, []string{"manufacturer", "model", "part-number"}},
		// Matching trims before comparing, so a space-padded field names
		// nothing and must count as missing here too — FRU data is padded
		// often enough that the two measures disagreeing would report a
		// complete identity that resolves as if the field were absent.
		{"whitespace only", quirks.Identity{Manufacturer: "Supermicro", Model: "   ", PartNumber: "\t"},
			[]string{"model", "part-number"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := identityFieldsMissing(tc.id)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("identityFieldsMissing = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReadHardwareIdentity_BoardReachabilityNeedsManufacturer pins the
// diagnostic's accuracy. Every registry entry requires a manufacturer match
// before any model or part-number rule can apply, so an identity naming a
// board but no vendor resolves Default() — reporting a reachable board entry
// there would send a postmortem looking for a board quirk that was never on
// the table.
func TestReadHardwareIdentity_BoardReachabilityNeedsManufacturer(t *testing.T) {
	// Every case is an INCOMPLETE identity, because the field only appears
	// on the WARN a complete identity does not raise (covered by
	// TestReadHardwareIdentity_CompleteIdentityIsNotWarned).
	cases := []struct {
		name string
		id   quirks.Identity
		want bool
	}{
		{"vendor and model, no part number", quirks.Identity{Manufacturer: "Supermicro", Model: "X10SDV-TP8F"}, true},
		{"vendor and part number, no model", quirks.Identity{Manufacturer: "Supermicro", PartNumber: "SYS-5018D-FN8T-AS001"}, true},
		{"vendor only", quirks.Identity{Manufacturer: "Supermicro"}, false},
		{"board but no vendor", quirks.Identity{Model: "X10SDV-TP8F", PartNumber: "SYS-5018D-FN8T-AS001"}, false},
		{"nothing", quirks.Identity{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := bmc.NewMockClient()
			client.Identity = tc.id

			var logs bytes.Buffer
			readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&logs))

			var rec map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &rec); err != nil {
				t.Fatalf("log record: %v (%q)", err, logs.String())
			}
			got, present := rec["board_entry_reachable"]
			if !present {
				t.Fatalf("incomplete identity %+v logged no board_entry_reachable", tc.id)
			}
			if got != tc.want {
				t.Errorf("board_entry_reachable = %v, want %v", got, tc.want)
			}
			// The claim must match what the registry actually does.
			board := quirks.ResolveIdentity(tc.id).Key != quirks.Default().Key
			if tc.want && !board {
				t.Errorf("claimed a board entry is reachable but %+v resolves %q", tc.id, quirks.ResolveIdentity(tc.id).Key)
			}
		})
	}
}

// flakyIdentityClient answers HardwareIdentity with a partial identity and a
// retryable error for the first `failures` calls, then the full identity.
// It embeds bmc.Client (nil) so it satisfies the interface without
// implementing methods this test never calls.
type flakyIdentityClient struct {
	bmc.Client
	failures int
	partial  quirks.Identity
	full     quirks.Identity
	calls    int
	// script, when set, answers call N (1-based) instead of the
	// failures/partial/full behaviour, so a test can vary what each attempt
	// learns.
	script func(call int) (quirks.Identity, error)
}

func (f *flakyIdentityClient) HardwareIdentity(context.Context) (quirks.Identity, error) {
	f.calls++
	if f.script != nil {
		return f.script(f.calls)
	}
	if f.calls <= f.failures {
		return f.partial, bmc.ErrInventory{Cause: errors.New("fru read timeout")}
	}
	return f.full, nil
}

// TestReadHardwareIdentity_RetriesBeforeStagingAPartial covers the case where
// staging too eagerly loses parity in the one direction nothing can correct.
// A retryable FRU timeout is NOT cached by the client, so a later BMC
// operation retries and can resolve the board entry — while the installer
// config, written once, would be frozen on the manufacturer-wide entry.
// Re-reading at capture time is the cheap chance to agree.
func TestReadHardwareIdentity_RetriesBeforeStagingAPartial(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	client := &flakyIdentityClient{
		failures: 2, // succeeds on the third attempt, within identityReadAttempts
		partial:  quirks.Identity{Manufacturer: "Supermicro"},
		full:     miniFleetIdentity,
	}

	var logs bytes.Buffer
	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&logs))
	if id == nil {
		t.Fatal("readHardwareIdentity returned nil despite a successful retry")
	}
	if *id != miniFleetIdentity {
		t.Fatalf("staged %+v, want the full identity the retry resolved (%+v)", *id, miniFleetIdentity)
	}
	if client.calls != 3 {
		t.Errorf("HardwareIdentity called %d times, want 3", client.calls)
	}
	if got := quirks.ResolveIdentity(*id).Key; got != "supermicro/x10sdv" {
		t.Errorf("staged identity resolves %q, want supermicro/x10sdv — the board entry the "+
			"BMC side reaches once the FRU read succeeds", got)
	}
}

// TestReadHardwareIdentity_StagesPartialWhenRetriesExhausted keeps the
// fallback: retrying is a chance to agree, not a precondition. A BMC that
// never recovers still yields the vendor it named, because the BMC's own
// quirk resolution uses that same partial value.
func TestReadHardwareIdentity_StagesPartialWhenRetriesExhausted(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	client := &flakyIdentityClient{
		failures: identityReadAttempts + 1, // never succeeds
		partial:  quirks.Identity{Manufacturer: "Supermicro"},
	}

	var logs bytes.Buffer
	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&logs))
	if id == nil {
		t.Fatal("a partial identity was discarded after retries were exhausted")
	}
	if id.Manufacturer != "Supermicro" {
		t.Errorf("staged %+v, want the vendor the BMC named", *id)
	}
	if client.calls != identityReadAttempts {
		t.Errorf("HardwareIdentity called %d times, want %d", client.calls, identityReadAttempts)
	}
	if !bytes.Contains(logs.Bytes(), []byte("still partial after retries")) {
		t.Errorf("exhausted retries were not announced: %s", logs.String())
	}
}

// TestReadHardwareIdentity_RetryStopsOnCancelledContext keeps a cancelled run
// from sitting in the retry loop: discovery is concurrent across nodes and a
// cancelled context must unwind promptly.
func TestReadHardwareIdentity_RetryStopsOnCancelledContext(t *testing.T) {
	identityRetryDelay = time.Hour // any wait would hang the test
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := &flakyIdentityClient{failures: 99, partial: quirks.Identity{Manufacturer: "Supermicro"}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		readHardwareIdentity(ctx, client, "cp-01", captureLogs(&bytes.Buffer{}))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("readHardwareIdentity did not unwind on a cancelled context")
	}
	if client.calls != 1 {
		t.Errorf("HardwareIdentity called %d times on a cancelled context, want 1", client.calls)
	}
}

// TestReadHardwareIdentity_LaterEmptyFailureCannotEraseAPartial pins that
// retry attempts are not monotonic. Attempt 1 can name the vendor from Get
// Device ID and fail on the FRU; attempt 3 can fail earlier still — a
// dropped session names nothing at all. Overwriting the vendor with that
// later zero would report "learned nothing" and leave the keys unset, which
// is the behaviour the retry was added to avoid, reintroduced by the retry
// itself.
func TestReadHardwareIdentity_LaterEmptyFailureCannotEraseAPartial(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	client := &flakyIdentityClient{
		script: func(call int) (quirks.Identity, error) {
			if call == 1 {
				// Vendor learned, FRU timed out.
				return quirks.Identity{Manufacturer: "Supermicro"},
					bmc.ErrInventory{Cause: errors.New("fru read timeout")}
			}
			// Session dropped: nothing learned at all.
			return quirks.Identity{}, bmc.ErrInventory{Cause: errors.New("session closed")}
		},
	}

	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&bytes.Buffer{}))
	if id == nil {
		t.Fatal("the vendor learned on attempt 1 was erased by a later empty failure")
	}
	if id.Manufacturer != "Supermicro" {
		t.Fatalf("staged %+v, want the vendor attempt 1 learned", *id)
	}
	if got := quirks.ResolveIdentity(*id).Key; got != "supermicro" {
		t.Errorf("staged identity resolves %q, want supermicro — the entry the BMC side uses", got)
	}
}

// TestReadHardwareIdentity_RicherLaterAttemptWins is the other direction: a
// later attempt that learns MORE must replace the earlier, poorer answer.
func TestReadHardwareIdentity_RicherLaterAttemptWins(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	client := &flakyIdentityClient{
		script: func(call int) (quirks.Identity, error) {
			err := bmc.ErrInventory{Cause: errors.New("fru read timeout")}
			if call == 1 {
				return quirks.Identity{Manufacturer: "Supermicro"}, err
			}
			return miniFleetIdentity, err // names the board, still not definitive
		},
	}

	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&bytes.Buffer{}))
	if id == nil {
		t.Fatal("readHardwareIdentity discarded a usable identity")
	}
	if got := quirks.ResolveIdentity(*id).Key; got != "supermicro/x10sdv" {
		t.Errorf("staged identity resolves %q, want supermicro/x10sdv — the richer later answer must win", got)
	}
}

// placeholderModelIdentity and boardPartNumberIdentity are the two readings a
// Supermicro X10 BMC can give of the SAME board when the FRU read is partial.
// Both name two of the three fields, so field count cannot separate them —
// but only the part number reaches the supermicro/x10sdv entry; the
// placeholder Model "Super Server" identifies nothing and falls through to
// the manufacturer-wide entry.
var (
	placeholderModelIdentity = quirks.Identity{Manufacturer: "Supermicro", Model: "Super Server"}
	boardPartNumberIdentity  = quirks.Identity{Manufacturer: "Supermicro", PartNumber: "SYS-5018D-FN8T-AS001"}
)

// TestReadHardwareIdentity_BoardSpecificBeatsEqualFieldCount is the case
// field-counting gets wrong. Attempt 1 returns the placeholder model, attempt
// 2 the part number; both are one field short, so a selection that only
// counts empty fields keeps attempt 1 and stages the manufacturer-wide quirk
// while the BMC client goes on to resolve the board entry — the exact parity
// loss the retry exists to prevent, reintroduced by the selection rule.
func TestReadHardwareIdentity_BoardSpecificBeatsEqualFieldCount(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	// Guard the premise: the two readings are equally complete and resolve
	// different quirks. If the registry ever changes, this test says so.
	if len(identityFieldsMissing(placeholderModelIdentity)) != len(identityFieldsMissing(boardPartNumberIdentity)) {
		t.Fatalf("premise broken: %+v and %+v are no longer equally complete",
			placeholderModelIdentity, boardPartNumberIdentity)
	}
	if quirks.ResolveIdentity(placeholderModelIdentity).Key != "supermicro" {
		t.Fatalf("premise broken: the placeholder model no longer resolves the manufacturer-wide entry")
	}
	if quirks.ResolveIdentity(boardPartNumberIdentity).Key != "supermicro/x10sdv" {
		t.Fatalf("premise broken: the part number no longer resolves the board entry")
	}

	client := &flakyIdentityClient{
		script: func(call int) (quirks.Identity, error) {
			err := bmc.ErrInventory{Cause: errors.New("fru read timeout")}
			if call == 1 {
				return placeholderModelIdentity, err
			}
			return boardPartNumberIdentity, err
		},
	}

	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&bytes.Buffer{}))
	if id == nil {
		t.Fatal("readHardwareIdentity discarded a usable identity")
	}
	if got := quirks.ResolveIdentity(*id).Key; got != "supermicro/x10sdv" {
		t.Errorf("staged identity resolves %q, want supermicro/x10sdv — the board entry the later "+
			"attempt learned, which the BMC client will resolve too", got)
	}
}

// TestReadHardwareIdentity_BoardSpecificSurvivesALaterBroaderRead is the same
// pair in the other order: the board-specific answer arrives FIRST and a
// later, equally complete but broader answer must not displace it.
func TestReadHardwareIdentity_BoardSpecificSurvivesALaterBroaderRead(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	client := &flakyIdentityClient{
		script: func(call int) (quirks.Identity, error) {
			err := bmc.ErrInventory{Cause: errors.New("fru read timeout")}
			if call == 1 {
				return boardPartNumberIdentity, err
			}
			return placeholderModelIdentity, err
		},
	}

	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&bytes.Buffer{}))
	if id == nil {
		t.Fatal("readHardwareIdentity discarded a usable identity")
	}
	if got := quirks.ResolveIdentity(*id).Key; got != "supermicro/x10sdv" {
		t.Errorf("staged identity resolves %q, want supermicro/x10sdv — a broader later read must "+
			"not displace a board-specific one", got)
	}
}

// TestReadHardwareIdentity_FieldCountBreaksASpecificityTie covers the
// tiebreaker: when two attempts resolve the SAME quirk, the answer naming
// more fields is staged, because the extra field is what a human reading the
// staged config — or a future registry entry — has to go on.
func TestReadHardwareIdentity_FieldCountBreaksASpecificityTie(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	vendorOnly := quirks.Identity{Manufacturer: "Supermicro"}
	if quirks.ResolveIdentity(vendorOnly).Key != quirks.ResolveIdentity(placeholderModelIdentity).Key {
		t.Fatalf("premise broken: %+v and %+v no longer resolve the same quirk",
			vendorOnly, placeholderModelIdentity)
	}

	for _, tc := range []struct {
		name       string
		first      quirks.Identity
		later      quirks.Identity
		wantStaged quirks.Identity
	}{
		{"richer later attempt wins", vendorOnly, placeholderModelIdentity, placeholderModelIdentity},
		{"poorer later attempt loses", placeholderModelIdentity, vendorOnly, placeholderModelIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &flakyIdentityClient{
				script: func(call int) (quirks.Identity, error) {
					err := bmc.ErrInventory{Cause: errors.New("fru read timeout")}
					if call == 1 {
						return tc.first, err
					}
					return tc.later, err
				},
			}

			id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&bytes.Buffer{}))
			if id == nil {
				t.Fatal("readHardwareIdentity discarded a usable identity")
			}
			if *id != tc.wantStaged {
				t.Errorf("staged %+v, want %+v — equal specificity is broken by field count", *id, tc.wantStaged)
			}
		})
	}
}

// TestBetterIdentity exercises the selection rule directly, including the
// degenerate inputs readHardwareIdentity can hand it: the zero identity a
// dropped session returns, and an identity naming a vendor no entry knows.
func TestBetterIdentity(t *testing.T) {
	unknownVendor := quirks.Identity{Manufacturer: "Nobody", Model: "Nothing", PartNumber: "NONE"}

	for _, tc := range []struct {
		name string
		a, b quirks.Identity
		want bool
	}{
		{"board-specific beats equally complete manufacturer-wide", boardPartNumberIdentity, placeholderModelIdentity, true},
		{"manufacturer-wide never beats board-specific", placeholderModelIdentity, boardPartNumberIdentity, false},
		{"richer breaks a specificity tie", placeholderModelIdentity, quirks.Identity{Manufacturer: "Supermicro"}, true},
		{"poorer loses a specificity tie", quirks.Identity{Manufacturer: "Supermicro"}, placeholderModelIdentity, false},
		{"anything known beats the zero identity", quirks.Identity{Manufacturer: "Supermicro"}, quirks.Identity{}, true},
		{"the zero identity beats nothing", quirks.Identity{}, quirks.Identity{Manufacturer: "Supermicro"}, false},
		{"an unmatched vendor loses to a matched one", unknownVendor, quirks.Identity{Manufacturer: "Supermicro"}, false},
		{"an unmatched vendor still beats the zero identity on field count", unknownVendor, quirks.Identity{}, true},
		{"identical identities do not replace each other", boardPartNumberIdentity, boardPartNumberIdentity, false},
		// A space-padded field matches nothing, so it cannot make one
		// reading richer than another that leaves it empty.
		{"a padded field is not a populated one",
			quirks.Identity{Manufacturer: "Supermicro", Model: "  "},
			quirks.Identity{Manufacturer: "Supermicro"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := betterIdentity(tc.a, tc.b); got != tc.want {
				t.Errorf("betterIdentity(%+v, %+v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestReadHardwareIdentity_DefinitiveAnswerBeatsARicherFailedOne pins the one
// place richness does NOT win. A nil error is the client's definitive answer
// and the value it caches and resolves its own quirk from, so it is staged
// as-is even when an earlier failed attempt named the board: the earlier
// attempt's part number came from a FRU read now known to be unavailable
// rather than slow, and staging it would put the installed OS on
// supermicro/x10sdv while the BMC client uses the manufacturer-wide entry —
// the divergence this whole path exists to prevent.
func TestReadHardwareIdentity_DefinitiveAnswerBeatsARicherFailedOne(t *testing.T) {
	identityRetryDelay = 0
	t.Cleanup(func() { identityRetryDelay = 500 * time.Millisecond })

	definitive := quirks.Identity{Manufacturer: "Supermicro"}
	client := &flakyIdentityClient{
		script: func(call int) (quirks.Identity, error) {
			if call == 1 {
				return boardPartNumberIdentity, bmc.ErrInventory{Cause: errors.New("fru read timeout")}
			}
			return definitive, nil // FRU definitively unavailable, and cached
		},
	}

	id := readHardwareIdentity(context.Background(), client, "cp-01", captureLogs(&bytes.Buffer{}))
	if id == nil {
		t.Fatal("readHardwareIdentity discarded the definitive answer")
	}
	if *id != definitive {
		t.Fatalf("staged %+v, want %+v — the client's definitive answer", *id, definitive)
	}
	if got := quirks.ResolveIdentity(*id).Key; got != "supermicro" {
		t.Errorf("staged identity resolves %q, want supermicro — the entry the BMC client now uses", got)
	}
	if client.calls != 2 {
		t.Errorf("HardwareIdentity called %d times, want 2 — a definitive answer ends the loop", client.calls)
	}
}
