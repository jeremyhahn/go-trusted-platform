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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildManifest(t *testing.T) {
	nodes := []DiscoveredNodeInfo{
		{MACs: []string{"AA:BB:CC:DD:EE:01"}, Role: "control-plane", Hostname: "cp-01"},
		{MACs: []string{"aa:bb:cc:dd:ee:02"}, Role: "worker", Hostname: "worker-01"},
	}

	manifest := BuildManifest(nodes)

	if len(manifest.Nodes) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(manifest.Nodes))
	}

	// MACs should be lowercased.
	if manifest.Nodes[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("expected lowercased MAC, got %s", manifest.Nodes[0].MAC)
	}
	if manifest.Nodes[0].Role != "control-plane" {
		t.Errorf("expected role control-plane, got %s", manifest.Nodes[0].Role)
	}
	if manifest.Nodes[0].Hostname != "cp-01" {
		t.Errorf("expected hostname cp-01, got %s", manifest.Nodes[0].Hostname)
	}
	if manifest.Nodes[1].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("expected lowercased MAC, got %s", manifest.Nodes[1].MAC)
	}
}

// TestBuildManifest_BootModel: the boot model travels per node, each MAC
// of a node carrying it, and a node without one stays without.
func TestBuildManifest_BootModel(t *testing.T) {
	manifest := BuildManifest([]DiscoveredNodeInfo{
		{MACs: []string{"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"}, Role: "worker", Hostname: "diskless-01", BootModel: "diskless"},
		{MACs: []string{"aa:bb:cc:dd:ee:03"}, Role: "worker", Hostname: "disk-01"},
	})
	if len(manifest.Nodes) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(manifest.Nodes))
	}
	for i, want := range []string{"diskless", "diskless", ""} {
		if manifest.Nodes[i].BootModel != want {
			t.Errorf("entry %d (%s) boot model = %q, want %q", i, manifest.Nodes[i].MAC, manifest.Nodes[i].BootModel, want)
		}
	}
}

func TestBuildManifest_Empty(t *testing.T) {
	manifest := BuildManifest(nil)
	if len(manifest.Nodes) != 0 {
		t.Fatalf("expected 0 entries for nil input, got %d", len(manifest.Nodes))
	}
}

func TestLookupMAC_Found(t *testing.T) {
	manifest := &Manifest{
		Nodes: []ManifestEntry{
			{MAC: "aa:bb:cc:dd:ee:01", Role: "control-plane", Hostname: "cp-01"},
			{MAC: "aa:bb:cc:dd:ee:02", Role: "worker", Hostname: "worker-01"},
		},
	}

	entry, found := manifest.LookupMAC("aa:bb:cc:dd:ee:01")
	if !found {
		t.Fatal("expected to find MAC")
	}
	if entry.Hostname != "cp-01" {
		t.Errorf("expected hostname cp-01, got %s", entry.Hostname)
	}
}

func TestLookupMAC_NotFound(t *testing.T) {
	manifest := &Manifest{
		Nodes: []ManifestEntry{
			{MAC: "aa:bb:cc:dd:ee:01", Role: "control-plane", Hostname: "cp-01"},
		},
	}

	_, found := manifest.LookupMAC("ff:ff:ff:ff:ff:ff")
	if found {
		t.Fatal("expected MAC not to be found")
	}
}

func TestLookupMAC_CaseInsensitive(t *testing.T) {
	manifest := &Manifest{
		Nodes: []ManifestEntry{
			{MAC: "aa:bb:cc:dd:ee:01", Role: "control-plane", Hostname: "cp-01"},
		},
	}

	entry, found := manifest.LookupMAC("AA:BB:CC:DD:EE:01")
	if !found {
		t.Fatal("expected case-insensitive lookup to succeed")
	}
	if entry.Hostname != "cp-01" {
		t.Errorf("expected hostname cp-01, got %s", entry.Hostname)
	}
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.yaml")

	original := &Manifest{
		Nodes: []ManifestEntry{
			{MAC: "aa:bb:cc:dd:ee:01", Role: "control-plane", Hostname: "cp-01", Architecture: "arm64", MediaSet: "aarch64-rpi"},
			{MAC: "aa:bb:cc:dd:ee:02", Role: "worker", Hostname: "worker-01"},
		},
	}

	if err := original.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}

	if len(loaded.Nodes) != len(original.Nodes) {
		t.Fatalf("expected %d entries, got %d", len(original.Nodes), len(loaded.Nodes))
	}

	for i := range original.Nodes {
		if loaded.Nodes[i].MAC != original.Nodes[i].MAC {
			t.Errorf("entry %d: MAC mismatch: %s vs %s", i, loaded.Nodes[i].MAC, original.Nodes[i].MAC)
		}
		if loaded.Nodes[i].Role != original.Nodes[i].Role {
			t.Errorf("entry %d: role mismatch: %s vs %s", i, loaded.Nodes[i].Role, original.Nodes[i].Role)
		}
		if loaded.Nodes[i].Hostname != original.Nodes[i].Hostname {
			t.Errorf("entry %d: hostname mismatch: %s vs %s", i, loaded.Nodes[i].Hostname, original.Nodes[i].Hostname)
		}
		if loaded.Nodes[i].Architecture != original.Nodes[i].Architecture || loaded.Nodes[i].MediaSet != original.Nodes[i].MediaSet {
			t.Errorf("entry %d: architecture/media_set mismatch: %s/%s vs %s/%s", i, loaded.Nodes[i].Architecture, loaded.Nodes[i].MediaSet, original.Nodes[i].Architecture, original.Nodes[i].MediaSet)
		}
	}
}

func TestLoadManifest_NotFound(t *testing.T) {
	_, err := LoadManifest("/nonexistent/manifest.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent manifest")
	}
	var target ErrManifestNotFound
	if !errors.As(err, &target) {
		t.Errorf("expected ErrManifestNotFound, got %T: %v", err, err)
	}
}

func TestLoadManifest_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadManifest(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	var target ErrManifestParse
	if !errors.As(err, &target) {
		t.Errorf("expected ErrManifestParse, got %T: %v", err, err)
	}
}

func TestSaveToFile_InvalidPath(t *testing.T) {
	manifest := &Manifest{
		Nodes: []ManifestEntry{
			{MAC: "aa:bb:cc:dd:ee:01", Role: "worker", Hostname: "w-01"},
		},
	}

	err := manifest.SaveToFile("/nonexistent/dir/manifest.yaml")
	if err == nil {
		t.Fatal("expected error for invalid write path")
	}
	var target ErrManifestWrite
	if !errors.As(err, &target) {
		t.Errorf("expected ErrManifestWrite, got %T: %v", err, err)
	}
}

func TestBuildManifest_MultipleMACsPerNode(t *testing.T) {
	nodes := []DiscoveredNodeInfo{
		{
			MACs:     []string{"00:25:90:00:02:AA", "00:25:90:00:02:AB", "00:25:90:00:02:AC"},
			Role:     "control-plane",
			Hostname: "cp-01",
		},
		{
			MACs:     []string{"00:25:90:00:02:BA"},
			Role:     "worker",
			Hostname: "w-01",
		},
	}

	manifest := BuildManifest(nodes)
	if len(manifest.Nodes) != 4 {
		t.Fatalf("expected 4 entries (3+1), got %d", len(manifest.Nodes))
	}

	// All three CP entries should resolve to the same hostname/role.
	for i := 0; i < 3; i++ {
		if manifest.Nodes[i].Hostname != "cp-01" || manifest.Nodes[i].Role != "control-plane" {
			t.Errorf("entry %d: expected cp-01/control-plane, got %s/%s",
				i, manifest.Nodes[i].Hostname, manifest.Nodes[i].Role)
		}
	}

	// Lookup by any of the three MACs returns the same entry.
	for _, mac := range []string{"00:25:90:00:02:aa", "00:25:90:00:02:AB", "00-25-90-00-02-ac"} {
		entry, ok := manifest.LookupMAC(mac)
		if !ok && mac != "00-25-90-00-02-ac" {
			t.Errorf("expected to find MAC %s", mac)
			continue
		}
		if ok && entry.Hostname != "cp-01" {
			t.Errorf("MAC %s resolved to wrong hostname: %s", mac, entry.Hostname)
		}
	}
}

func TestBuildManifest_SkipsEmptyMACs(t *testing.T) {
	nodes := []DiscoveredNodeInfo{
		{MACs: []string{"", "aa:bb:cc:dd:ee:01", ""}, Role: "worker", Hostname: "w-01"},
	}
	manifest := BuildManifest(nodes)
	if len(manifest.Nodes) != 1 {
		t.Fatalf("expected 1 entry (empty MACs filtered), got %d", len(manifest.Nodes))
	}
	if manifest.Nodes[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("unexpected MAC: %s", manifest.Nodes[0].MAC)
	}
}
