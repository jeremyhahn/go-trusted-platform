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

package iso

import (
	"reflect"
	"sort"
	"testing"
)

// sampleModulesDep mirrors the relevant shape of an Alpine modules.dep:
// chained, transitive dependencies plus standalone leaf modules.
const sampleModulesDep = `# a comment line is ignored
kernel/drivers/net/ethernet/intel/ixgbe/ixgbe.ko: kernel/drivers/net/mdio.ko kernel/drivers/ptp/ptp.ko
kernel/drivers/net/ethernet/intel/igb/igb.ko: kernel/drivers/i2c/algos/i2c-algo-bit.ko kernel/drivers/dca/dca.ko
kernel/drivers/net/ethernet/intel/i40e/i40e.ko: kernel/drivers/ptp/ptp.ko
kernel/drivers/net/mdio.ko:
kernel/drivers/ptp/ptp.ko:
kernel/drivers/i2c/algos/i2c-algo-bit.ko:
kernel/drivers/dca/dca.ko:
kernel/drivers/net/ethernet/realtek/r8169.ko:
`

func TestResolveModuleDeps(t *testing.T) {
	tests := []struct {
		name    string
		deps    string
		wanted  []string
		want    []string
		wantErr bool
	}{
		{
			name:   "transitive closure for igb and ixgbe",
			deps:   sampleModulesDep,
			wanted: []string{"igb", "ixgbe"},
			want: []string{
				"kernel/drivers/dca/dca.ko",
				"kernel/drivers/i2c/algos/i2c-algo-bit.ko",
				"kernel/drivers/net/ethernet/intel/igb/igb.ko",
				"kernel/drivers/net/ethernet/intel/ixgbe/ixgbe.ko",
				"kernel/drivers/net/mdio.ko",
				"kernel/drivers/ptp/ptp.ko",
			},
		},
		{
			name:   "shared dependency deduplicated across drivers",
			deps:   sampleModulesDep,
			wanted: []string{"ixgbe", "i40e"},
			want: []string{
				"kernel/drivers/net/ethernet/intel/i40e/i40e.ko",
				"kernel/drivers/net/ethernet/intel/ixgbe/ixgbe.ko",
				"kernel/drivers/net/mdio.ko",
				"kernel/drivers/ptp/ptp.ko",
			},
		},
		{
			name:   "missing wanted module is skipped, present one resolved",
			deps:   sampleModulesDep,
			wanted: []string{"igb", "nonexistent_driver"},
			want: []string{
				"kernel/drivers/dca/dca.ko",
				"kernel/drivers/i2c/algos/i2c-algo-bit.ko",
				"kernel/drivers/net/ethernet/intel/igb/igb.ko",
			},
		},
		{
			name:   "leaf module with no dependencies",
			deps:   sampleModulesDep,
			wanted: []string{"r8169"},
			want:   []string{"kernel/drivers/net/ethernet/realtek/r8169.ko"},
		},
		{
			name:   "empty wanted yields empty result",
			deps:   sampleModulesDep,
			wanted: nil,
			want:   nil,
		},
		{
			name:   "all wanted absent yields empty result",
			deps:   sampleModulesDep,
			wanted: []string{"foo", "bar"},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveModuleDeps(tt.deps, tt.wanted)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("resolveModuleDeps() closure mismatch\n got: %v\nwant: %v", got, want)
			}
		})
	}
}

func TestModuleName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"kernel/drivers/net/ethernet/intel/igb/igb.ko", "igb"},
		{"kernel/drivers/net/mdio.ko.gz", "mdio"},
		{"kernel/drivers/net/foo.ko.xz", "foo"},
		{"kernel/drivers/net/bar.ko.zst", "bar"},
		{"i2c-algo-bit.ko", "i2c-algo-bit"},
		{"plain", "plain"},
	}
	for _, tt := range tests {
		if got := moduleName(tt.path); got != tt.want {
			t.Errorf("moduleName(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestNormalizeModuleName(t *testing.T) {
	if got := normalizeModuleName("bnxt-en"); got != "bnxt_en" {
		t.Errorf("normalizeModuleName(bnxt-en) = %q, want bnxt_en", got)
	}
	if got := normalizeModuleName("mlx5_core"); got != "mlx5_core" {
		t.Errorf("normalizeModuleName(mlx5_core) = %q, want mlx5_core", got)
	}
}

// TestResolveModuleDepsNameNormalization confirms a wanted name using hyphens
// resolves a dep-file entry that uses underscores (modprobe alias behavior).
func TestResolveModuleDepsNameNormalization(t *testing.T) {
	deps := "kernel/drivers/net/ethernet/broadcom/bnxt/bnxt_en.ko:\n"
	got, err := resolveModuleDeps(deps, []string{"bnxt-en"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"kernel/drivers/net/ethernet/broadcom/bnxt/bnxt_en.ko"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
