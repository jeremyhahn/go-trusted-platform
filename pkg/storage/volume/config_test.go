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

package volume

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultConfig_Validates(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() = %v, want nil", err)
	}
}

func TestDefaultConfig_ClassMapping(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DefaultClass != ClassGeneral {
		t.Fatalf("DefaultClass = %q, want %q", cfg.DefaultClass, ClassGeneral)
	}

	tests := []struct {
		name        string
		provider    string
		volumeGroup string
		defaults    VolumeDefaults
		object      bool
	}{
		{ClassReplicated, ProviderDRBD, DefaultVolumeGroup, VolumeDefaults{FSType: DefaultFSType, Replicas: DefaultReplicas}, false},
		{ClassGeneral, ProviderLocal, DefaultVolumeGroup, VolumeDefaults{FSType: DefaultFSType}, false},
		{ClassObject, ProviderObjStore, "", VolumeDefaults{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc, err := cfg.Class(tc.name)
			if err != nil {
				t.Fatalf("Class(%q) error = %v", tc.name, err)
			}
			if sc.Provider != tc.provider {
				t.Errorf("Provider = %q, want %q", sc.Provider, tc.provider)
			}
			if sc.VolumeGroup != tc.volumeGroup {
				t.Errorf("VolumeGroup = %q, want %q", sc.VolumeGroup, tc.volumeGroup)
			}
			if sc.Defaults != tc.defaults {
				t.Errorf("Defaults = %+v, want %+v", sc.Defaults, tc.defaults)
			}
			if sc.IsObjectStore() != tc.object {
				t.Errorf("IsObjectStore() = %v, want %v", sc.IsObjectStore(), tc.object)
			}
			if tc.object && !sc.Defaults.IsZero() {
				t.Errorf("object class Defaults.IsZero() = false, want true")
			}
		})
	}
}

func TestStorageClass_ToSettings(t *testing.T) {
	sc := StorageClass{
		Name:        "general",
		Provider:    ProviderLocal,
		VolumeGroup: "vg0",
		NodeID:      "node-a",
		Settings:    map[string]string{"minor_base": "100"},
	}
	got := sc.ToSettings()
	want := map[string]string{"volume_group": "vg0", "node_id": "node-a", "minor_base": "100"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ToSettings() = %v, want %v", got, want)
	}

	got["minor_base"] = "200"
	got["extra"] = "x"
	if sc.Settings["minor_base"] != "100" || len(sc.Settings) != 1 {
		t.Fatalf("mutating ToSettings() result changed Settings: %v", sc.Settings)
	}

	empty := StorageClass{Name: "general", Provider: ProviderLocal}
	if got := empty.ToSettings(); len(got) != 0 {
		t.Fatalf("ToSettings() with empty typed fields = %v, want empty", got)
	}
	if got := empty.ToSettings(); got == nil {
		t.Fatalf("ToSettings() = nil, want a non-nil map")
	}
}

func TestStorageClass_Validate(t *testing.T) {
	valid := func() StorageClass {
		return StorageClass{
			Name:        "general",
			Provider:    ProviderLocal,
			VolumeGroup: "vg0",
			Defaults:    VolumeDefaults{FSType: DefaultFSType},
		}
	}
	tests := []struct {
		name   string
		mutate func(*StorageClass)
		want   error
	}{
		{"valid", func(*StorageClass) {}, nil},
		{"empty name", func(sc *StorageClass) { sc.Name = "" }, ErrClassNameRequired},
		{"empty provider", func(sc *StorageClass) { sc.Provider = "" }, ErrProviderRequired},
		{"unknown provider", func(sc *StorageClass) { sc.Provider = "nfs" }, ErrUnknownProvider},
		{"negative replicas", func(sc *StorageClass) { sc.Defaults.Replicas = -1 }, ErrInvalidReplicas},
		{"setting conflict", func(sc *StorageClass) {
			sc.Settings = map[string]string{"volume_group": "vg1"}
		}, ErrSettingConflict},
		{"object with volume group", func(sc *StorageClass) {
			sc.Provider = ProviderObjStore
			sc.Defaults = VolumeDefaults{}
		}, ErrBlockSettingOnObjectClass},
		{"object with replicas", func(sc *StorageClass) {
			sc.Provider = ProviderObjStore
			sc.VolumeGroup = ""
			sc.Defaults = VolumeDefaults{Replicas: 2}
		}, ErrBlockSettingOnObjectClass},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc := valid()
			tc.mutate(&sc)
			err := sc.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate() = %v, want errors.Is %v", err, tc.want)
			}
		})
	}
}

func TestStorageClass_ValidateConflictIsStable(t *testing.T) {
	sc := StorageClass{
		Name:        "general",
		Provider:    ProviderLocal,
		VolumeGroup: "vg0",
		NodeID:      "node-a",
		Settings:    map[string]string{"volume_group": "vg1", "node_id": "node-b"},
	}
	first := sc.Validate()
	if !errors.Is(first, ErrSettingConflict) {
		t.Fatalf("Validate() = %v, want ErrSettingConflict", first)
	}
	for i := 0; i < 20; i++ {
		if err := sc.Validate(); err.Error() != first.Error() {
			t.Fatalf("Validate() run %d = %q, want %q", i, err, first)
		}
	}
	if !strings.Contains(first.Error(), SettingVolumeGroup) {
		t.Fatalf("Validate() = %q, want the first typed key %q", first, SettingVolumeGroup)
	}
}

func TestConfig_Validate(t *testing.T) {
	var nilCfg *Config
	if err := nilCfg.Validate(); !errors.Is(err, ErrNilConfig) {
		t.Fatalf("nil Validate() = %v, want ErrNilConfig", err)
	}

	if err := (&Config{}).Validate(); !errors.Is(err, ErrNoClasses) {
		t.Fatalf("no classes Validate() = %v, want ErrNoClasses", err)
	}

	dup := &Config{
		DefaultClass: "general",
		Classes: []StorageClass{
			{Name: "general", Provider: ProviderLocal},
			{Name: "general", Provider: ProviderLocal},
		},
	}
	if err := dup.Validate(); !errors.Is(err, ErrDuplicateClass) {
		t.Fatalf("duplicate Validate() = %v, want ErrDuplicateClass", err)
	}

	unknownDefault := DefaultConfig()
	unknownDefault.DefaultClass = "fast"
	if err := unknownDefault.Validate(); !errors.Is(err, ErrUnknownDefaultClass) {
		t.Fatalf("unknown default Validate() = %v, want ErrUnknownDefaultClass", err)
	}

	bad := DefaultConfig()
	bad.Classes[0].Provider = "nfs"
	err := bad.Validate()
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("bad class Validate() = %v, want ErrUnknownProvider", err)
	}
	if !strings.Contains(err.Error(), bad.Classes[0].Name) {
		t.Fatalf("bad class Validate() = %q, want the class name %q", err, bad.Classes[0].Name)
	}
}

func TestConfig_Class(t *testing.T) {
	cfg := DefaultConfig()

	sc, err := cfg.Class("")
	if err != nil || sc.Name != cfg.DefaultClass {
		t.Fatalf("Class(\"\") = %q, %v; want %q", sc.Name, err, cfg.DefaultClass)
	}

	sc, err = cfg.Class(ClassReplicated)
	if err != nil || sc.Name != ClassReplicated || sc.Provider != ProviderDRBD {
		t.Fatalf("Class(replicated) = %+v, %v", sc, err)
	}

	if _, err := cfg.Class("fast"); !errors.Is(err, ErrUnknownClass) {
		t.Fatalf("Class(fast) error = %v, want ErrUnknownClass", err)
	}

	noDefault := DefaultConfig()
	noDefault.DefaultClass = ""
	if _, err := noDefault.Class(""); !errors.Is(err, ErrNoDefaultClass) {
		t.Fatalf("Class(\"\") with no default error = %v, want ErrNoDefaultClass", err)
	}

	cfg.Classes[0].Settings = map[string]string{"minor_base": "100"}
	sc, err = cfg.Class(cfg.Classes[0].Name)
	if err != nil {
		t.Fatalf("Class() error = %v", err)
	}
	sc.Settings["minor_base"] = "200"
	sc.Settings["extra"] = "x"
	if cfg.Classes[0].Settings["minor_base"] != "100" || len(cfg.Classes[0].Settings) != 1 {
		t.Fatalf("changing the returned class changed the Config: %v", cfg.Classes[0].Settings)
	}

	var nilCfg *Config
	if _, err := nilCfg.Class(""); !errors.Is(err, ErrNilConfig) {
		t.Fatalf("nil Class() error = %v, want ErrNilConfig", err)
	}
}

func TestConfig_Clone(t *testing.T) {
	var nilCfg *Config
	if nilCfg.Clone() != nil {
		t.Fatalf("nil Clone() != nil")
	}

	orig := DefaultConfig()
	orig.Classes[0].Settings = map[string]string{"minor_base": "100"}
	clone := orig.Clone()
	if !reflect.DeepEqual(orig, clone) {
		t.Fatalf("Clone() = %+v, want %+v", clone, orig)
	}

	clone.Classes[0].Settings["minor_base"] = "200"
	clone.Classes[0].Name = "changed"
	clone.Classes = append(clone.Classes[:1], StorageClass{Name: "fast", Provider: ProviderLocal})
	clone.DefaultClass = "fast"

	if orig.Classes[0].Settings["minor_base"] != "100" {
		t.Fatalf("clone Settings change reached the original")
	}
	if orig.Classes[0].Name == "changed" || len(orig.Classes) != 3 || orig.Classes[1].Name == "fast" {
		t.Fatalf("clone Classes change reached the original: %+v", orig.Classes)
	}
	if orig.DefaultClass != ClassGeneral {
		t.Fatalf("clone DefaultClass change reached the original")
	}
}
