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

import "fmt"

// Storage class names.
const (
	// ClassReplicated is block storage replicated across nodes.
	ClassReplicated = "replicated"

	// ClassGeneral is general-purpose block storage.
	ClassGeneral = "general"

	// ClassObject is object storage.
	ClassObject = "object"
)

// Provider names.
const (
	// ProviderLocal is node-local block storage.
	ProviderLocal = "local"

	// ProviderDRBD is DRBD-replicated block storage.
	ProviderDRBD = "drbd"

	// ProviderCephRBD is Ceph RBD block storage. It is named here and not
	// yet available from any provider.
	ProviderCephRBD = "cephrbd"

	// ProviderObjStore is not a block provider: a class naming it routes
	// to the object store in pkg/store/object.
	ProviderObjStore = "objstore"
)

// Construction settings keys every block backend shares. Anything
// provider-specific goes through StorageClass.Settings under that
// provider's own key names.
const (
	// SettingVolumeGroup is the volume group a block provider allocates in.
	SettingVolumeGroup = "volume_group"

	// SettingNodeID is the node a block provider runs as.
	SettingNodeID = "node_id"
)

// Defaults for the built-in storage classes.
const (
	// DefaultVolumeGroup is the volume group of the default block classes.
	DefaultVolumeGroup = "platform"

	// DefaultFSType is the default filesystem of a new volume.
	DefaultFSType = "ext4"

	// DefaultReplicas is the default replica count of the replicated class.
	DefaultReplicas = 2
)

// typedKeys lists the settings keys a typed StorageClass field owns, in the
// fixed order validation checks them.
var typedKeys = []string{SettingVolumeGroup, SettingNodeID}

// VolumeDefaults are per-volume defaults of a storage class. They are not
// construction settings, so ToSettings never emits them.
type VolumeDefaults struct {
	// FSType is the filesystem a new volume is formatted with.
	FSType string `yaml:"fstype,omitempty" json:"fstype,omitempty" mapstructure:"fstype"`

	// Replicas is the replica count of a new volume (0 = provider default).
	Replicas int `yaml:"replicas,omitempty" json:"replicas,omitempty" mapstructure:"replicas"`
}

// IsZero reports whether no default is set.
func (d VolumeDefaults) IsZero() bool {
	return d == VolumeDefaults{}
}

// StorageClass maps a class name to the provider that serves it and the
// settings that provider is constructed with.
type StorageClass struct {
	// Name is the class name a workload asks for.
	Name string `yaml:"name" json:"name" mapstructure:"name"`

	// Provider names the provider serving the class.
	Provider string `yaml:"provider" json:"provider" mapstructure:"provider"`

	// VolumeGroup is the volume group a block provider allocates in.
	VolumeGroup string `yaml:"volume-group,omitempty" json:"volume_group,omitempty" mapstructure:"volume-group"`

	// NodeID is the node a block provider runs as.
	NodeID string `yaml:"node-id,omitempty" json:"node_id,omitempty" mapstructure:"node-id"`

	// Settings holds provider-specific construction settings.
	Settings map[string]string `yaml:"settings,omitempty" json:"settings,omitempty" mapstructure:"settings"`

	// Defaults are the per-volume defaults of the class.
	Defaults VolumeDefaults `yaml:"defaults,omitempty" json:"defaults,omitempty" mapstructure:"defaults"`
}

// IsObjectStore reports whether the class routes to the object store
// rather than to a block provider.
func (c StorageClass) IsObjectStore() bool {
	return c.Provider == ProviderObjStore
}

// Clone returns a copy of the class with its own Settings map.
func (c StorageClass) Clone() StorageClass {
	out := c
	if c.Settings != nil {
		out.Settings = make(map[string]string, len(c.Settings))
		for k, v := range c.Settings {
			out.Settings[k] = v
		}
	}
	return out
}

// typedValue returns the value of the typed field owning key.
func (c StorageClass) typedValue(key string) string {
	switch key {
	case SettingVolumeGroup:
		return c.VolumeGroup
	case SettingNodeID:
		return c.NodeID
	}
	return ""
}

// ToSettings returns a new map of the class's construction settings:
// Settings, then each non-empty typed field under its key.
func (c StorageClass) ToSettings() map[string]string {
	out := make(map[string]string, len(c.Settings)+len(typedKeys))
	for k, v := range c.Settings {
		out[k] = v
	}
	for _, key := range typedKeys {
		if v := c.typedValue(key); v != "" {
			out[key] = v
		}
	}
	return out
}

// Validate checks the class. Errors wrap one of the package sentinels.
func (c StorageClass) Validate() error {
	if c.Name == "" {
		return ErrClassNameRequired
	}
	if err := c.validate(); err != nil {
		return fmt.Errorf("storage class %q: %w", c.Name, err)
	}
	return nil
}

func (c StorageClass) validate() error {
	switch c.Provider {
	case "":
		return ErrProviderRequired
	case ProviderLocal, ProviderDRBD, ProviderCephRBD, ProviderObjStore:
	default:
		return fmt.Errorf("%w %q", ErrUnknownProvider, c.Provider)
	}
	if c.Defaults.Replicas < 0 {
		return fmt.Errorf("%w: %d", ErrInvalidReplicas, c.Defaults.Replicas)
	}
	for _, key := range typedKeys {
		typed := c.typedValue(key)
		if v, ok := c.Settings[key]; ok && typed != "" && v != typed {
			return fmt.Errorf("%w: %s is %q and settings has %q", ErrSettingConflict, key, typed, v)
		}
	}
	if c.IsObjectStore() {
		switch {
		case c.VolumeGroup != "":
			return fmt.Errorf("%w: %s", ErrBlockSettingOnObjectClass, SettingVolumeGroup)
		case c.NodeID != "":
			return fmt.Errorf("%w: %s", ErrBlockSettingOnObjectClass, SettingNodeID)
		case c.Defaults.Replicas != 0:
			return fmt.Errorf("%w: replicas", ErrBlockSettingOnObjectClass)
		case c.Defaults.FSType != "":
			return fmt.Errorf("%w: fstype", ErrBlockSettingOnObjectClass)
		}
	}
	return nil
}

// Config is the volume configuration: the storage classes and the class
// used when a workload names none.
type Config struct {
	// DefaultClass is the class used for an empty class name.
	DefaultClass string `yaml:"default-class" json:"default_class" mapstructure:"default-class"`

	// Classes are the configured storage classes.
	Classes []StorageClass `yaml:"classes" json:"classes" mapstructure:"classes"`
}

// DefaultConfig returns the built-in classes: replicated (DRBD), general
// (local) and object (the object store), with general as the default.
func DefaultConfig() *Config {
	return &Config{
		DefaultClass: ClassGeneral,
		Classes: []StorageClass{
			{
				Name:        ClassReplicated,
				Provider:    ProviderDRBD,
				VolumeGroup: DefaultVolumeGroup,
				Defaults:    VolumeDefaults{FSType: DefaultFSType, Replicas: DefaultReplicas},
			},
			{
				Name:        ClassGeneral,
				Provider:    ProviderLocal,
				VolumeGroup: DefaultVolumeGroup,
				Defaults:    VolumeDefaults{FSType: DefaultFSType},
			},
			{
				Name:     ClassObject,
				Provider: ProviderObjStore,
			},
		},
	}
}

// Clone returns a deep copy of the Config; Clone of nil is nil.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := &Config{DefaultClass: c.DefaultClass}
	if c.Classes != nil {
		out.Classes = make([]StorageClass, len(c.Classes))
		for i, sc := range c.Classes {
			out.Classes[i] = sc.Clone()
		}
	}
	return out
}

// Validate checks every class, that class names are unique and that a set
// DefaultClass names a configured class.
func (c *Config) Validate() error {
	if c == nil {
		return ErrNilConfig
	}
	if len(c.Classes) == 0 {
		return ErrNoClasses
	}
	seen := make(map[string]struct{}, len(c.Classes))
	for i, sc := range c.Classes {
		if err := sc.Validate(); err != nil {
			if sc.Name == "" {
				return fmt.Errorf("storage class %d: %w", i, err)
			}
			return err
		}
		if _, dup := seen[sc.Name]; dup {
			return fmt.Errorf("%w %q", ErrDuplicateClass, sc.Name)
		}
		seen[sc.Name] = struct{}{}
	}
	if c.DefaultClass != "" {
		if _, ok := seen[c.DefaultClass]; !ok {
			return fmt.Errorf("%w: %q", ErrUnknownDefaultClass, c.DefaultClass)
		}
	}
	return nil
}

// Class returns a copy of the named class; an empty name is the
// DefaultClass.
func (c *Config) Class(name string) (StorageClass, error) {
	if c == nil {
		return StorageClass{}, ErrNilConfig
	}
	if name == "" {
		if c.DefaultClass == "" {
			return StorageClass{}, ErrNoDefaultClass
		}
		name = c.DefaultClass
	}
	for _, sc := range c.Classes {
		if sc.Name == name {
			return sc.Clone(), nil
		}
	}
	return StorageClass{}, fmt.Errorf("%w %q", ErrUnknownClass, name)
}
