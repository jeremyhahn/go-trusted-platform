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
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// Manifest maps MAC addresses to node roles, hostnames and the media set
// each node boots.
type Manifest struct {
	Nodes []ManifestEntry `yaml:"nodes" json:"nodes"`
}

// ManifestEntry describes a single node in the manifest.
type ManifestEntry struct {
	MAC      string `yaml:"mac" json:"mac"`
	Role     string `yaml:"role" json:"role"`
	Hostname string `yaml:"hostname" json:"hostname"`
	// Architecture is the node's iPXE ${buildarch} (x86_64, arm64); empty
	// for x86_64.
	Architecture string `yaml:"architecture,omitempty" json:"architecture,omitempty"`
	// MediaSet names the set the node boots; empty means its
	// architecture's default.
	MediaSet string `yaml:"media_set,omitempty" json:"media_set,omitempty"`
	// BootModel is the node's boot model: disklessroot.BootModel for a node
	// that boots the set's diskless root, empty for one that installs to its
	// disk.
	BootModel string `yaml:"boot_model,omitempty" json:"boot_model,omitempty"`
}

// DiscoveredNodeInfo holds the minimal fields needed to build manifest
// entries from a discovered node. A node may expose multiple NIC MACs and
// the BIOS chooses one at PXE boot time, so all of them are passed to the
// manifest builder. This avoids importing the parent bootstrap package.
type DiscoveredNodeInfo struct {
	MACs         []string
	Role         string
	Hostname     string
	Architecture string
	MediaSet     string
	BootModel    string
}

// BuildManifest creates a manifest from discovered node info. One entry is
// emitted per (node x MAC) so the PXE server can resolve whichever NIC the
// BIOS happens to PXE-boot from to the same role / hostname / config.
func BuildManifest(nodes []DiscoveredNodeInfo) *Manifest {
	entries := make([]ManifestEntry, 0, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		for _, mac := range node.MACs {
			if mac == "" {
				continue
			}
			entries = append(entries, ManifestEntry{
				MAC:          strings.ToLower(mac),
				Role:         node.Role,
				Hostname:     node.Hostname,
				Architecture: node.Architecture,
				MediaSet:     node.MediaSet,
				BootModel:    node.BootModel,
			})
		}
	}
	return &Manifest{Nodes: entries}
}

// LookupMAC finds a manifest entry by MAC address (case-insensitive).
func (m *Manifest) LookupMAC(mac string) (*ManifestEntry, bool) {
	normalized := strings.ToLower(mac)
	for i := range m.Nodes {
		if strings.ToLower(m.Nodes[i].MAC) == normalized {
			return &m.Nodes[i], true
		}
	}
	return nil, false
}

// SaveToFile writes the manifest as YAML to the specified path.
func (m *Manifest) SaveToFile(path string) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return ErrManifestWrite{Path: path, Cause: err}
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return ErrManifestWrite{Path: path, Cause: err}
	}
	return nil
}

// LoadManifest reads a manifest from a YAML file.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrManifestNotFound{Path: path}
		}
		return nil, ErrManifestRead{Path: path, Cause: err}
	}
	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, ErrManifestParse{Path: path, Cause: err}
	}
	return &manifest, nil
}

// checkMediaSets verifies every entry can be served: a named set exists,
// or its architecture has a default. Caught at start, not when the node
// boots.
func (m *Manifest) checkMediaSets(sets, defaults map[string]MediaSet) error {
	for i := range m.Nodes {
		e := &m.Nodes[i]
		if e.MediaSet != "" {
			if _, ok := sets[e.MediaSet]; !ok {
				return ErrUnknownMediaSet{MAC: e.MAC, MediaSet: e.MediaSet}
			}
			continue
		}
		arch := e.Architecture
		if arch == "" {
			arch = ipxe.ArchitectureX86_64
		}
		if _, ok := defaults[arch]; !ok {
			return ErrUnknownMediaSet{MAC: e.MAC, Architecture: arch}
		}
	}
	return nil
}
