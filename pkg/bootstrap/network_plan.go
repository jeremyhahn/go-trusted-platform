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
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
)

// ErrSwitchPortClass is returned when a switch port assignment names a port
// class the network plan cannot realise: an unknown class, or a class that
// carries no zone of the environment.
type ErrSwitchPortClass struct {
	// Port is the switch port of the assignment.
	Port string
	// Class is the class it names.
	Class zone.PortClass
	// Cause is the plan's error.
	Cause error
}

// Error implements the error interface.
func (e ErrSwitchPortClass) Error() string {
	return fmt.Sprintf("bootstrap: switch port %q: class %q: %v", e.Port, e.Class, e.Cause)
}

// Unwrap returns the plan's error.
func (e ErrSwitchPortClass) Unwrap() error { return e.Cause }

// ErrRetiredKey is returned when bootstrap.yaml still carries a key the
// reference-network schema retired. Those keys held literal VLAN and subnet
// numbers; a lax parser would silently ignore them, so they are refused.
type ErrRetiredKey struct {
	// Path is the bootstrap.yaml path.
	Path string
	// Key is the retired key, as a dotted path.
	Key string
	// Line is its line in the file.
	Line int
	// Use names what replaces it.
	Use string
}

// Error implements the error interface.
func (e ErrRetiredKey) Error() string {
	return fmt.Sprintf("bootstrap: %s:%d: %q is retired; use %s", e.Path, e.Line, e.Key, e.Use)
}

// NetworkPlan derives the deployment's network plan from Environment and
// Zones: the zone set is resolved and validated, then numbered by netplan.
// Environment is required.
func (c *BootstrapConfig) NetworkPlan() (*netplan.Plan, error) {
	if c.Environment == nil {
		return nil, ErrMissingRequiredField{Field: "environment"}
	}
	zones, err := zone.Resolve(c.Zones)
	if err != nil {
		return nil, err
	}
	if err := zone.Validate(zones); err != nil {
		return nil, err
	}
	plan, err := netplan.New(*c.Environment, zones)
	if err != nil {
		return nil, err
	}
	if c.Switch != nil {
		for _, pa := range c.Switch.PortAssignments {
			if pa.Port == "" {
				return nil, ErrMissingRequiredField{Field: "switch.port_assignments[].port"}
			}
			if _, err := plan.PortClass(pa.Class); err != nil {
				return nil, ErrSwitchPortClass{Port: pa.Port, Class: pa.Class, Cause: err}
			}
		}
	}
	return plan, nil
}

// buildSwitchConfig converts the bootstrap SwitchConfig to a switchmgmt.Config
// on the network plan: one VLAN per zone (named after the zone, with its
// IPv4 subnet), and every assigned port programmed with its class's mode,
// allowed VLANs, native VLAN and MTU.
func buildSwitchConfig(sc *SwitchConfig, plan *netplan.Plan) (*switchmgmt.Config, error) {
	zones := plan.Zones()
	vlans := make([]switchmgmt.VLANConfig, 0, len(zones))
	for _, z := range zones {
		vlans = append(vlans, switchmgmt.VLANConfig{
			ID:     int(z.VLAN),
			Name:   string(z.Zone),
			Subnet: z.Subnet4.String(),
		})
	}
	slices.SortFunc(vlans, func(a, b switchmgmt.VLANConfig) int { return a.ID - b.ID })

	ports := make([]switchmgmt.PortConfig, 0, len(sc.PortAssignments))
	for _, pa := range sc.PortAssignments {
		pc, err := plan.PortClass(pa.Class)
		if err != nil {
			return nil, ErrSwitchPortClass{Port: pa.Port, Class: pa.Class, Cause: err}
		}
		port := switchmgmt.PortConfig{
			Port:        pa.Port,
			Mode:        string(pc.Mode),
			MTU:         pc.MTU,
			Description: pa.Description,
		}
		if pc.Mode == netplan.PortModeAccess {
			port.AccessVLAN = int(pc.Native)
		} else {
			port.VLANs = toInts(pc.Allowed)
			port.NativeVLAN = int(pc.Native)
		}
		ports = append(ports, port)
	}

	return &switchmgmt.Config{
		Vendor:         switchmgmt.SwitchVendor(sc.Vendor),
		Host:           sc.Host,
		User:           sc.User,
		SSHKey:         sc.SSHKey,
		KnownHostsPath: sc.KnownHostsPath,
		VLANs:          vlans,
		Ports:          ports,
	}, nil
}

// toInts widens VLAN IDs for the switchmgmt schema.
func toInts(vlans []uint16) []int {
	out := make([]int, len(vlans))
	for i, v := range vlans {
		out[i] = int(v)
	}
	return out
}

// retiredKeys lists the bootstrap.yaml keys the reference-network schema
// retired, as paths from the document root ("*" matches every sequence
// item), with what replaces each.
var retiredKeys = []struct {
	path []string
	use  string
}{
	{[]string{"subnets"}, "environment (numbering is derived by netplan)"},
	{[]string{"fabric"}, "switch.port_assignments with port classes"},
	{[]string{"platform", "networks"}, "environment"},
	{[]string{"switch", "vlans"}, "environment (the switch carries every zone VLAN)"},
	{[]string{"switch", "port_assignments", "*", "mode"}, "switch.port_assignments[].class"},
	{[]string{"switch", "port_assignments", "*", "vlans"}, "switch.port_assignments[].class"},
	{[]string{"nodes", "*", "post_enrollment"}, "the port class (a hypervisor trunk's native VLAN is provisioning)"},
}

// checkRetiredKeys refuses any retired key present in the parsed document.
func checkRetiredKeys(doc *yaml.Node, path string) error {
	root := resolveYAMLNode(doc)
	for _, rk := range retiredKeys {
		if key, line, ok := findYAMLPath(root, rk.path, ""); ok {
			return ErrRetiredKey{Path: path, Key: key, Line: line, Use: rk.use}
		}
	}
	return nil
}

// findYAMLPath reports whether the key path exists under node, returning
// the dotted key it matched and that key's line.
func findYAMLPath(node *yaml.Node, path []string, prefix string) (string, int, bool) {
	node = resolveYAMLNode(node)
	if node == nil || len(path) == 0 {
		return "", 0, false
	}
	if path[0] == "*" {
		if node.Kind != yaml.SequenceNode {
			return "", 0, false
		}
		for i, item := range node.Content {
			if key, line, ok := findYAMLPath(item, path[1:], fmt.Sprintf("%s[%d]", prefix, i)); ok {
				return key, line, true
			}
		}
		return "", 0, false
	}
	keyNode, val := yamlMappingEntry(node, path[0])
	if keyNode == nil {
		return "", 0, false
	}
	key := path[0]
	if prefix != "" {
		key = prefix + "." + path[0]
	}
	if len(path) == 1 {
		return key, keyNode.Line, true
	}
	return findYAMLPath(val, path[1:], key)
}
