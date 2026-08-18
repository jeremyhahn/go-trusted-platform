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

import "gopkg.in/yaml.v3"

// DeviceIdentity holds the network-level identity fields that can be inherited
// from the global PXE bootstrap configuration. These fields map to the
// corresponding fields in app.App without creating an import cycle.
type DeviceIdentity struct {
	Domain      string
	Hostmaster  string
	TenantID    string
	Environment string
	DNSFallback []string
}

// ApplyNetworkIdentity merges global network-level values into a device
// template's identity fields. Only fields that are empty or zero-valued in
// the target are set; existing template values always take precedence.
//
// Callers should create a DeviceIdentity from their app.App fields, call
// this function, then write the result back into the app.App.
func ApplyNetworkIdentity(global *PlatformGlobalConfig, target *DeviceIdentity) *DeviceIdentity {
	if global == nil || target == nil {
		return target
	}

	if target.Domain == "" {
		target.Domain = global.Domain
	}

	if target.Hostmaster == "" {
		target.Hostmaster = global.Hostmaster
	}

	if target.TenantID == "" {
		target.TenantID = global.TenantID
	}

	if target.Environment == "" {
		target.Environment = global.Environment
	}

	if len(target.DNSFallback) == 0 && len(global.UpstreamDNS) > 0 {
		target.DNSFallback = make([]string, len(global.UpstreamDNS))
		copy(target.DNSFallback, global.UpstreamDNS)
	}

	return target
}

// ApplyNodeIdentity overwrites the merged device-config map with the
// node's authoritative first-class fields. Unconditional overwrite —
// validation guarantees YAML-sourced overrides never carry these keys.
//
// Injected keys: os.hostname (from Hostname), bmc.address / bmc.username /
// bmc.password / bmc.protocol (from the BMC* fields, only when BMCAddress
// is set), and network.interfaces (from Interfaces, emitted with the
// installer.InterfaceConfig YAML tags). Submaps are created when absent; a
// non-map value under an injected key is a typed error rather than a
// silent clobber.
func ApplyNodeIdentity(m map[string]interface{}, node *NodeConfig) error {
	if m == nil {
		return ErrNilConfigMap{}
	}
	if node == nil {
		return nil
	}

	if node.Hostname != "" {
		osMap, err := ensureSubMap(m, "os", node.Hostname)
		if err != nil {
			return err
		}
		osMap["hostname"] = node.Hostname
	}

	if node.BMCAddress != "" {
		bmcMap, err := ensureSubMap(m, "bmc", node.Hostname)
		if err != nil {
			return err
		}
		bmcMap["address"] = node.BMCAddress
		if node.BMCUser != "" {
			bmcMap["username"] = node.BMCUser
		}
		if node.BMCPassword != "" {
			bmcMap["password"] = node.BMCPassword
		}
		if node.BMCProtocol != "" {
			bmcMap["protocol"] = node.BMCProtocol
		}
	}

	if len(node.Interfaces) > 0 {
		converted, err := interfacesToGeneric(node)
		if err != nil {
			return err
		}
		netMap, err := ensureSubMap(m, "network", node.Hostname)
		if err != nil {
			return err
		}
		netMap["interfaces"] = converted
	}

	return nil
}

// ensureSubMap returns m[key] as a map, creating it when absent or nil.
// A non-map value under key is a typed error — never silently clobbered.
func ensureSubMap(m map[string]interface{}, key, hostname string) (map[string]interface{}, error) {
	existing, ok := m[key]
	if !ok || existing == nil {
		sub := map[string]interface{}{}
		m[key] = sub
		return sub, nil
	}
	sub, isMap := existing.(map[string]interface{})
	if !isMap {
		return nil, ErrConfigKeyNotMap{Hostname: hostname, Key: key}
	}
	return sub, nil
}

// interfacesToGeneric round-trips the node's typed Interfaces through YAML
// so the emitted keys are exactly the installer.InterfaceConfig YAML tags
// and the result is the []interface{} of map[string]interface{} shape the
// deep-merge and JSON serialization paths expect.
func interfacesToGeneric(node *NodeConfig) ([]interface{}, error) {
	encoded, err := yaml.Marshal(node.Interfaces)
	if err != nil {
		return nil, ErrInterfaceConvertFailed{Hostname: node.Hostname, Cause: err}
	}
	var generic []interface{}
	if err := yaml.Unmarshal(encoded, &generic); err != nil {
		return nil, ErrInterfaceConvertFailed{Hostname: node.Hostname, Cause: err}
	}
	return generic, nil
}
