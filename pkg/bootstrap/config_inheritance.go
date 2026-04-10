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
