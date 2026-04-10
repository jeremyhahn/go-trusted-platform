// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"context"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// Target bundles the minimum information a backend needs to contact a
// BMC. It is decoupled from [bmc.Config] so that callers may supply
// credentials out of band (for example from a secret store).
type Target struct {
	Address  string
	Port     int
	Username string
	Password string
	// Manufacturer may be left empty; when blank the dispatcher queries
	// the supplied [bmc.Client] via GetSystemInfo.
	Manufacturer string
	// Platform is an optional human-readable board/product identifier
	// (e.g. "X10SDV-TP8F", "PowerEdge R640", "ProLiant DL380 Gen11").
	// Vendor backends use it to enrich error messages and logs; leave
	// blank when unknown.
	Platform string
}

// ProviderFactory builds an [AttestationProvider] for a specific
// [Target]. Vendor subpackages register a factory in their init().
type ProviderFactory func(ctx context.Context, tgt Target) (AttestationProvider, error)

var (
	registryMu sync.RWMutex
	registry   = map[Vendor]ProviderFactory{}
)

// Register installs a [ProviderFactory] for the given [Vendor]. It is
// safe for concurrent use and panics only when called with a nil
// factory. Vendor subpackages invoke Register from init().
func Register(vendor Vendor, factory ProviderFactory) {
	if factory == nil {
		panic("bmc attestation: Register called with nil factory")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[vendor] = factory
}

// lookup returns the factory for a vendor, if any.
func lookup(vendor Vendor) (ProviderFactory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[vendor]
	return f, ok
}

// NewProvider constructs a vendor-appropriate [AttestationProvider]
// using the registered factories. When tgt.Manufacturer is empty the
// dispatcher queries client.GetSystemInfo to detect the vendor.
//
// Callers must blank-import the vendor subpackages they wish to
// support, for example:
//
//	import _ "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation/supermicro"
func NewProvider(ctx context.Context, client bmc.Client, tgt Target) (AttestationProvider, error) {
	manufacturer := tgt.Manufacturer
	if manufacturer == "" {
		if client == nil {
			return nil, ErrUnsupportedVendor{}
		}
		info, err := client.GetSystemInfo(ctx)
		if err != nil {
			return nil, ErrAttestationFailed{
				Action: ActionGetInfo,
				Reason: "vendor detection via GetSystemInfo failed",
				Cause:  err,
			}
		}
		if info != nil {
			manufacturer = info.Manufacturer
		}
	}

	vendor := DetectVendor(manufacturer)
	if vendor == VendorUnknown {
		return nil, ErrUnsupportedVendor{Manufacturer: manufacturer}
	}
	factory, ok := lookup(vendor)
	if !ok {
		return nil, ErrUnsupportedVendor{Manufacturer: manufacturer}
	}
	return factory(ctx, tgt)
}

// DetectVendor normalizes a free-form manufacturer string into a
// [Vendor] constant. Matching is case-insensitive and ignores
// surrounding whitespace.
func DetectVendor(manufacturer string) Vendor {
	m := strings.ToLower(strings.TrimSpace(manufacturer))
	switch {
	case m == "":
		return VendorUnknown
	case strings.Contains(m, "supermicro"), strings.Contains(m, "super micro"):
		return VendorSupermicro
	case strings.Contains(m, "dell"):
		return VendorDell
	case strings.Contains(m, "hpe"), strings.Contains(m, "hewlett"), strings.HasPrefix(m, "hp "):
		return VendorHPE
	default:
		return VendorUnknown
	}
}
