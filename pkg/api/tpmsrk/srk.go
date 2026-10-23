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

// Package tpmsrk contains the single, transport-level dispatch from a
// requested SRK persistent handle to the platform key it names, shared
// by every daemon transport (gRPC, REST, QUIC, MCP).
//
// The platform defines two storage root keys and they are different
// keys, not two names for one: the storage-hierarchy SSRK and the
// platform-hierarchy PlatformSRK, which parents the Platform KeyStore.
// A caller names one by its persistent handle.
//
// Keeping the dispatch here guarantees every protocol resolves a handle
// identically, including the case that matters most: a handle naming
// neither key is an error. A transport that instead falls through to
// the SSRK does not degrade gracefully — it returns the WRONG KEY and
// reports success, which is worse than failing, because the caller has
// no way to notice. That is what issue #475 recorded, and this package
// is the fix.
package tpmsrk

import (
	"fmt"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// The persistent handles the platform dispatches on. These are the wire
// constants a caller names, not the handles the keys necessarily occupy:
// a deployment may point tpm.platform-srk.srk-handle elsewhere, and the
// resolved attributes then carry that configured handle. So a caller
// must never assume the handle it asked for is the handle it got — see
// the note on Resolve.
const (
	// SSRKHandle names the storage-hierarchy Storage Root Key.
	SSRKHandle uint32 = 0x81000001
	// PlatformSRKHandle names the platform-hierarchy SRK that parents
	// the Platform KeyStore.
	PlatformSRKHandle uint32 = 0x81000002
	// DefaultHandle is the "unspecified" request. It resolves to the
	// SSRK, which is what a caller that names no handle has always got.
	DefaultHandle uint32 = 0
)

// ErrUnknownHandle is returned when a caller names a handle that is
// neither platform SRK. Every transport maps it to its own not-found
// status rather than answering with a key the caller did not ask for.
type ErrUnknownHandle struct {
	Requested uint32
}

func (e ErrUnknownHandle) Error() string {
	return fmt.Sprintf(
		"unknown SRK handle 0x%08x (supported: 0x%08x SSRK, 0x%08x PlatformSRK)",
		e.Requested, SSRKHandle, PlatformSRKHandle)
}

// ErrTPMUnavailable is returned when no TPM service is wired.
type ErrTPMUnavailable struct{}

func (e ErrTPMUnavailable) Error() string { return "TPM service not available" }

// resolver is the dispatch table: requested handle to the accessor that
// answers it. Map-based so adding a third platform key is a table entry
// rather than another arm every transport has to grow.
var resolvers = map[uint32]func(xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error){
	DefaultHandle: func(t xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error) { return t.SSRKAttributes() },
	SSRKHandle:    func(t xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error) { return t.SSRKAttributes() },
	PlatformSRKHandle: func(t xkmssdk.TrustedPlatformModule) (*xkmssdk.KeyAttributes, error) {
		return t.PlatformSRKAttributes()
	},
}

// Info property keys under which the daemon publishes the SRK handles it
// is configured with, so a client probes the real handle instead of
// assuming the default. The client SDK owns the key names.
const (
	PropertyPlatformSRKHandle = tpmsvc.InfoPropertyPlatformSRKHandle
	PropertySSRKHandle        = tpmsvc.InfoPropertySSRKHandle
)

// ConfiguredPlatformHandle returns the Platform KeyStore SRK handle the TPM
// is configured with (tpm.platform-srk.handle), or PlatformSRKHandle when
// the config is absent or leaves it unset.
func ConfiguredPlatformHandle(tpm xkmssdk.TrustedPlatformModule) uint32 {
	if cfg := tpm.Config(); cfg != nil && cfg.PlatformSRK != nil && cfg.PlatformSRK.SRKHandle != 0 {
		return uint32(cfg.PlatformSRK.SRKHandle)
	}
	return PlatformSRKHandle
}

// ConfiguredSSRKHandle returns the storage-hierarchy SRK handle the TPM is
// configured with (tpm.ssrk.handle), or SSRKHandle when the config is
// absent or leaves it unset.
func ConfiguredSSRKHandle(tpm xkmssdk.TrustedPlatformModule) uint32 {
	if cfg := tpm.Config(); cfg != nil && cfg.SSRK != nil && cfg.SSRK.Handle != 0 {
		return uint32(cfg.SSRK.Handle)
	}
	return SSRKHandle
}

// InfoProperties returns the SRK handles the TPM is configured with, as
// 0x%08X strings keyed by PropertyPlatformSRKHandle and PropertySSRKHandle.
// Every transport's Info response publishes this map so they agree.
func InfoProperties(tpm xkmssdk.TrustedPlatformModule) map[string]string {
	return map[string]string{
		PropertyPlatformSRKHandle: fmt.Sprintf("0x%08X", ConfiguredPlatformHandle(tpm)),
		PropertySSRKHandle:        fmt.Sprintf("0x%08X", ConfiguredSSRKHandle(tpm)),
	}
}

// Resolve returns the attributes of the SRK the caller named.
//
// handle 0 and SSRKHandle resolve to the SSRK; PlatformSRKHandle
// resolves to the PlatformSRK; the configured PlatformSRK and SSRK handles
// (see InfoProperties) resolve to their keys; anything else is
// ErrUnknownHandle. A nil TPM is ErrTPMUnavailable.
//
// The returned attributes carry the handle the key actually occupies,
// which is the deployment's configured value and need not equal the one
// requested. Callers that want to know whether a transport honoured the
// request must compare against a different key's answer, not against
// what they asked for.
func Resolve(tpm xkmssdk.TrustedPlatformModule, handle uint32) (*xkmssdk.KeyAttributes, error) {
	if tpm == nil {
		return nil, ErrTPMUnavailable{}
	}
	if resolve, ok := resolvers[handle]; ok {
		return resolve(tpm)
	}
	if handle == ConfiguredPlatformHandle(tpm) {
		return resolvers[PlatformSRKHandle](tpm)
	}
	if handle == ConfiguredSSRKHandle(tpm) {
		return resolvers[SSRKHandle](tpm)
	}
	return nil, ErrUnknownHandle{Requested: handle}
}

// IsUnknownHandle reports whether err is an ErrUnknownHandle, so a
// transport can pick its not-found status without a type switch at
// every call site.
func IsUnknownHandle(err error) bool {
	_, ok := err.(ErrUnknownHandle)
	return ok
}
