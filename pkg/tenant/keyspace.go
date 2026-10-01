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

package tenant

import (
	"errors"
	"fmt"
	"strings"
)

// Package tenant / keyspace.go defines the canonical key-path convention used
// when platform resources are stored in the parameter store (non-secret) and
// secret store (encrypted, ACL-gated). Every component that reads or writes a
// tenant-scoped resource MUST use these helpers so that:
//
//   - The future Node / Network / Cluster view can aggregate everything
//     related to a single entity via a single prefix query, e.g.
//     "tenants/{tenant}/nodes/{node}/**"
//   - ACLs and audit policies can be expressed as prefix rules instead of
//     having to enumerate every key each component invents ad-hoc.
//   - Backups, restores, and disaster recovery can reason about "all of
//     tenant X" as a single prefix.
//
// The layout is intentionally two-dimensional: the first axis is the
// RESOURCE KIND (nodes, networks, clusters, ca), the second axis is WHETHER
// THE VALUE IS A SECRET (params vs secrets). A component that needs to
// publish both non-secret metadata and a secret for the same resource writes
// to two paths under the same {kind}/{id} prefix.
//
// Example full paths:
//
//	tenants/acme/nodes/node-02/params/hostname                  → "node-02.acme.local"
//	tenants/acme/nodes/node-02/params/role                      → "control-plane"
//	tenants/acme/nodes/node-02/params/bmc/host                  → "10.4.2.103"
//	tenants/acme/nodes/node-02/secrets/bmc/password             → (encrypted)
//	tenants/acme/nodes/node-02/secrets/luks/recovery            → (encrypted, escrow only)
//	tenants/acme/nodes/node-02/params/firstboot/escrowed_at     → "2026-04-07T18:14:21Z"
//	tenants/acme/networks/mgmt/params/cidr                      → "10.4.2.0/24"
//	tenants/acme/clusters/prod/secrets/join_token               → (encrypted)
//	tenants/acme/ca/params/root_fingerprint                     → "sha256:..."
//
// NOTE: These helpers deal ONLY in path composition. They have no awareness
// of which backing store (parameter vs secret) a given path routes to — that
// routing decision is made by the caller based on whether the last segment
// lives under "params/" or "secrets/". Keeping the two concerns separate
// means a single aggregation query can span both.

// Root is the top-level prefix under which every tenant-scoped key is stored.
const Root = "tenants"

// Resource kinds.
const (
	KindNodes    = "nodes"
	KindNetworks = "networks"
	KindClusters = "clusters"
	KindCA       = "ca"
)

// Category suffixes. A tenant resource's keys live under either params/ (non
// secret, signed at rest) or secrets/ (encrypted, ACL gated).
const (
	CategoryParams  = "params"
	CategorySecrets = "secrets"
)

// Well known leaf paths. Components that read or write these MUST reference
// them by constant so the path convention stays consistent across packages.
//
// Node leaves:
const (
	// Non-secret node params.
	NodeParamHostname             = "hostname"
	NodeParamRole                 = "role"
	NodeParamHardwareVendor       = "hardware/vendor"
	NodeParamHardwareModel        = "hardware/model"
	NodeParamHardwareSerial       = "hardware/serial"
	NodeParamNetworkMgmtMAC       = "network/mgmt/mac"
	NodeParamNetworkMgmtIP        = "network/mgmt/ip"
	NodeParamNetworkMgmtGateway   = "network/mgmt/gateway"
	NodeParamBMCHost              = "bmc/host"
	NodeParamBMCProtocol          = "bmc/protocol"
	NodeParamBMCUser              = "bmc/user"
	NodeParamTPMEKCertFingerprint = "tpm/ek_cert_fingerprint"
	NodeParamTPMAKCertFingerprint = "tpm/ak_cert_fingerprint"
	NodeParamProvisionedAt        = "provisioned_at"
	NodeParamLastSeen             = "last_seen"
	NodeParamFirstbootEscrowedAt  = "firstboot/escrowed_at"

	// Secrets.
	NodeSecretBMCPassword  = "bmc/password"
	NodeSecretLUKSRecovery = "luks/recovery"
	NodeSecretRootPassword = "root/password"
	NodeSecretSSHHostKey   = "ssh/host_ed25519_key"
	NodeSecretTPMSRKAuth   = "tpm/srk_auth"
)

// ErrInvalidID is returned by the key helpers when an id segment contains
// characters that would corrupt a path (slash, empty, control chars).
var ErrInvalidID = errors.New("tenant: invalid id segment")

// TenantPath returns "tenants/{tenant}".
func TenantPath(tenant string) (string, error) {
	if err := validateID(tenant); err != nil {
		return "", err
	}
	return Root + "/" + tenant, nil
}

// ResourcePath returns "tenants/{tenant}/{kind}/{id}".
func ResourcePath(tenant, kind, id string) (string, error) {
	if err := validateID(tenant); err != nil {
		return "", &WrappedError{Msg: "tenant", Err: err}
	}
	if err := validateKind(kind); err != nil {
		return "", err
	}
	if err := validateID(id); err != nil {
		return "", &WrappedError{Msg: "id", Err: err}
	}
	return Root + "/" + tenant + "/" + kind + "/" + id, nil
}

// ParamPath returns "tenants/{tenant}/{kind}/{id}/params/{leaf}".
func ParamPath(tenant, kind, id, leaf string) (string, error) {
	base, err := ResourcePath(tenant, kind, id)
	if err != nil {
		return "", err
	}
	if leaf == "" {
		return base + "/" + CategoryParams, nil
	}
	return base + "/" + CategoryParams + "/" + leaf, nil
}

// SecretPath returns "tenants/{tenant}/{kind}/{id}/secrets/{leaf}".
func SecretPath(tenant, kind, id, leaf string) (string, error) {
	base, err := ResourcePath(tenant, kind, id)
	if err != nil {
		return "", err
	}
	if leaf == "" {
		return base + "/" + CategorySecrets, nil
	}
	return base + "/" + CategorySecrets + "/" + leaf, nil
}

// NodeParam is a convenience for ParamPath(tenant, KindNodes, node, leaf).
func NodeParam(tenant, node, leaf string) (string, error) {
	return ParamPath(tenant, KindNodes, node, leaf)
}

// NodeSecret is a convenience for SecretPath(tenant, KindNodes, node, leaf).
func NodeSecret(tenant, node, leaf string) (string, error) {
	return SecretPath(tenant, KindNodes, node, leaf)
}

// NodePrefix returns the aggregation prefix for a single node, suitable for
// a "give me everything about this node" query by the Node view.
func NodePrefix(tenant, node string) (string, error) {
	return ResourcePath(tenant, KindNodes, node)
}

func validateID(id string) error {
	if id == "" {
		return ErrInvalidID
	}
	if strings.ContainsAny(id, "/ \t\r\n") {
		return ErrInvalidID
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return ErrInvalidID
		}
	}
	return nil
}

func validateKind(kind string) error {
	switch kind {
	case KindNodes, KindNetworks, KindClusters, KindCA:
		return nil
	default:
		return &MessageError{Msg: fmt.Sprintf("tenant: unknown resource kind %q", kind)}
	}
}
