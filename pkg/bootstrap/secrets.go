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

// Package bootstrap provides secret-URI scheme constants and path utilities
// used during platform bootstrap. Secret resolution and config walking are
// delegated to the unified qrdb-SDK ResolverRegistry / ConfigProcessor.
package bootstrap

import "strings"

// URI scheme prefixes for secret resolution.
const (
	SchemeKMS        = "kms://"
	SchemeRemoteKMS  = "remote-kms://"
	SchemeEnv        = "env://"
	SchemeIDevID     = "idevid://"
	SchemeFile       = "file://"
	SchemeDynamic    = "dynamic://"
	SchemeXKMS       = "xkms://"
	SchemeCredential = "credential://"
	SchemeAutoGen    = "autogen://"
)

// Strategy constants for tracking how secrets were resolved.
const (
	StrategyKMS       = "kms"
	StrategyRemoteKMS = "remote-kms"
	StrategyEnv       = "env"
	StrategyIDevID    = "idevid"
	StrategyFile      = "file"
	StrategyDynamic   = "dynamic"
	StrategyXKMS      = "xkms"
	StrategyLiteral   = "literal"
	StrategyPlainText = "plaintext"
)

// SecretStructTag is the struct tag key used to mark fields as secrets.
const SecretStructTag = "secret"

// IsSecretURI returns true if the string appears to be a secret URI handled
// by one of the schemes the platform resolves: its own, and credential:// and
// autogen://, which the go-quicbaas registry resolves.
func IsSecretURI(s string) bool {
	return strings.HasPrefix(s, SchemeKMS) ||
		strings.HasPrefix(s, SchemeRemoteKMS) ||
		strings.HasPrefix(s, SchemeEnv) ||
		strings.HasPrefix(s, SchemeIDevID) ||
		strings.HasPrefix(s, SchemeFile) ||
		strings.HasPrefix(s, SchemeDynamic) ||
		strings.HasPrefix(s, SchemeXKMS) ||
		strings.HasPrefix(s, SchemeCredential) ||
		strings.HasPrefix(s, SchemeAutoGen)
}

// ExpandShortKMSPath expands a short KMS path that does not start with
// "tenants/" into a fully-qualified keyspace path by prepending
// tenants/{tenantID}/nodes/{nodeID}/secrets/. This allows config files
// to use compact URIs like kms://bmc/password while the resolver maps
// them to the full multi-tenant keyspace.
//
// If the path already starts with "tenants/", it is returned unchanged.
// If tenantID or nodeID is empty, the path is returned unchanged to
// avoid producing malformed paths.
func ExpandShortKMSPath(path, tenantID, nodeID string) string {
	if strings.HasPrefix(path, "tenants/") {
		return path
	}
	if tenantID == "" || nodeID == "" {
		return path
	}
	return "tenants/" + tenantID + "/nodes/" + nodeID + "/secrets/" + path
}
