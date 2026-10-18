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

//go:build integration

package provision

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Environment variable names for service endpoints, matching the values
// exported by build/docker/devcontainer/run-integration-tests.sh.
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
)

// envOrDefault returns the environment variable value or the default.
func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// grpcEndpoint returns the platformd gRPC TCP endpoint.
func grpcEndpoint() string { return envOrDefault(EnvPlatformGRPCEndpoint, "localhost:10443") }

// restEndpoint returns the platformd REST base URL.
func restEndpoint() string { return envOrDefault(EnvPlatformRESTEndpoint, "https://localhost:8443") }

// quicEndpoint returns the platformd QUIC endpoint.
func quicEndpoint() string { return envOrDefault(EnvPlatformQUICEndpoint, "localhost:9444") }

// mcpEndpoint returns the platformd MCP base URL (TLS 1.3 only, #844).
func mcpEndpoint() string { return envOrDefault(EnvPlatformMCPEndpoint, "https://localhost:9445") }

// unixSocket returns the platformd Unix socket path.
func unixSocket() string {
	return envOrDefault(EnvPlatformUnixSocket, "/tmp/platformd-integration/platformd.sock")
}

// platformctlPath returns the platformctl binary path.
func platformctlPath() string { return envOrDefault(EnvPlatformCTL, "platformctl") }

// uniqueCounter disambiguates identities generated within the same
// nanosecond across parallel adapters.
var uniqueCounter atomic.Uint64

// uniqueID generates a unique identifier for test resources (EK serials,
// unknown session IDs) so adapters never collide on the shared daemon.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), uniqueCounter.Add(1))
}

// containsAny reports whether the lower-cased error text contains any of
// the needles. Every transport preserves the typed configdelivery error
// text (REST envelope body, gRPC status message, QUIC error payload, MCP
// tool error, CLI stderr), so substring matching on the domain error
// strings is stable across protocols.
func containsAny(err error, needles ...string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range needles {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// isNotFound reports whether err corresponds to a not-found condition on
// any transport (gRPC NotFound, REST 404, QUIC StatusNotFound, MCP/CLI
// error text).
func isNotFound(err error) bool {
	return containsAny(err,
		"session not found",
		"profile not found",
		"not found",
		"notfound",
		"404",
	)
}

// isEABAuthError reports whether err corresponds to an EAB credential
// rejection (REST 401, gRPC Unauthenticated, QUIC StatusUnauthorized,
// MCP/CLI error text).
func isEABAuthError(err error) bool {
	return containsAny(err,
		"eab validation failed",
		"unauthenticated",
		"unauthorized",
		"401",
	)
}

// isInvalidArgument reports whether err corresponds to a request
// validation failure (REST 400, gRPC InvalidArgument, QUIC
// StatusInvalidArgument).
func isInvalidArgument(err error) bool {
	return containsAny(err,
		"invalid request",
		"is required",
		"invalidargument",
		"invalid argument",
		"400",
	)
}

// isNonceSpent reports whether err corresponds to a consumed or expired
// single-use nonce.
func isNonceSpent(err error) bool {
	return containsAny(err, "nonce expired or already used", "nonce expired")
}

// isAlreadyFulfilled reports whether err corresponds to fulfilling a
// session twice.
func isAlreadyFulfilled(err error) bool {
	return containsAny(err, "already fulfilled")
}

// isProfileMissing reports whether err corresponds to polling a session
// that was fulfilled without a resolved profile (typed
// configdelivery.ErrSessionProfileMissing; REST 500, gRPC Internal, QUIC
// StatusInternalError -- the error text is preserved on every transport).
func isProfileMissing(err error) bool {
	return containsAny(err, "fulfilled without a resolved profile")
}

// isEKBindingRejected reports whether err corresponds to the EK-certificate
// binding rejection for a matched profile (typed configdelivery
// ErrEKCertRequired / ErrEKCertMismatch; REST 403, gRPC PermissionDenied,
// QUIC StatusForbidden — the error text is preserved on every transport).
func isEKBindingRejected(err error) bool {
	return containsAny(err,
		"ek certificate required",
		"ek certificate public key mismatch",
	)
}

// isSignerUnavailable reports whether err corresponds to the control plane
// having no Secure Boot DB key signer wired (typed configdelivery
// ErrSignerUnavailable; REST 503, gRPC Unavailable).
func isSignerUnavailable(err error) bool {
	return containsAny(err,
		"remote signing is unavailable",
		"no db key signer",
	)
}

// uniqueMAC generates a unique locally-administered MAC address for
// MAC-only device-identity tests so adapters never collide on the shared
// daemon.
func uniqueMAC() string {
	n := uniqueCounter.Add(1)
	now := uint64(time.Now().UnixNano())
	return fmt.Sprintf("aa:bb:%02x:%02x:%02x:%02x",
		byte(now>>16), byte(now>>8), byte(now), byte(n))
}
