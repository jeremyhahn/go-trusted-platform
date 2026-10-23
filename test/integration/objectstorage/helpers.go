// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package objectstorage

import (
	"context"
	"os"
	"strings"
	"time"
)

// envPlatformCTL names the platformctl binary the CLI adapter runs.
const envPlatformCTL = "PLATFORMCTL_PATH"

// testBackend is the object store backend the scenario writes to: the local
// backend platformd configures (pkg/storage/quicbaas/config.go). The pinned
// go-quicbaas object store has no primary backend, so every put and copy names
// one (docs/objectstorage/api-reference.md#limits-of-the-pinned-sdk).
const testBackend = "default"

// platformCTLPath returns the platformctl binary under test.
func platformCTLPath() string {
	if v := os.Getenv(envPlatformCTL); v != "" {
		return v
	}
	return "platformctl"
}

// notConfiguredMarkers are the error texts of a platformd that does not serve
// object storage: UNAVAILABLE / SERVICE_NOT_CONFIGURED on every transport.
var notConfiguredMarkers = []string{
	"service_not_configured",
	"not configured",
	"unavailable",
	"503",
}

// invalidMarkers are the error texts of an INVALID_ARGUMENT refusal.
var invalidMarkers = []string{
	"invalid argument",
	"invalidargument",
	"invalid_argument",
	"400",
}

// IsNotConfigured reports whether err says platformd does not serve object storage.
func IsNotConfigured(err error) bool { return matches(err, notConfiguredMarkers) }

// IsInvalid reports whether err is an INVALID_ARGUMENT refusal.
func IsInvalid(err error) bool { return matches(err, invalidMarkers) }

func matches(err error, markers []string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range markers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// ShortContext bounds a single call of the scenario.
func ShortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
