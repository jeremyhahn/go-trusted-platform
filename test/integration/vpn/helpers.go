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

package vpn

import (
	"context"
	"os"
	"strings"
	"time"
)

// envPlatformCTL names the platformctl binary the CLI adapter runs. Kept in
// sync with build/docker/devcontainer/run-integration-tests.sh.
const envPlatformCTL = "PLATFORMCTL_PATH"

// platformCTLPath resolves the platformctl binary, defaulting to $PATH.
func platformCTLPath() string {
	if v := os.Getenv(envPlatformCTL); v != "" {
		return v
	}
	return "platformctl"
}

// notConfiguredMarkers are the substrings every transport surfaces when the
// devcontainer's platformd has no vpn control plane. The suite treats that as
// a valid contract outcome only when every operation reports it — a node that
// fails closed on some calls and answers others is a regression.
var notConfiguredMarkers = []string{
	"vpn control plane is not configured",
	"service not available: vpn",
	"quic service unavailable: vpn",
	"unavailable",
	"503",
}

// notFoundMarkers are the substrings every transport surfaces for an unknown
// peer or posture policy.
var notFoundMarkers = []string{
	"is not an enrolled peer",
	"has no posture policy",
	"not found",
	"notfound",
	"404",
}

// invalidMarkers are the substrings every transport surfaces when a posture
// module does not compile.
var invalidMarkers = []string{
	"is invalid",
	"invalid argument",
	"invalidargument",
	"400",
}

// IsNotConfigured reports whether err is the "no vpn control plane" surface.
func IsNotConfigured(err error) bool { return matches(err, notConfiguredMarkers) }

// IsNotFound reports whether err is the unknown-peer or unknown-policy surface.
func IsNotFound(err error) bool { return matches(err, notFoundMarkers) }

// IsInvalid reports whether err is the invalid-posture-module surface.
func IsInvalid(err error) bool { return matches(err, invalidMarkers) }

// matches reports whether err's message contains any of markers.
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

// ShortContext derives a bounded per-call context.
func ShortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}

// testPostureModule is a posture module that compiles: it admits only peers
// reporting agent version 9.9.9.
const testPostureModule = `package vpn.posture

import rego.v1

default allow := false

allow if input.posture.agent_version == "9.9.9"
`

// brokenPostureModule does not compile, so every transport must refuse it.
const brokenPostureModule = `package vpn.posture

allow if {
`
