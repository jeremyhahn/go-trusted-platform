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

package app

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	quicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/stretchr/testify/assert"
)

// TestMirrorWebAuthnRelyingParty_AggregatesSameRPOrigins proves the
// primary listener's RP wins and the origins of every listener sharing its
// RP ID are aggregated, deduplicated, while a listener declaring a
// different RP ID contributes nothing (its ceremonies cannot work against
// the SDK's single-RP factory).
func TestMirrorWebAuthnRelyingParty_AggregatesSameRPOrigins(t *testing.T) {
	app := &App{
		Logger:         logging.DefaultLogger(),
		QuicBaaSConfig: &quicbaas.Config{},
		WebServices: []*v1.Config{
			{WebAuthn: &v1.WebAuthn{
				RPID:          "cp.trusted-platform.io",
				RPDisplayName: "Trusted Platform",
				RPOrigins:     []string{"https://cp.trusted-platform.io", "https://cp.trusted-platform.io:8443"},
			}},
			{WebAuthn: &v1.WebAuthn{
				RPID:      "cp.trusted-platform.io",
				RPOrigins: []string{"https://cp.trusted-platform.io:8443", "http://cp.trusted-platform.io:8080"},
			}},
			{WebAuthn: &v1.WebAuthn{
				RPID:      "cp.trusted-platform.internal",
				RPOrigins: []string{"https://cp.trusted-platform.internal"},
			}},
		},
	}
	app.mirrorWebAuthnRelyingParty()
	assert.Equal(t, "cp.trusted-platform.io", app.QuicBaaSConfig.WebAuthnRPID)
	assert.Equal(t, "Trusted Platform", app.QuicBaaSConfig.WebAuthnRPDisplayName)
	assert.Equal(t, []string{
		"https://cp.trusted-platform.io",
		"https://cp.trusted-platform.io:8443",
		"http://cp.trusted-platform.io:8080",
	}, app.QuicBaaSConfig.WebAuthnRPOrigins,
		"same-RP origins aggregated and deduplicated; the divergent-RP listener contributes nothing")
}

// TestMirrorWebAuthnRelyingParty_PluralOnlyConfigNotShadowedByDefault is
// the regression for the shipped deployment shape: DefaultConfig retains a
// singular WebServiceConfig whose WebAuthn is nil, while the real
// listeners arrive via the plural webservices: list. The mirror must skip
// the RP-less default and adopt the first plural listener's relying party.
func TestMirrorWebAuthnRelyingParty_PluralOnlyConfigNotShadowedByDefault(t *testing.T) {
	app := &App{
		Logger:           logging.DefaultLogger(),
		QuicBaaSConfig:   &quicbaas.Config{},
		WebServiceConfig: &v1.Config{}, // retained default: no WebAuthn
		WebServices: []*v1.Config{
			{WebAuthn: &v1.WebAuthn{
				RPID:          "cp.trusted-platform.io",
				RPDisplayName: "Trusted Platform",
				RPOrigins:     []string{"https://cp.trusted-platform.io:8443"},
			}},
		},
	}
	app.mirrorWebAuthnRelyingParty()
	assert.Equal(t, "cp.trusted-platform.io", app.QuicBaaSConfig.WebAuthnRPID,
		"a retained RP-less singular default must not shadow configured plural listeners")
	assert.Equal(t, []string{"https://cp.trusted-platform.io:8443"}, app.QuicBaaSConfig.WebAuthnRPOrigins)
}

// TestMirrorWebAuthnRelyingParty_NoWebAuthnConfigured proves the mirror is
// a no-op when no listener declares WebAuthn: nothing is invented and the
// SDK keeps its own defaults.
func TestMirrorWebAuthnRelyingParty_NoWebAuthnConfigured(t *testing.T) {
	app := &App{
		Logger:         logging.DefaultLogger(),
		QuicBaaSConfig: &quicbaas.Config{},
		WebServices:    []*v1.Config{{}},
	}
	app.mirrorWebAuthnRelyingParty()
	assert.Empty(t, app.QuicBaaSConfig.WebAuthnRPID)
	assert.Empty(t, app.QuicBaaSConfig.WebAuthnRPOrigins)
}
