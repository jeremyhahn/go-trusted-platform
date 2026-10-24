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
	"github.com/stretchr/testify/require"
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
				RPID:          "cp.example.com",
				RPDisplayName: "Trusted Platform",
				RPOrigins:     []string{"https://cp.example.com", "https://cp.example.com:8443"},
			}},
			{WebAuthn: &v1.WebAuthn{
				RPID:      "cp.example.com",
				RPOrigins: []string{"https://cp.example.com:8443", "http://cp.example.com:8080"},
			}},
			{WebAuthn: &v1.WebAuthn{
				RPID:      "cp.example.internal",
				RPOrigins: []string{"https://cp.example.internal"},
			}},
		},
	}
	app.mirrorWebAuthnRelyingParty()
	assert.Equal(t, "cp.example.com", app.QuicBaaSConfig.WebAuthnRPID)
	assert.Equal(t, "Trusted Platform", app.QuicBaaSConfig.WebAuthnRPDisplayName)
	assert.Equal(t, []string{
		"https://cp.example.com",
		"https://cp.example.com:8443",
		"http://cp.example.com:8080",
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
				RPID:          "cp.example.com",
				RPDisplayName: "Trusted Platform",
				RPOrigins:     []string{"https://cp.example.com:8443"},
			}},
		},
	}
	app.mirrorWebAuthnRelyingParty()
	assert.Equal(t, "cp.example.com", app.QuicBaaSConfig.WebAuthnRPID,
		"a retained RP-less singular default must not shadow configured plural listeners")
	assert.Equal(t, []string{"https://cp.example.com:8443"}, app.QuicBaaSConfig.WebAuthnRPOrigins)
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

// TestMirrorWebAuthnRelyingParty_CopiesAssurance proves the primary
// listener's attestation policy is mirrored into the embedded SDK config.
func TestMirrorWebAuthnRelyingParty_CopiesAssurance(t *testing.T) {
	app := &App{
		Logger:         logging.DefaultLogger(),
		QuicBaaSConfig: &quicbaas.Config{},
		WebServices: []*v1.Config{
			{WebAuthn: &v1.WebAuthn{
				RPID:      "cp.example.com",
				RPOrigins: []string{"https://cp.example.com:8443"},
				Assurance: "insecure-allow-software-administrators",
			}},
		},
	}
	app.mirrorWebAuthnRelyingParty()
	assert.Equal(t, "insecure-allow-software-administrators", app.QuicBaaSConfig.WebAuthnAssurance)
}

// TestMirrorWebAuthnRelyingParty_EmptyAssuranceStaysEmpty proves an unset
// policy is not replaced by any platform value, so the embedded IAM keeps
// its "hardware" default.
func TestMirrorWebAuthnRelyingParty_EmptyAssuranceStaysEmpty(t *testing.T) {
	app := &App{
		Logger:         logging.DefaultLogger(),
		QuicBaaSConfig: &quicbaas.Config{},
		WebServices: []*v1.Config{
			{WebAuthn: &v1.WebAuthn{
				RPID:      "cp.example.com",
				RPOrigins: []string{"https://cp.example.com:8443"},
			}},
		},
	}
	app.mirrorWebAuthnRelyingParty()
	require.Equal(t, "cp.example.com", app.QuicBaaSConfig.WebAuthnRPID)
	assert.Empty(t, app.QuicBaaSConfig.WebAuthnAssurance)
}
