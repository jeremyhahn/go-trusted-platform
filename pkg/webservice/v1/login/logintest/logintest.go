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

// Package logintest builds unified-login fixtures for tests.
//
// It exists because a completed ceremony's response cannot be written as a
// composite literal from inside this repository. quicbaas's
// FinishLoginResponse promotes Bearer, ExpiresAt and Identity from an
// EMBEDDED POINTER to a go-qrdb transport type that the quicbaas SDK does
// not re-export, and naming go-qrdb directly fails the layer guard
// (pkg/arch/layerguard_test.go scans _test.go files too). Unmarshalling
// JSON allocates the embedded struct and sets the promoted fields without
// the platform naming the upstream package.
//
// The construction lives here, once, rather than in each test package that
// needs a login fixture. Closing the underlying gap is tracked as
// jeremyhahn/go-quicbaas#857.
package logintest

import (
	"encoding/json"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// Identity describes the principal a ceremony resolved. It mirrors the
// promoted identity's shape so a test can state one without naming the
// upstream package.
type Identity struct {
	// Subject identifies the authenticated principal.
	Subject string `json:"subject"`

	// TenantID is the tenant scope the principal authenticated into.
	TenantID string `json:"tenantID"`

	// Roles are the role names the backbone resolved for the principal.
	Roles []string `json:"roles,omitempty"`
}

// FinishResponse builds the response a completed ceremony returns.
//
// An empty bearer is legal and useful: it is how a test drives the
// fail-closed path where an error-free ceremony authenticated nobody. A
// nil identity is legal for the same reason — it drives the path where the
// ceremony issued a bearer without naming who for.
func FinishResponse(
	bearer, refreshToken string,
	expiresAt, refreshExpiresAt time.Time,
	identity *Identity) (*quicbaas.FinishLoginResponse, error) {

	payload := map[string]any{
		"bearer":           bearer,
		"expiresAt":        expiresAt,
		"refreshToken":     refreshToken,
		"refreshExpiresAt": refreshExpiresAt,
	}
	if identity != nil {
		payload["identity"] = identity
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	response := &quicbaas.FinishLoginResponse{}
	if err := json.Unmarshal(encoded, response); err != nil {
		return nil, err
	}
	return response, nil
}

// AuthenticatedIdentity is the principal a successful platform login
// resolves: an operator in the platform's operating tenant. Tests that are
// not about the identity itself use it so they all state the same one.
func AuthenticatedIdentity() *Identity {
	return &Identity{
		Subject:  "operator@platform",
		TenantID: "tenant-a",
		Roles:    []string{"admin"},
	}
}
