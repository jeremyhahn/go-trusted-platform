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

// Package gate is the SDK client for platformd's pre-unseal surface: the
// plain-HTTP mux that serves /healthz, /init and /unseal before the barrier
// is unsealed, when none of the six SDK transports is bound yet.
//
// The mux listens only on the daemon's Unix socket and on 127.0.0.1:9446,
// so the client accepts nothing else: the init request carries both PINs
// and its response carries the platform's only copy of the admin key.
package gate

import "time"

// State is the platform state reported by the pre-unseal mux.
type State string

const (
	// StateUninitialized indicates the barrier has never been initialized.
	StateUninitialized State = "uninitialized"
	// StateSealed indicates the barrier is initialized but sealed.
	StateSealed State = "sealed"
	// StateUnsealing indicates a multi-share unseal is in progress.
	StateUnsealing State = "unsealing"
	// StateUnsealed indicates the barrier is operational.
	StateUnsealed State = "unsealed"
)

// InitRequest is the body of POST /init. The barrier seal strategy is not a
// request field: the daemon takes it from its barrier.seal_strategy
// configuration. A shamir init names one Security Officer per share.
type InitRequest struct {
	SOPIN                  string        `json:"so_pin,omitempty"`
	UserPIN                string        `json:"user_pin,omitempty"`
	Shares                 int           `json:"shares,omitempty"`
	Threshold              int           `json:"threshold,omitempty"`
	Hostname               string        `json:"hostname,omitempty"`
	SANs                   []string      `json:"sans,omitempty"`
	CredentialSealStrategy string        `json:"credential_seal_strategy,omitempty"`
	Officers               []InitOfficer `json:"officers,omitempty"`
}

// InitOfficer is a Security Officer enrolled by a shamir init: the officer's
// username and the PEM certificate signing request the ceremony signs into
// its custodian certificate. The officer keeps the private key.
type InitOfficer struct {
	Username string `json:"username"`
	CSRPEM   string `json:"csr_pem"`
}

// InitResponse is the body POST /init returns. AdminCertPEM and AdminKeyPEM
// are the one-shot admin bundle: the daemon does not store the key.
type InitResponse struct {
	CeremonyID    string    `json:"ceremony_id,omitempty"`
	State         State     `json:"state"`
	InitializedAt time.Time `json:"initialized_at,omitempty"`
	SPKIPin       string    `json:"spki_pin,omitempty"`
	AdminCertPEM  string    `json:"admin_cert_pem,omitempty"`
	AdminKeyPEM   string    `json:"admin_key_pem,omitempty"`
}
