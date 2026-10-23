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

package account

import (
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/account"
)

// Client is the pooled provider account client returned by
// quicbaas.Client.Account().
type Client = upstream.Client

// Account records and the value types they carry.
type (
	// AccountInfo is an account's non-secret metadata.
	AccountInfo = upstream.AccountInfo
	// Credential is the secret envelope of one account. Request-only: Create
	// and RotateCredential accept it and nothing returns it.
	Credential = upstream.Credential
	// CredentialHealth is the server's verdict on a credential's remaining life.
	CredentialHealth = upstream.CredentialHealth
	// Provider identifies which CLI or backend an account authenticates.
	Provider = upstream.Provider
	// RefreshPolicy selects how an account's credential is kept usable.
	RefreshPolicy = upstream.RefreshPolicy
	// Status is the lifecycle state of a pooled account.
	Status = upstream.Status
	// UsageReport is the cumulative token usage recorded against an account.
	UsageReport = upstream.UsageReport
	// MaterializedCredential is one released envelope plus the non-secret
	// metadata a caching caller needs.
	MaterializedCredential = upstream.MaterializedCredential
	// ReleasedCredential is the envelope Materialize releases. It carries no
	// refresh grant: renewal is the server's job.
	ReleasedCredential = upstream.ReleasedCredential
)

// Requests and responses of the Client verbs.
type (
	CreateAccountRequest         = upstream.CreateAccountRequest
	GetAccountRequest            = upstream.GetAccountRequest
	ListAccountsRequest          = upstream.ListAccountsRequest
	ListAccountsResponse         = upstream.ListAccountsResponse
	UpdateAccountRequest         = upstream.UpdateAccountRequest
	DeleteAccountRequest         = upstream.DeleteAccountRequest
	DeleteAccountResponse        = upstream.DeleteAccountResponse
	RotateCredentialRequest      = upstream.RotateCredentialRequest
	RevokeAccountRequest         = upstream.RevokeAccountRequest
	SetDefaultAccountRequest     = upstream.SetDefaultAccountRequest
	GetAccountUsageRequest       = upstream.GetAccountUsageRequest
	MaterializeCredentialRequest = upstream.MaterializeCredentialRequest
	AccountAckResponse           = upstream.AccountAckResponse
)

// Credential health verdicts.
const (
	CredentialHealthUnknown  = upstream.CredentialHealthUnknown
	CredentialHealthValid    = upstream.CredentialHealthValid
	CredentialHealthExpiring = upstream.CredentialHealthExpiring
	CredentialHealthExpired  = upstream.CredentialHealthExpired
)

// Pooled providers.
const (
	ProviderClaude   = upstream.ProviderClaude
	ProviderCodex    = upstream.ProviderCodex
	ProviderOpenCode = upstream.ProviderOpenCode
)

// Credential refresh policies.
const (
	RefreshNone   = upstream.RefreshNone
	RefreshOAuth2 = upstream.RefreshOAuth2
)

// Account lifecycle states.
const (
	StatusActive  = upstream.StatusActive
	StatusRevoked = upstream.StatusRevoked
	StatusError   = upstream.StatusError
	StatusLimited = upstream.StatusLimited
)
