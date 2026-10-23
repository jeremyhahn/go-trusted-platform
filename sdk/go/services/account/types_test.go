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
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/account"
)

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"AccountInfo", reflect.TypeFor[AccountInfo](), reflect.TypeFor[upstream.AccountInfo]()},
		{"Credential", reflect.TypeFor[Credential](), reflect.TypeFor[upstream.Credential]()},
		{"CredentialHealth", reflect.TypeFor[CredentialHealth](), reflect.TypeFor[upstream.CredentialHealth]()},
		{"Provider", reflect.TypeFor[Provider](), reflect.TypeFor[upstream.Provider]()},
		{"RefreshPolicy", reflect.TypeFor[RefreshPolicy](), reflect.TypeFor[upstream.RefreshPolicy]()},
		{"Status", reflect.TypeFor[Status](), reflect.TypeFor[upstream.Status]()},
		{"UsageReport", reflect.TypeFor[UsageReport](), reflect.TypeFor[upstream.UsageReport]()},
		{"MaterializedCredential", reflect.TypeFor[MaterializedCredential](), reflect.TypeFor[upstream.MaterializedCredential]()},
		{"ReleasedCredential", reflect.TypeFor[ReleasedCredential](), reflect.TypeFor[upstream.ReleasedCredential]()},
		{"CreateAccountRequest", reflect.TypeFor[CreateAccountRequest](), reflect.TypeFor[upstream.CreateAccountRequest]()},
		{"GetAccountRequest", reflect.TypeFor[GetAccountRequest](), reflect.TypeFor[upstream.GetAccountRequest]()},
		{"ListAccountsRequest", reflect.TypeFor[ListAccountsRequest](), reflect.TypeFor[upstream.ListAccountsRequest]()},
		{"ListAccountsResponse", reflect.TypeFor[ListAccountsResponse](), reflect.TypeFor[upstream.ListAccountsResponse]()},
		{"UpdateAccountRequest", reflect.TypeFor[UpdateAccountRequest](), reflect.TypeFor[upstream.UpdateAccountRequest]()},
		{"DeleteAccountRequest", reflect.TypeFor[DeleteAccountRequest](), reflect.TypeFor[upstream.DeleteAccountRequest]()},
		{"DeleteAccountResponse", reflect.TypeFor[DeleteAccountResponse](), reflect.TypeFor[upstream.DeleteAccountResponse]()},
		{"RotateCredentialRequest", reflect.TypeFor[RotateCredentialRequest](), reflect.TypeFor[upstream.RotateCredentialRequest]()},
		{"RevokeAccountRequest", reflect.TypeFor[RevokeAccountRequest](), reflect.TypeFor[upstream.RevokeAccountRequest]()},
		{"SetDefaultAccountRequest", reflect.TypeFor[SetDefaultAccountRequest](), reflect.TypeFor[upstream.SetDefaultAccountRequest]()},
		{"GetAccountUsageRequest", reflect.TypeFor[GetAccountUsageRequest](), reflect.TypeFor[upstream.GetAccountUsageRequest]()},
		{"MaterializeCredentialRequest", reflect.TypeFor[MaterializeCredentialRequest](), reflect.TypeFor[upstream.MaterializeCredentialRequest]()},
		{"AccountAckResponse", reflect.TypeFor[AccountAckResponse](), reflect.TypeFor[upstream.AccountAckResponse]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported constant carries the
// upstream value and type, so a filter or comparison written against this
// package means what the server means.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"CredentialHealthUnknown", CredentialHealthUnknown, upstream.CredentialHealthUnknown},
		{"CredentialHealthValid", CredentialHealthValid, upstream.CredentialHealthValid},
		{"CredentialHealthExpiring", CredentialHealthExpiring, upstream.CredentialHealthExpiring},
		{"CredentialHealthExpired", CredentialHealthExpired, upstream.CredentialHealthExpired},
		{"ProviderClaude", ProviderClaude, upstream.ProviderClaude},
		{"ProviderCodex", ProviderCodex, upstream.ProviderCodex},
		{"ProviderOpenCode", ProviderOpenCode, upstream.ProviderOpenCode},
		{"RefreshNone", RefreshNone, upstream.RefreshNone},
		{"RefreshOAuth2", RefreshOAuth2, upstream.RefreshOAuth2},
		{"StatusActive", StatusActive, upstream.StatusActive},
		{"StatusRevoked", StatusRevoked, upstream.StatusRevoked},
		{"StatusError", StatusError, upstream.StatusError},
		{"StatusLimited", StatusLimited, upstream.StatusLimited},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}
