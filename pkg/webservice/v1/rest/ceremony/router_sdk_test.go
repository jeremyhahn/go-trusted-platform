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

package ceremony

import (
	"context"
	"net/http/httptest"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// TestCeremonyRouter_GoRESTAdapterRoundTrips drives the real router through
// the Go SDK's REST adapter: the router's protojson replies must decode in the
// adapter (Init's one-shot admin key must reach the caller), and the adapter's
// lowercase role and authenticator strings must reach the service.
func TestCeremonyRouter_GoRESTAdapterRoundTrips(t *testing.T) {
	server := &recordingServer{}
	srv := httptest.NewServer(mountRouter(server))
	t.Cleanup(srv.Close)

	adapter, err := sdkrest.NewWithRoundTripper(srv.URL, srv.Client().Transport, "")
	if err != nil {
		t.Fatalf("NewWithRoundTripper: %v", err)
	}
	client := platformv1.NewCeremonyServiceClient(adapter.Connection())
	ctx := context.Background()

	t.Run("init", func(t *testing.T) {
		reply, err := client.Init(ctx, &platformv1.CeremonyInitRequest{
			SoPin:     "1234",
			Threshold: "2-of-3",
			Officers: []*platformv1.CeremonyInitOfficer{
				{Username: "alice", CsrPem: "CSR-A"},
				{Username: "bob", CsrPem: "CSR-B"},
			},
		})
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if reply.GetAdminKeyPem() != "KEY" || reply.GetAdminCertPem() != "CERT" || reply.GetSpkiPin() != "PIN" {
			t.Errorf("Init credentials = key %q cert %q pin %q; want KEY CERT PIN",
				reply.GetAdminKeyPem(), reply.GetAdminCertPem(), reply.GetSpkiPin())
		}
		if reply.GetCeremonyId() != "cer-1" {
			t.Errorf("CeremonyId = %q, want cer-1", reply.GetCeremonyId())
		}
		if reply.GetState() != platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS {
			t.Errorf("State = %v, want IN_PROGRESS", reply.GetState())
		}
	})

	t.Run("status", func(t *testing.T) {
		reply, err := client.Status(ctx, &platformv1.CeremonyStatusRequest{})
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if reply.GetOfficersEnrolled() != 2 || reply.GetOfficersRequired() != 5 {
			t.Errorf("Status officers = %d/%d, want 2/5", reply.GetOfficersEnrolled(), reply.GetOfficersRequired())
		}
	})

	t.Run("claim cert begin", func(t *testing.T) {
		reply, err := client.ClaimCertBegin(ctx, &platformv1.CeremonyClaimCertBeginRequest{
			AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV,
			Username:          "alice",
		})
		if err != nil {
			t.Fatalf("ClaimCertBegin: %v", err)
		}
		got, ok := server.last.(*platformv1.CeremonyClaimCertBeginRequest)
		if !ok {
			t.Fatalf("service saw %T, want *CeremonyClaimCertBeginRequest", server.last)
		}
		if got.GetAuthenticatorType() != platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV {
			t.Errorf("AuthenticatorType = %v, want PIV", got.GetAuthenticatorType())
		}
		if reply.GetChallengeId() != "ch-1" || reply.GetNonce() != "n1" {
			t.Errorf("reply = challenge %q nonce %q, want ch-1 n1", reply.GetChallengeId(), reply.GetNonce())
		}
	})

	t.Run("sign csr", func(t *testing.T) {
		reply, err := client.SignCSR(ctx, &platformv1.CeremonySignCSRRequest{
			Role:   platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
			CsrPem: "CSR",
		})
		if err != nil {
			t.Fatalf("SignCSR: %v", err)
		}
		got, ok := server.last.(*platformv1.CeremonySignCSRRequest)
		if !ok {
			t.Fatalf("service saw %T, want *CeremonySignCSRRequest", server.last)
		}
		if got.GetRole() != platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN {
			t.Errorf("Role = %v, want ROLE_ADMIN", got.GetRole())
		}
		if reply.GetCertificatePem() != "SIGNED" {
			t.Errorf("CertificatePem = %q, want SIGNED", reply.GetCertificatePem())
		}
	})
}
