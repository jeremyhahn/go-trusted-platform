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

package adminclaim

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

type harness struct {
	svc      *Service
	pki      *pki
	ceremony *fakeCeremony
	factors  *fakeFactors
	users    *fakeUsers
	issuer   *fakeIssuer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	p := newPKI(t)
	h := &harness{
		pki: p,
		ceremony: &fakeCeremony{
			beginResp: &quicbaassdk.FIDO2BeginRegistrationResponse{
				SessionID:   "sess-1",
				OptionsJSON: `{"publicKey":{"challenge":"abc"}}`,
			},
			finishResp: &quicbaassdk.FIDO2FinishRegistrationResponse{
				Success: true, CredentialID: "cred-1",
			},
		},
		factors: &fakeFactors{resp: &quicbaassdk.AuthFactorListResponse{}},
		users:   newFakeUsers(),
		issuer:  &fakeIssuer{token: "console-jwt"},
	}
	svc, err := NewService(ServiceParams{
		Logger:       testLogger(),
		Ceremony:     h.ceremony,
		Factors:      h.factors,
		Users:        h.users,
		TokenIssuer:  h.issuer,
		TrustAnchors: p.pool,
		TenantID:     testTenantID,
		AdminEmail:   testAdminEmail,
	})
	require.NoError(t, err)
	h.svc = svc
	return h
}

// claimTo walks the happy path up to a claim token.
func (h *harness) claimTo(t *testing.T) string {
	t.Helper()
	challenge, _, err := h.svc.Challenge(context.Background())
	require.NoError(t, err)
	_, certPEM, signer := h.pki.adminLeaf(t)
	token, _, err := h.svc.Prove(context.Background(), ProveRequest{
		Challenge:      challenge,
		CertificatePEM: string(certPEM),
		Signature:      signChallenge(t, signer, challenge),
	}, nil)
	require.NoError(t, err)
	return token
}

func TestNewService_RejectsMissingDependencies(t *testing.T) {
	p := newPKI(t)
	complete := ServiceParams{
		Logger:       testLogger(),
		Ceremony:     &fakeCeremony{},
		Factors:      &fakeFactors{},
		Users:        newFakeUsers(),
		TokenIssuer:  &fakeIssuer{},
		TrustAnchors: p.pool,
		TenantID:     testTenantID,
	}
	tests := []struct {
		name    string
		mutate  func(*ServiceParams)
		missing string
	}{
		{"logger", func(p *ServiceParams) { p.Logger = nil }, "logger"},
		{"ceremony", func(p *ServiceParams) { p.Ceremony = nil }, "FIDO2 ceremony client"},
		{"factors", func(p *ServiceParams) { p.Factors = nil }, "auth factors client"},
		{"users", func(p *ServiceParams) { p.Users = nil }, "user service"},
		{"issuer", func(p *ServiceParams) { p.TokenIssuer = nil }, "token issuer"},
		{"anchors", func(p *ServiceParams) { p.TrustAnchors = nil }, "admin trust anchor"},
		{"tenant", func(p *ServiceParams) { p.TenantID = "" }, "tenant id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := complete
			tt.mutate(&params)
			svc, err := NewService(params)
			assert.Nil(t, svc)
			var missing ErrDependencyRequired
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, tt.missing, missing.Name)
		})
	}
}

func TestNewService_DefaultsAdminUsername(t *testing.T) {
	h := newHarness(t)
	assert.Equal(t, common.AdminUsername, h.svc.adminUsername)
}

func TestClaimed(t *testing.T) {
	revoked := time.Now()
	tests := []struct {
		name    string
		resp    *quicbaassdk.AuthFactorListResponse
		err     error
		claimed bool
		wantErr bool
	}{
		{
			name: "no factors is unclaimed",
			resp: &quicbaassdk.AuthFactorListResponse{},
		},
		{
			name: "only the bootstrap mtls factor is unclaimed",
			resp: &quicbaassdk.AuthFactorListResponse{
				Enrollments: []quicbaassdk.AuthFactorEntry{{FactorName: "mtls"}},
			},
		},
		{
			name: "a revoked passkey does not count",
			resp: &quicbaassdk.AuthFactorListResponse{
				Enrollments: []quicbaassdk.AuthFactorEntry{
					{FactorName: "fido2", RevokedAt: &revoked},
				},
			},
		},
		{
			name: "a live passkey is claimed",
			resp: &quicbaassdk.AuthFactorListResponse{
				Enrollments: []quicbaassdk.AuthFactorEntry{{FactorName: "FIDO2"}},
			},
			claimed: true,
		},
		{
			name: "nil response is unclaimed",
		},
		{
			name:    "an SDK failure is reported, never guessed",
			err:     errors.New("transport down"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.factors.resp, h.factors.err = tt.resp, tt.err
			claimed, err := h.svc.Claimed(context.Background())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.claimed, claimed)
		})
	}
}

func TestProve_SignedChallengeHappyPath(t *testing.T) {
	h := newHarness(t)
	token := h.claimTo(t)
	assert.NotEmpty(t, token)
}

func TestProve_MTLSHandshakeIsItsOwnProof(t *testing.T) {
	h := newHarness(t)
	cert, _, _ := h.pki.adminLeaf(t)

	// No challenge, no signature: the handshake already proved possession.
	token, expiresAt, err := h.svc.Prove(context.Background(), ProveRequest{},
		[]*x509.Certificate{cert})
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.True(t, expiresAt.After(time.Now()))
}

// TestProve_OnlyTheHandshakeLeafCounts is the property the mTLS path rests
// on. r.TLS.PeerCertificates is the whole Certificate message the client
// sent, but TLS proves possession of the private key for the LEAF alone.
// A client holding any acceptable certificate must not be able to attach a
// copy of the (public, freely readable) admin certificate behind its own
// and be taken for the admin.
func TestProve_OnlyTheHandshakeLeafCounts(t *testing.T) {
	h := newHarness(t)
	adminCert, _, _ := h.pki.adminLeaf(t)
	attackerCert, _, _ := h.pki.issue(t, leafOptions{commonName: "mallory"})

	token, _, err := h.svc.Prove(context.Background(), ProveRequest{},
		[]*x509.Certificate{attackerCert, adminCert})

	assert.Empty(t, token, "the admin cert behind another leaf must not grant a claim")
	require.Error(t, err)
	// With no usable handshake proof the request falls to the signed
	// challenge it did not supply.
	require.ErrorAs(t, err, &ErrChallengeUnknown{})
}

func TestProve_EmptyPeerChain(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.svc.Prove(context.Background(), ProveRequest{}, []*x509.Certificate{})
	require.ErrorAs(t, err, &ErrChallengeUnknown{})
}

func TestProve_RejectsBadProofs(t *testing.T) {
	tests := []struct {
		name    string
		request func(t *testing.T, h *harness, challenge string) ProveRequest
		peers   func(t *testing.T, h *harness) []*x509.Certificate
		errAs   any
	}{
		{
			name: "unknown challenge",
			request: func(t *testing.T, h *harness, _ string) ProveRequest {
				_, certPEM, signer := h.pki.adminLeaf(t)
				return ProveRequest{
					Challenge:      "not-a-challenge",
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, signer, "not-a-challenge"),
				}
			},
			errAs: &ErrChallengeUnknown{},
		},
		{
			name: "certificate from a foreign CA",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				other := newPKI(t)
				_, certPEM, signer := other.adminLeaf(t)
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, signer, challenge),
				}
			},
			errAs: &ErrCertificateInvalid{},
		},
		{
			name: "correct CA but the wrong subject",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				_, certPEM, signer := h.pki.issue(t, leafOptions{commonName: "operator"})
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, signer, challenge),
				}
			},
			errAs: &ErrIdentityMismatch{},
		},
		{
			name: "admin CN but a SPIFFE id naming someone else",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				_, certPEM, signer := h.pki.issue(t, leafOptions{
					commonName: "admin",
					spiffeURI:  "spiffe://example.internal/tenant/system/user/mallory",
				})
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, signer, challenge),
				}
			},
			errAs: &ErrIdentityMismatch{},
		},
		{
			name: "signature by a different key",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				_, certPEM, _ := h.pki.adminLeaf(t)
				_, _, otherSigner := h.pki.adminLeaf(t)
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, otherSigner, challenge),
				}
			},
			errAs: &ErrProofInvalid{},
		},
		{
			name: "no signature at all",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				_, certPEM, _ := h.pki.adminLeaf(t)
				return ProveRequest{Challenge: challenge, CertificatePEM: string(certPEM)}
			},
			errAs: &ErrProofInvalid{},
		},
		{
			name: "garbage certificate",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----",
					Signature:      []byte("x"),
				}
			},
			errAs: &ErrCertificateInvalid{},
		},
		{
			name: "expired admin certificate",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				_, certPEM, signer := h.pki.issue(t, leafOptions{
					commonName: "admin",
					notBefore:  time.Now().Add(-48 * time.Hour),
					notAfter:   time.Now().Add(-24 * time.Hour),
				})
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, signer, challenge),
				}
			},
			errAs: &ErrCertificateInvalid{},
		},
		{
			name: "self-signed certificate claiming to be the admin",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				_, certPEM, signer := h.pki.issue(t, leafOptions{
					commonName: "admin", selfSigned: true,
				})
				return ProveRequest{
					Challenge:      challenge,
					CertificatePEM: string(certPEM),
					Signature:      signChallenge(t, signer, challenge),
				}
			},
			errAs: &ErrCertificateInvalid{},
		},
		{
			name: "a peer certificate from a foreign CA is not a proof",
			request: func(t *testing.T, h *harness, challenge string) ProveRequest {
				return ProveRequest{Challenge: "unused"}
			},
			peers: func(t *testing.T, h *harness) []*x509.Certificate {
				other := newPKI(t)
				cert, _, _ := other.adminLeaf(t)
				return []*x509.Certificate{cert}
			},
			errAs: &ErrChallengeUnknown{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			challenge, _, err := h.svc.Challenge(context.Background())
			require.NoError(t, err)

			var peers []*x509.Certificate
			if tt.peers != nil {
				peers = tt.peers(t, h)
			}
			token, _, err := h.svc.Prove(context.Background(), tt.request(t, h, challenge), peers)
			assert.Empty(t, token)
			require.Error(t, err)
			require.ErrorAs(t, err, tt.errAs)
		})
	}
}

func TestProve_ChallengeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	challenge, _, err := h.svc.Challenge(context.Background())
	require.NoError(t, err)
	_, certPEM, signer := h.pki.adminLeaf(t)
	req := ProveRequest{
		Challenge:      challenge,
		CertificatePEM: string(certPEM),
		Signature:      signChallenge(t, signer, challenge),
	}
	_, _, err = h.svc.Prove(context.Background(), req, nil)
	require.NoError(t, err)

	// Replaying the identical, cryptographically valid proof must fail.
	_, _, err = h.svc.Prove(context.Background(), req, nil)
	require.ErrorAs(t, err, &ErrChallengeUnknown{})
}

func TestClaimFlow_RefusesOnceClaimed(t *testing.T) {
	h := newHarness(t)
	h.factors.resp = &quicbaassdk.AuthFactorListResponse{
		Enrollments: []quicbaassdk.AuthFactorEntry{{FactorName: "fido2"}},
	}
	_, _, err := h.svc.Challenge(context.Background())
	require.ErrorAs(t, err, &ErrAlreadyClaimed{})

	_, _, err = h.svc.Prove(context.Background(), ProveRequest{}, nil)
	require.ErrorAs(t, err, &ErrAlreadyClaimed{})

	_, err = h.svc.BeginPasskey(context.Background(), "anything")
	require.Error(t, err)
}

func TestBeginPasskey(t *testing.T) {
	h := newHarness(t)
	token := h.claimTo(t)

	options, err := h.svc.BeginPasskey(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, "sess-1", options.SessionID)

	// Begin must NOT spend the token — finish still needs it.
	_, err = h.svc.BeginPasskey(context.Background(), token)
	require.NoError(t, err)
	assert.Equal(t, 2, h.ceremony.beginCalls)
}

func TestBeginPasskey_RejectsBadToken(t *testing.T) {
	h := newHarness(t)
	h.claimTo(t)

	for _, token := range []string{"", "wrong-token"} {
		_, err := h.svc.BeginPasskey(context.Background(), token)
		require.ErrorAs(t, err, &ErrClaimTokenInvalid{})
	}
	assert.Zero(t, h.ceremony.beginCalls)
}

func TestFinishPasskey_HappyPath(t *testing.T) {
	h := newHarness(t)
	token := h.claimTo(t)

	bearer, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{SessionID: "sess-1"})
	require.NoError(t, err)
	assert.Equal(t, "console-jwt", bearer)

	// The platform-local admin exists, in the operating tenant, with the
	// admin role — without it the issued token carries no roles and every
	// gated surface would refuse the operator it just enrolled.
	stored, err := h.users.Get(context.Background(), util.NewID([]byte(common.AdminUsername)))
	require.NoError(t, err)
	assert.Equal(t, testTenantID, stored.TenantID)
	require.Len(t, stored.Roles, 1)
	assert.Equal(t, common.ROLE_ADMIN, stored.Roles[0].Name)
	assert.Same(t, stored, h.issuer.user)
}

func TestFinishPasskey_DoesNotDuplicateTheAdminRole(t *testing.T) {
	h := newHarness(t)
	existing := entities.NewUser(common.AdminUsername)
	existing.AddRole(entities.NewRole(common.ROLE_ADMIN))
	require.NoError(t, h.users.Save(context.Background(), existing))

	token := h.claimTo(t)
	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.NoError(t, err)

	stored, err := h.users.Get(context.Background(), existing.ID)
	require.NoError(t, err)
	assert.Len(t, stored.Roles, 1)
}

func TestFinishPasskey_FailureModes(t *testing.T) {
	tests := []struct {
		name    string
		arrange func(h *harness)
		token   func(h *harness, valid string) string
		errAs   any
	}{
		{
			name:  "missing claim token",
			token: func(h *harness, valid string) string { return "" },
			errAs: &ErrClaimTokenInvalid{},
		},
		{
			name: "SDK reports the attestation unverified",
			arrange: func(h *harness) {
				h.ceremony.finishResp = &quicbaassdk.FIDO2FinishRegistrationResponse{Success: false}
			},
			errAs: &ErrCeremonyRejected{},
		},
		{
			name: "SDK returns nothing at all",
			arrange: func(h *harness) {
				h.ceremony.finishResp = nil
			},
			errAs: &ErrCeremonyRejected{},
		},
		{
			name: "the user store rejects the write",
			arrange: func(h *harness) {
				h.users.saveErr = errors.New("disk full")
			},
			errAs: new(error),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			valid := h.claimTo(t)
			if tt.arrange != nil {
				tt.arrange(h)
			}
			token := valid
			if tt.token != nil {
				token = tt.token(h, valid)
			}
			bearer, err := h.svc.FinishPasskey(context.Background(), token,
				&quicbaassdk.FIDO2FinishRegistrationRequest{})
			assert.Empty(t, bearer)
			require.Error(t, err)
			if _, ok := tt.errAs.(*error); !ok {
				require.ErrorAs(t, err, tt.errAs)
			}
		})
	}
}

func TestFinishPasskey_SpendsTheTokenEvenWhenTheCeremonyFails(t *testing.T) {
	h := newHarness(t)
	token := h.claimTo(t)
	h.ceremony.finishErr = errors.New("authenticator withdrawn")

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.Error(t, err)

	// A failed attempt must not leave the proof reusable.
	h.ceremony.finishErr = nil
	_, err = h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.ErrorAs(t, err, &ErrClaimTokenInvalid{})
}

func TestPeerCertificates(t *testing.T) {
	assert.Nil(t, PeerCertificates(nil))
}

// TestMaterialiseAdmin_FailsClosedOnAReadError distinguishes "the store
// says there is no such user" from "the store could not answer". Treating
// them alike would let a transient read error replace an existing admin
// record with a fresh minimal one, mid-ceremony.
func TestFinishPasskey_FailsClosedOnAUserStoreReadError(t *testing.T) {
	h := newHarness(t)
	existing := entities.NewUser(common.AdminUsername)
	existing.DisplayName = "the real admin"
	existing.AddRole(entities.NewRole(common.ROLE_ADMIN))
	require.NoError(t, h.users.Save(context.Background(), existing))

	token := h.claimTo(t)
	h.users.getErr = errors.New("store unavailable")

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store unavailable")

	// The irreversible step must not have run.
	assert.Zero(t, h.ceremony.finishCalls.Load(),
		"enrolment must not commit when the admin record could not be read")

	// And the existing record is intact.
	h.users.getErr = nil
	stored, err := h.users.Get(context.Background(), existing.ID)
	require.NoError(t, err)
	assert.Equal(t, "the real admin", stored.DisplayName)
}

// TestFinishPasskey_DoesNotStrandTheOperator: the SDK enrolment is the
// irreversible step — once the factor exists the ceremony is closed
// forever. Anything that can fail must therefore fail BEFORE it, or the
// operator ends up with a claimed identity and no way in.
func TestFinishPasskey_DoesNotStrandTheOperator(t *testing.T) {
	h := newHarness(t)
	h.users.saveErr = errors.New("disk full")
	token := h.claimTo(t)

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.Error(t, err)
	assert.Zero(t, h.ceremony.finishCalls.Load(),
		"a failure that precedes enrolment must not have enrolled anything")

	// The identity is still claimable, so the operator can retry.
	claimed, err := h.svc.Claimed(context.Background())
	require.NoError(t, err)
	assert.False(t, claimed)
}

// TestFinishPasskey_TokenFailureLeavesAUsablePasskey is the other half:
// once enrolment HAS committed, a later failure costs only the response.
// The operator signs in with the passkey they just registered.
func TestFinishPasskey_TokenFailureLeavesAUsablePasskey(t *testing.T) {
	h := newHarness(t)
	h.issuer.err = errors.New("signer unavailable")
	token := h.claimTo(t)

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.Error(t, err)

	// The local admin record exists with the admin role, so the passkey
	// login that follows resolves a usable identity.
	stored, err := h.users.Get(context.Background(), util.NewID([]byte(common.AdminUsername)))
	require.NoError(t, err)
	require.Len(t, stored.Roles, 1)
	assert.Equal(t, common.ROLE_ADMIN, stored.Roles[0].Name)
}

// TestFinishPasskey_OnlyOneConcurrentClaimCompletes is the one-time
// ownership property under a race. Two callers holding DIFFERENT valid
// claim tokens must not both enrol an authenticator — otherwise someone
// with a copied bootstrap key could race the legitimate operator and keep
// admin access.
func TestFinishPasskey_OnlyOneConcurrentClaimCompletes(t *testing.T) {
	h := newHarness(t)
	// The enrolment becomes visible to the factor lister, as a real
	// write-through enrolment does.
	h.ceremony.onFinish = h.factors.enrolFIDO2

	tokens := []string{h.claimTo(t), h.claimTo(t)}
	require.NotEqual(t, tokens[0], tokens[1])

	var wg sync.WaitGroup
	results := make(chan error, len(tokens))
	start := make(chan struct{})
	for _, token := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := h.svc.FinishPasskey(context.Background(), token,
				&quicbaassdk.FIDO2FinishRegistrationRequest{})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		require.ErrorAs(t, err, &ErrAlreadyClaimed{},
			"the loser must be told the identity is already claimed")
	}
	assert.Equal(t, 1, succeeded, "exactly one claim may complete")
	assert.Equal(t, int64(1), h.ceremony.finishCalls.Load(),
		"exactly one authenticator may be enrolled")
}

// TestFinishPasskey_RunsUnderTheCompletionLock proves the mutual exclusion
// directly rather than by racing for it. The claimed-check and the
// enrolment are a check-then-act; a scheduling-dependent test would pass
// against an unlocked implementation most of the time, so this asserts the
// lock is held at the moment the irreversible step runs.
func TestFinishPasskey_RunsUnderTheCompletionLock(t *testing.T) {
	h := newHarness(t)
	token := h.claimTo(t)

	observed := false
	h.ceremony.onFinish = func() {
		observed = true
		// TryLock fails for a mutex already held — including by this very
		// goroutine. It succeeding would mean nothing is serialising the
		// completion.
		if h.svc.completing.TryLock() {
			h.svc.completing.Unlock()
			t.Error("enrolment ran without holding the completion lock")
		}
	}

	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.NoError(t, err)
	require.True(t, observed, "the ceremony hook must have run")
}

// TestClaimed_TracksLiveFactorsNotHistory pins a deliberate design choice
// that a reviewer reasonably challenged: the ceremony closes while an
// authenticator is enrolled, and re-opens when the last one is removed.
//
// That is the recovery path for a lost security key. An irreversible
// claimed marker would brick a deployment's admin identity the first time
// someone loses one — a worse failure than a re-claim, which still demands
// the node's root-only bootstrap private key AND an authenticated admin
// session to remove the factor in the first place.
func TestClaimed_TracksLiveFactorsNotHistory(t *testing.T) {
	h := newHarness(t)
	h.ceremony.onFinish = h.factors.enrolFIDO2

	token := h.claimTo(t)
	_, err := h.svc.FinishPasskey(context.Background(), token,
		&quicbaassdk.FIDO2FinishRegistrationRequest{})
	require.NoError(t, err)

	claimed, err := h.svc.Claimed(context.Background())
	require.NoError(t, err)
	require.True(t, claimed, "an enrolled passkey closes the ceremony")

	// The operator loses the key and an admin revokes the factor.
	revoked := time.Now()
	h.factors.resp = &quicbaassdk.AuthFactorListResponse{
		Enrollments: []quicbaassdk.AuthFactorEntry{
			{FactorName: "fido2", RevokedAt: &revoked},
		},
	}
	claimed, err = h.svc.Claimed(context.Background())
	require.NoError(t, err)
	assert.False(t, claimed,
		"revoking the last authenticator re-opens the ceremony, by design")

	// And the ceremony really is runnable again.
	_, _, err = h.svc.Challenge(context.Background())
	require.NoError(t, err)
}

// TestMultiInstanceRefusesCeremony proves the fail-closed gate for
// clustered deployments: the ceremony's one-time state is process-local
// and SDK factor enrolment is not conditional (#170), so a deployment
// running several platformd instances against one store must not be
// offered a ceremony whose safety property does not hold. Both the ENTRY
// point and the completion refuse, so an operator cannot walk the whole
// ceremony only to fail at the irreversible step.
func TestMultiInstanceRefusesCeremony(t *testing.T) {
	p := newPKI(t)
	svc, err := NewService(ServiceParams{
		Logger:        testLogger(),
		Ceremony:      &fakeCeremony{},
		Factors:       &fakeFactors{resp: &quicbaassdk.AuthFactorListResponse{}},
		Users:         newFakeUsers(),
		TokenIssuer:   &fakeIssuer{token: "console-jwt"},
		TrustAnchors:  p.pool,
		TenantID:      testTenantID,
		AdminEmail:    testAdminEmail,
		MultiInstance: true,
	})
	require.NoError(t, err)

	var refused ErrMultiInstanceUnsupported

	_, _, err = svc.Challenge(context.Background())
	require.ErrorAs(t, err, &refused, "Challenge must refuse on a multi-instance deployment")

	_, _, err = svc.Prove(context.Background(), ProveRequest{}, nil)
	require.ErrorAs(t, err, &refused, "Prove must refuse — the mTLS path issues a claim token without Challenge")

	_, err = svc.BeginPasskey(context.Background(), "any-claim-token")
	require.ErrorAs(t, err, &refused, "BeginPasskey must refuse before reaching the SDK ceremony")

	_, err = svc.FinishPasskey(context.Background(), "any-claim-token", nil)
	require.ErrorAs(t, err, &refused, "FinishPasskey must refuse on a multi-instance deployment")
}

// TestSingleInstanceServesCeremony pins the default: an ordinary
// single-instance deployment is unaffected by the gate.
func TestSingleInstanceServesCeremony(t *testing.T) {
	h := newHarness(t)

	_, _, err := h.svc.Challenge(context.Background())
	require.NoError(t, err, "single-instance Challenge must not be refused by the gate")
}
