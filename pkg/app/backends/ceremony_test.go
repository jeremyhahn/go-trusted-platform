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

package backends

import (
	"context"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeQuicbaasClient routes BarrierCeremonyMgmt().Ceremony() to a fake
// ceremony client; every other SDK method is unused by CeremonyBackend.
type fakeQuicbaasClient struct {
	quicbaassdk.Client
	ceremony quicbaassdk.QRDBCeremonyClient
	kv       quicbaassdk.KVClient
}

func (f *fakeQuicbaasClient) KV() quicbaassdk.KVClient { return f.kv }

func (f *fakeQuicbaasClient) BarrierCeremonyMgmt() quicbaassdk.BarrierCeremonyService {
	return &fakeCeremonyMgmt{ceremony: f.ceremony}
}

type fakeCeremonyMgmt struct {
	quicbaassdk.BarrierCeremonyService
	ceremony quicbaassdk.QRDBCeremonyClient
}

func (f *fakeCeremonyMgmt) Ceremony() (quicbaassdk.QRDBCeremonyClient, error) {
	return f.ceremony, nil
}

// fakeQRDBCeremony records the order of calls so tests can prove the admin
// bundle is minted before the ceremony mutates anything.
type fakeQRDBCeremony struct {
	quicbaassdk.QRDBCeremonyClient
	calls *[]string
	resp  *quicbaassdk.QRDBCeremonyInitializeResponse
	err   error
	req   *quicbaassdk.QRDBCeremonyInitializeRequest
}

func (f *fakeQRDBCeremony) CeremonyInitialize(_ context.Context, req *quicbaassdk.QRDBCeremonyInitializeRequest) (*quicbaassdk.QRDBCeremonyInitializeResponse, error) {
	*f.calls = append(*f.calls, "ceremony")
	f.req = req
	return f.resp, f.err
}

type fakeAdminIssuer struct {
	calls  *[]string
	bundle *AdminBundle
	err    error
}

func (f *fakeAdminIssuer) IssueAdminBundle(_ context.Context) (*AdminBundle, error) {
	*f.calls = append(*f.calls, "admin")
	return f.bundle, f.err
}

func newInitBackend(calls *[]string, issuerErr, ceremonyErr error) *CeremonyBackend {
	ceremony := &fakeQRDBCeremony{
		calls: calls,
		resp:  &quicbaassdk.QRDBCeremonyInitializeResponse{SPKIPin: "pin", State: "in_progress"},
		err:   ceremonyErr,
	}
	issuer := &fakeAdminIssuer{
		calls:  calls,
		bundle: &AdminBundle{CertPEM: "CERT", KeyPEM: "KEY"},
		err:    issuerErr,
	}
	return NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: ceremony}, issuer)
}

func TestCeremonyBackend_Initialize_ReturnsAdminBundleMintedFirst(t *testing.T) {
	var calls []string
	b := newInitBackend(&calls, nil, nil)

	out, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{SOPIN: "so", UserPIN: "user"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if out.AdminCertPEM != "CERT" || out.AdminKeyPEM != "KEY" {
		t.Fatalf("admin bundle not carried: cert=%q key=%q", out.AdminCertPEM, out.AdminKeyPEM)
	}
	if out.SPKIPin != "pin" {
		t.Fatalf("SPKIPin = %q, want pin", out.SPKIPin)
	}
	if out.State != daemon.CeremonyStateInProgress {
		t.Fatalf("State = %v, want in_progress", out.State)
	}
	if len(calls) != 2 || calls[0] != "admin" || calls[1] != "ceremony" {
		t.Fatalf("call order = %v, want [admin ceremony]", calls)
	}
}

func TestCeremonyBackend_Initialize_IssuerFailureLeavesCeremonyUntouched(t *testing.T) {
	var calls []string
	cause := errors.New("ca offline")
	b := newInitBackend(&calls, cause, nil)

	_, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
	var bundleErr *ErrCeremonyAdminBundle
	if !errors.As(err, &bundleErr) || !errors.Is(err, cause) {
		t.Fatalf("expected ErrCeremonyAdminBundle wrapping the cause, got %v", err)
	}
	if len(calls) != 1 || calls[0] != "admin" {
		t.Fatalf("ceremony must not run after an issuing failure; calls = %v", calls)
	}
}

func TestCeremonyBackend_Initialize_IncompleteBundleLeavesCeremonyUntouched(t *testing.T) {
	var calls []string
	ceremony := &fakeQRDBCeremony{calls: &calls, resp: &quicbaassdk.QRDBCeremonyInitializeResponse{}}
	issuer := &fakeAdminIssuer{calls: &calls, bundle: &AdminBundle{CertPEM: "CERT"}}
	b := NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: ceremony}, issuer)

	_, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
	var incomplete *ErrAdminBundleIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("expected ErrAdminBundleIncomplete, got %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("ceremony must not run with an incomplete bundle; calls = %v", calls)
	}
}

func TestCeremonyBackend_Initialize_NilIssuerRejectedBeforeCeremony(t *testing.T) {
	var calls []string
	ceremony := &fakeQRDBCeremony{calls: &calls, resp: &quicbaassdk.QRDBCeremonyInitializeResponse{}}
	b := NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: ceremony}, nil)

	_, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
	var nilErr *ErrCeremonyAdminIssuerNil
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected ErrCeremonyAdminIssuerNil, got %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("ceremony must not run without an issuer; calls = %v", calls)
	}
}

func TestCeremonyBackend_Initialize_CeremonyFailurePropagates(t *testing.T) {
	var calls []string
	cause := errors.New("already initialized")
	b := newInitBackend(&calls, nil, cause)

	out, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
	if !errors.Is(err, cause) {
		t.Fatalf("expected the ceremony error, got %v", err)
	}
	if out != nil {
		t.Fatalf("no result may be returned on failure, got %+v", out)
	}
}

func TestCeremonyBackend_Initialize_ReturnsSPKIPin(t *testing.T) {
	var calls []string
	ceremony := &fakeQRDBCeremony{
		calls: &calls,
		resp:  &quicbaassdk.QRDBCeremonyInitializeResponse{SPKIPin: "sha256/abc", State: "complete"},
	}
	issuer := &fakeAdminIssuer{calls: &calls, bundle: &AdminBundle{CertPEM: "CERT", KeyPEM: "KEY"}}
	b := NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: ceremony}, issuer)

	res, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{SOPIN: "so", UserPIN: "user"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if res.SPKIPin != "sha256/abc" {
		t.Fatalf("SPKIPin = %q, want sha256/abc", res.SPKIPin)
	}
	if res.State != daemon.CeremonyStateComplete {
		t.Fatalf("State = %v, want complete", res.State)
	}
}

func TestCeremonyBackend_Initialize_PropagatesUpstreamError(t *testing.T) {
	var calls []string
	boom := errors.New("ceremony failed")
	b := newInitBackend(&calls, nil, boom)

	res, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the upstream error", err)
	}
	if res != nil {
		t.Fatalf("expected no result, got %+v", res)
	}
}

func TestCeremonyBackend_NilClient_ReturnsTypedError(t *testing.T) {
	b := NewCeremonyBackend(logging.DefaultLogger(), nil, nil)

	t.Run("Initialize", func(t *testing.T) {
		_, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("Status", func(t *testing.T) {
		_, err := b.Status(context.Background())
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimCertBegin", func(t *testing.T) {
		_, err := b.ClaimCertBegin(context.Background(), &daemon.CeremonyClaimCertBeginRequest{Username: "u"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimCertComplete", func(t *testing.T) {
		_, err := b.ClaimCertComplete(context.Background(), &daemon.CeremonyClaimCertCompleteRequest{Username: "u", Nonce: "x", Signature: "y"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimShareBegin", func(t *testing.T) {
		_, err := b.ClaimShareBegin(context.Background(), &daemon.CeremonyClaimShareBeginRequest{Username: "u"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("ClaimShareComplete", func(t *testing.T) {
		_, err := b.ClaimShareComplete(context.Background(), &daemon.CeremonyClaimShareCompleteRequest{Username: "u", Nonce: "x", Signature: []byte("y")})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})

	t.Run("SignCSR", func(t *testing.T) {
		_, err := b.SignCSR(context.Background(), &daemon.CeremonySignCSRRequest{Username: "u", CSRPEM: "pem"})
		if !errors.Is(err, ErrCeremonyBackendClientNil) {
			t.Fatalf("expected ErrCeremonyBackendClientNil, got %v", err)
		}
	})
}

func TestMapCeremonyState(t *testing.T) {
	cases := []struct {
		in   string
		want daemon.CeremonyStateValue
	}{
		{"", daemon.CeremonyStateUnknown},
		// go-qrdb's canonical ceremony.CeremonyState spellings.
		{"awaiting_init", daemon.CeremonyStateUninitialized},
		{"enrolling", daemon.CeremonyStateInProgress},
		{"operational", daemon.CeremonyStateComplete},
		{"uninitialized", daemon.CeremonyStateUninitialized},
		{"in_progress", daemon.CeremonyStateInProgress},
		{"in-progress", daemon.CeremonyStateInProgress},
		{"inprogress", daemon.CeremonyStateInProgress},
		{"complete", daemon.CeremonyStateComplete},
		{"completed", daemon.CeremonyStateComplete},
		{"bogus", daemon.CeremonyStateUnknown},
	}
	for _, tc := range cases {
		if got := mapCeremonyState(tc.in); got != tc.want {
			t.Errorf("mapCeremonyState(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestThresholdQuorum(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"3-of-5", 3},
		{"2-of-3", 2},
		{"1-of-1", 1},
		{"10-of-25", 10},
	}
	for _, tc := range cases {
		if got := thresholdQuorum(tc.in); got != tc.want {
			t.Errorf("thresholdQuorum(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestThresholdQuorum_Malformed falls back to zero, the ceremony's
// single-admin mode, for any spec that is not "M-of-N".
func TestThresholdQuorum_Malformed(t *testing.T) {
	for _, in := range []string{"", "garbage", "x-of-5", "-1-of-3", "3of5"} {
		if got := thresholdQuorum(in); got != 0 {
			t.Errorf("thresholdQuorum(%q) = %d, want 0", in, got)
		}
	}
}

// TestCeremonyBackend_Initialize_ForwardsOfficersAndQuorum pins the SDK
// request an M-of-N init sends: Threshold is the quorum M, not the share
// count, and every officer reaches the ceremony to have its CSR signed.
func TestCeremonyBackend_Initialize_ForwardsOfficersAndQuorum(t *testing.T) {
	var calls []string
	ceremony := &fakeQRDBCeremony{
		calls: &calls,
		resp:  &quicbaassdk.QRDBCeremonyInitializeResponse{SPKIPin: "pin", State: "enrolling"},
	}
	issuer := &fakeAdminIssuer{calls: &calls, bundle: &AdminBundle{CertPEM: "CERT", KeyPEM: "KEY"}}
	b := NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: ceremony}, issuer)

	_, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{
		SOPIN:     "so",
		UserPIN:   "user",
		Threshold: "2-of-3",
		Officers: []daemon.CeremonyOfficer{
			{Username: "alice", CSRPEM: "csr-a"},
			{Username: "bob", CSRPEM: "csr-b"},
			{Username: "carol", CSRPEM: "csr-c"},
		},
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if ceremony.req.Threshold != 2 {
		t.Errorf("ceremony Threshold = %d, want the quorum 2", ceremony.req.Threshold)
	}
	if len(ceremony.req.Officers) != 3 {
		t.Fatalf("ceremony Officers = %d, want 3", len(ceremony.req.Officers))
	}
	if got := ceremony.req.Officers[1]; got.Username != "bob" || got.CSRPEM != "csr-b" {
		t.Errorf("officer 1 = %+v, want bob with csr-b", got)
	}
}

// TestCeremonyBackend_Initialize_SingleAdminSendsNoOfficers keeps a
// single-admin init on the ceremony's single-admin path: no threshold and no
// officer list.
func TestCeremonyBackend_Initialize_SingleAdminSendsNoOfficers(t *testing.T) {
	var calls []string
	ceremony := &fakeQRDBCeremony{calls: &calls, resp: &quicbaassdk.QRDBCeremonyInitializeResponse{SPKIPin: "pin"}}
	issuer := &fakeAdminIssuer{calls: &calls, bundle: &AdminBundle{CertPEM: "CERT", KeyPEM: "KEY"}}
	b := NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: ceremony}, issuer)

	if _, err := b.Initialize(context.Background(), &daemon.CeremonyInitRequest{SOPIN: "so", UserPIN: "user"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if ceremony.req.Threshold != 0 || ceremony.req.Officers != nil {
		t.Errorf("single-admin request carried threshold %d and officers %v", ceremony.req.Threshold, ceremony.req.Officers)
	}
}

func TestCeremonyBackend_ImplementsInterface(t *testing.T) {
	// Compile-time check is the real test; this asserts the pointer satisfies
	// the interface in a way that is visible to go vet.
	var _ daemon.CeremonyBackend = (*CeremonyBackend)(nil)
}
