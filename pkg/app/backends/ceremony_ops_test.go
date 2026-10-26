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
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

var errUpstreamCeremony = errors.New("upstream ceremony failure")

// mgmtClient returns a caller-chosen BarrierCeremonyService, including none.
type mgmtClient struct {
	quicbaassdk.Client
	mgmt quicbaassdk.BarrierCeremonyService
}

func (c *mgmtClient) BarrierCeremonyMgmt() quicbaassdk.BarrierCeremonyService { return c.mgmt }

// resolvingMgmt returns a caller-chosen ceremony client and error.
type resolvingMgmt struct {
	quicbaassdk.BarrierCeremonyService
	ceremony quicbaassdk.QRDBCeremonyClient
	err      error
}

func (m *resolvingMgmt) Ceremony() (quicbaassdk.QRDBCeremonyClient, error) {
	return m.ceremony, m.err
}

// opsCeremony answers every delegated ceremony call with a fixed response,
// an error, or a nil response, and records the request it received.
type opsCeremony struct {
	quicbaassdk.QRDBCeremonyClient
	err     error
	nilResp bool
	got     any
}

func (c *opsCeremony) CeremonyStatus(_ context.Context) (*quicbaassdk.QRDBCeremonyStatusResponse, error) {
	if c.err != nil || c.nilResp {
		return nil, c.err
	}
	return &quicbaassdk.QRDBCeremonyStatusResponse{State: "completed", SPKIPin: "sha256/pin"}, nil
}

func (c *opsCeremony) CeremonyClaimCertBegin(_ context.Context, req *quicbaassdk.QRDBClaimCertBeginRequest) (*quicbaassdk.QRDBClaimCertBeginResponse, error) {
	c.got = req
	if c.err != nil || c.nilResp {
		return nil, c.err
	}
	return &quicbaassdk.QRDBClaimCertBeginResponse{NonceHex: "c0ffee", ExpiresAt: "2026-10-19T12:00:00.5Z"}, nil
}

func (c *opsCeremony) CeremonyClaimCertComplete(_ context.Context, req *quicbaassdk.QRDBClaimCertCompleteRequest) (*quicbaassdk.QRDBClaimCertCompleteResponse, error) {
	c.got = req
	if c.err != nil || c.nilResp {
		return nil, c.err
	}
	return &quicbaassdk.QRDBClaimCertCompleteResponse{CertPEM: "CERT", CACertPEM: "CA"}, nil
}

func (c *opsCeremony) CeremonyBeginClaimShare(_ context.Context, req *quicbaassdk.QRDBBeginClaimShareRequest) (*quicbaassdk.QRDBBeginClaimShareResponse, error) {
	c.got = req
	if c.err != nil || c.nilResp {
		return nil, c.err
	}
	return &quicbaassdk.QRDBBeginClaimShareResponse{NonceHex: "beef", ExpiresAt: "2026-10-19T13:00:00Z"}, nil
}

func (c *opsCeremony) CeremonyCompleteClaimShare(_ context.Context, req *quicbaassdk.QRDBCompleteClaimShareRequest) (*quicbaassdk.QRDBCompleteClaimShareResponse, error) {
	c.got = req
	if c.err != nil || c.nilResp {
		return nil, c.err
	}
	return &quicbaassdk.QRDBCompleteClaimShareResponse{ShareIndex: 3, ShareJSON: `{"share":"x"}`}, nil
}

func (c *opsCeremony) CeremonySignCSR(_ context.Context, req *quicbaassdk.QRDBSignCSRInitRequest) (*quicbaassdk.QRDBSignCSRInitResponse, error) {
	c.got = req
	if c.err != nil || c.nilResp {
		return nil, c.err
	}
	return &quicbaassdk.QRDBSignCSRInitResponse{CertPEM: "SIGNED"}, nil
}

func newOpsBackend(c *opsCeremony) *CeremonyBackend {
	return NewCeremonyBackend(logging.DefaultLogger(), &fakeQuicbaasClient{ceremony: c}, nil)
}

func TestCeremonyBackend_Status_MapsUpstreamStatus(t *testing.T) {
	got, err := newOpsBackend(&opsCeremony{}).Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	want := daemon.CeremonyStatusInfo{CeremonyID: "sha256/pin", State: daemon.CeremonyStateComplete}
	if *got != want {
		t.Fatalf("Status = %+v, want %+v", *got, want)
	}
}

func TestCeremonyBackend_ClaimCertBegin_ForwardsUsernameAndParsesExpiry(t *testing.T) {
	c := &opsCeremony{}
	got, err := newOpsBackend(c).ClaimCertBegin(context.Background(), &daemon.CeremonyClaimCertBeginRequest{Username: "alice"})
	if err != nil {
		t.Fatalf("ClaimCertBegin: %v", err)
	}
	if req := c.got.(*quicbaassdk.QRDBClaimCertBeginRequest); req.Username != "alice" {
		t.Fatalf("forwarded username = %q, want alice", req.Username)
	}
	want := daemon.CeremonyClaimCertBeginResult{
		Nonce:       "c0ffee",
		ChallengeID: "c0ffee",
		ExpiresAt:   time.Date(2026, 10, 19, 12, 0, 0, 500_000_000, time.UTC),
	}
	if *got != want {
		t.Fatalf("ClaimCertBegin = %+v, want %+v", *got, want)
	}
}

func TestCeremonyBackend_ClaimCertComplete_ForwardsChallenge(t *testing.T) {
	c := &opsCeremony{}
	got, err := newOpsBackend(c).ClaimCertComplete(context.Background(), &daemon.CeremonyClaimCertCompleteRequest{
		Username: "alice", Nonce: "c0ffee", Signature: "sig",
	})
	if err != nil {
		t.Fatalf("ClaimCertComplete: %v", err)
	}
	wantReq := quicbaassdk.QRDBClaimCertCompleteRequest{Username: "alice", NonceHex: "c0ffee", Signature: "sig"}
	if req := c.got.(*quicbaassdk.QRDBClaimCertCompleteRequest); *req != wantReq {
		t.Fatalf("forwarded request = %+v, want %+v", *req, wantReq)
	}
	want := daemon.CeremonyClaimCertCompleteResult{CertificatePEM: "CERT", ChainPEM: "CA"}
	if *got != want {
		t.Fatalf("ClaimCertComplete = %+v, want %+v", *got, want)
	}
}

func TestCeremonyBackend_ClaimShareBegin_ForwardsUsernameAndParsesExpiry(t *testing.T) {
	c := &opsCeremony{}
	got, err := newOpsBackend(c).ClaimShareBegin(context.Background(), &daemon.CeremonyClaimShareBeginRequest{Username: "bob"})
	if err != nil {
		t.Fatalf("ClaimShareBegin: %v", err)
	}
	if req := c.got.(*quicbaassdk.QRDBBeginClaimShareRequest); req.Username != "bob" {
		t.Fatalf("forwarded username = %q, want bob", req.Username)
	}
	want := daemon.CeremonyClaimShareBeginResult{
		Nonce:     "beef",
		ExpiresAt: time.Date(2026, 10, 19, 13, 0, 0, 0, time.UTC),
	}
	if *got != want {
		t.Fatalf("ClaimShareBegin = %+v, want %+v", *got, want)
	}
}

func TestCeremonyBackend_ClaimShareComplete_ReturnsShareAndIndex(t *testing.T) {
	c := &opsCeremony{}
	got, err := newOpsBackend(c).ClaimShareComplete(context.Background(), &daemon.CeremonyClaimShareCompleteRequest{
		Username: "bob", Nonce: "beef", Signature: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("ClaimShareComplete: %v", err)
	}
	req := c.got.(*quicbaassdk.QRDBCompleteClaimShareRequest)
	if req.Username != "bob" || req.NonceHex != "beef" || string(req.Signature) != "\x01\x02\x03" {
		t.Fatalf("forwarded request = %+v", *req)
	}
	want := daemon.CeremonyClaimShareResult{Share: `{"share":"x"}`, Index: 3}
	if *got != want {
		t.Fatalf("ClaimShareComplete = %+v, want %+v", *got, want)
	}
}

func TestCeremonyBackend_SignCSR_ForwardsRoleAndPIN(t *testing.T) {
	c := &opsCeremony{}
	got, err := newOpsBackend(c).SignCSR(context.Background(), &daemon.CeremonySignCSRRequest{
		Username: "carol", SOPIN: "so-pin", CSRPEM: "CSR", Role: daemon.CeremonyRoleAdmin,
	})
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	wantReq := quicbaassdk.QRDBSignCSRInitRequest{Username: "carol", SOPin: "so-pin", CSRPEM: "CSR", Role: "admin"}
	if req := c.got.(*quicbaassdk.QRDBSignCSRInitRequest); *req != wantReq {
		t.Fatalf("forwarded request = %+v, want %+v", *req, wantReq)
	}
	if got.CertificatePEM != "SIGNED" || got.ChainPEM != "" {
		t.Fatalf("SignCSR = %+v, want only CertificatePEM SIGNED", *got)
	}
}

// ceremonyOps runs each delegated operation against b, keeping only its error.
var ceremonyOps = map[string]func(b *CeremonyBackend) error{
	"Status": func(b *CeremonyBackend) error {
		_, err := b.Status(context.Background())
		return err
	},
	"ClaimCertBegin": func(b *CeremonyBackend) error {
		_, err := b.ClaimCertBegin(context.Background(), &daemon.CeremonyClaimCertBeginRequest{Username: "u"})
		return err
	},
	"ClaimCertComplete": func(b *CeremonyBackend) error {
		_, err := b.ClaimCertComplete(context.Background(), &daemon.CeremonyClaimCertCompleteRequest{Username: "u"})
		return err
	},
	"ClaimShareBegin": func(b *CeremonyBackend) error {
		_, err := b.ClaimShareBegin(context.Background(), &daemon.CeremonyClaimShareBeginRequest{Username: "u"})
		return err
	},
	"ClaimShareComplete": func(b *CeremonyBackend) error {
		_, err := b.ClaimShareComplete(context.Background(), &daemon.CeremonyClaimShareCompleteRequest{Username: "u"})
		return err
	},
	"SignCSR": func(b *CeremonyBackend) error {
		_, err := b.SignCSR(context.Background(), &daemon.CeremonySignCSRRequest{Username: "u"})
		return err
	},
}

func TestCeremonyBackend_Operations_PropagateUpstreamError(t *testing.T) {
	for name, op := range ceremonyOps {
		t.Run(name, func(t *testing.T) {
			err := op(newOpsBackend(&opsCeremony{err: errUpstreamCeremony}))
			if !errors.Is(err, errUpstreamCeremony) {
				t.Fatalf("err = %v, want the upstream error", err)
			}
		})
	}
}

func TestCeremonyBackend_Operations_NilResponseIsTransportUnavailable(t *testing.T) {
	for name, op := range ceremonyOps {
		t.Run(name, func(t *testing.T) {
			err := op(newOpsBackend(&opsCeremony{nilResp: true}))
			if !errors.Is(err, ErrCeremonyTransportUnavailable) {
				t.Fatalf("err = %v, want ErrCeremonyTransportUnavailable", err)
			}
		})
	}
}

func TestCeremonyBackend_TransportResolutionFailures(t *testing.T) {
	tests := []struct {
		name string
		mgmt quicbaassdk.BarrierCeremonyService
		want error
	}{
		{"no ceremony management service", nil, ErrCeremonyTransportUnavailable},
		{"management service fails", &resolvingMgmt{err: errUpstreamCeremony}, errUpstreamCeremony},
		{"management service returns no client", &resolvingMgmt{}, ErrCeremonyTransportUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCeremonyBackend(logging.DefaultLogger(), &mgmtClient{mgmt: tt.mgmt}, nil)
			for name, op := range ceremonyOps {
				if err := op(b); !errors.Is(err, tt.want) {
					t.Fatalf("%s err = %v, want %v", name, err, tt.want)
				}
			}
		})
	}
}

func TestCeremonyBackend_NilReceiverIsClientNil(t *testing.T) {
	var b *CeremonyBackend
	if _, err := b.Status(context.Background()); !errors.Is(err, ErrCeremonyBackendClientNil) {
		t.Fatalf("err = %v, want ErrCeremonyBackendClientNil", err)
	}
}

func TestParseExpiresAt(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want time.Time
	}{
		{"fractional seconds", "2026-10-19T12:00:00.123456789Z", time.Date(2026, 10, 19, 12, 0, 0, 123456789, time.UTC)},
		{"whole seconds", "2026-10-19T12:00:00Z", time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)},
		{"offset", "2026-10-19T14:00:00+02:00", time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)},
		{"empty", "", time.Time{}},
		{"not a timestamp", "tomorrow", time.Time{}},
		{"date only", "2026-10-19", time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseExpiresAt(tt.in); !got.Equal(tt.want) {
				t.Fatalf("parseExpiresAt(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestCeremonyAdminErrors(t *testing.T) {
	bundleErr := &ErrCeremonyAdminBundle{Cause: errUpstreamCeremony}
	tests := []struct {
		err  error
		want string
	}{
		{&ErrCeremonyAdminIssuerNil{}, "ceremony backend: no admin bundle issuer configured"},
		{bundleErr, "ceremony backend: issue admin bundle: upstream ceremony failure"},
		{&ErrAdminBundleIncomplete{}, "admin bundle is missing its certificate or key"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
	if !errors.Is(bundleErr, errUpstreamCeremony) {
		t.Fatal("ErrCeremonyAdminBundle does not unwrap to its cause")
	}
}
