// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdksecrets "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

func TestQuicBaaSDial_RequiresTrust(t *testing.T) {
	dial := QuicBaaSDial(Config{QuicBaaSAddr: "127.0.0.1:1"}, nil)
	session, err := dial(context.Background())
	var want *ErrTrustRequired
	if !errors.As(err, &want) {
		t.Fatalf("got %v, want ErrTrustRequired", err)
	}
	if session != nil {
		t.Fatal("expected no session")
	}
}

func TestQuicBaaSDial_PropagatesTLSFailure(t *testing.T) {
	boom := errors.New("no trust anchor")
	dial := QuicBaaSDial(Config{QuicBaaSAddr: "127.0.0.1:1"}, func(context.Context, string) (*tls.Config, error) {
		return nil, boom
	})
	_, err := dial(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the TLS error", err)
	}
}

func TestQuicBaaSDial_BuildsAndClosesASession(t *testing.T) {
	var endpoint string
	dial := QuicBaaSDial(Config{QuicBaaSAddr: "127.0.0.1:1"}, func(_ context.Context, ep string) (*tls.Config, error) {
		endpoint = ep
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}, nil
	})
	session, err := dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if endpoint != "127.0.0.1:1" {
		t.Fatalf("TLS asked for endpoint %q", endpoint)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestQuicBaaSDial_RefusesABadAddress(t *testing.T) {
	dial := QuicBaaSDial(Config{QuicBaaSAddr: ""}, func(context.Context, string) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}, nil
	})
	if _, err := dial(context.Background()); err == nil {
		t.Fatal("expected an error for an empty address")
	}
}

// fakeSecretsClient records the path the session reads.
type fakeSecretsClient struct {
	sdksecrets.Client
	path string
}

func (f *fakeSecretsClient) Get(_ context.Context, path string, _ ...sdksecrets.GetOption) (*sdksecrets.Secret, error) {
	f.path = path
	return &sdksecrets.Secret{Path: path, Data: map[string]interface{}{"data": "v"}}, nil
}

func TestSDKSession_GetReadsThePath(t *testing.T) {
	fake := &fakeSecretsClient{}
	session := &sdkSession{secrets: fake}
	secret, err := session.Get(context.Background(), "a/b")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fake.path != "a/b" || secret.Path != "a/b" {
		t.Fatalf("read %q, want a/b", fake.path)
	}
}

// stubSecurity reports no secrets service.
type stubSecurity struct {
	quicbaassdk.SecurityService
}

func (stubSecurity) Secrets() sdksecrets.Client { return nil }

// stubClient is an SDK client whose security service has no secrets
// service, and which records that it was closed.
type stubClient struct {
	quicbaassdk.Client
	closed   bool
	closeErr error
}

func (c *stubClient) Security() quicbaassdk.SecurityService { return stubSecurity{} }

func (c *stubClient) Close() error {
	c.closed = true
	return c.closeErr
}

func TestNewSDKSession_RefusesAClientWithNoSecretsService(t *testing.T) {
	client := &stubClient{}
	session, err := newSDKSession(client)
	var want *ErrNilSecretsClient
	if !errors.As(err, &want) {
		t.Fatalf("got %v, want ErrNilSecretsClient", err)
	}
	if session != nil {
		t.Fatal("expected no session")
	}
	if !client.closed {
		t.Fatal("the connection must be closed when it cannot serve the store")
	}
}

func TestNewSDKSession_ReportsACloseFailureOnTheRefusalPath(t *testing.T) {
	client := &stubClient{closeErr: errors.New("close failed")}
	_, err := newSDKSession(client)
	var want *ErrStoreUnavailable
	if !errors.As(err, &want) {
		t.Fatalf("got %v, want ErrStoreUnavailable", err)
	}
}

// serverTLS is the anchor's shape: roots to verify the store by, no
// certificate of the caller's own.
func serverTLS(roots *x509.CertPool) TLSFunc {
	return func(context.Context, string) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, nil
	}
}

func TestWithClientIdentity_PresentsTheNodeCertificate(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	var served *tls.Config
	server := func(ctx context.Context, ep string) (*tls.Config, error) {
		cfg, err := serverTLS(bundle.CAPool)(ctx, ep)
		served = cfg
		return cfg, err
	}

	cfg, err := WithClientIdentity(server, bundle.ClientCert)(context.Background(), "127.0.0.1:1")
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	if len(cfg.Certificates) != 1 || !bytes.Equal(cfg.Certificates[0].Certificate[0], bundle.ClientCert.Certificate[0]) {
		t.Fatal("the session must present the node certificate")
	}
	if cfg.RootCAs != bundle.CAPool {
		t.Fatal("the session must keep verifying the store against the server roots")
	}
	if len(served.Certificates) != 0 {
		t.Fatal("the server config must be cloned, not modified")
	}
}

func TestWithClientIdentity_NilServerIsRefusedByTheDial(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	tlsFn := WithClientIdentity(nil, bundle.ClientCert)
	if tlsFn != nil {
		t.Fatal("no server verification must yield no TLSFunc")
	}
	var trustErr *ErrTrustRequired
	if _, err := QuicBaaSDial(Config{QuicBaaSAddr: "127.0.0.1:1"}, tlsFn)(context.Background()); !errors.As(err, &trustErr) {
		t.Fatalf("err = %v, want *ErrTrustRequired", err)
	}
}

func TestWithClientIdentity_RefusesAnEmptyIdentity(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	noKey := tls.Certificate{Certificate: bundle.ClientCert.Certificate}
	for name, identity := range map[string]tls.Certificate{
		"no certificate": {},
		"no private key": noKey,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := WithClientIdentity(serverTLS(bundle.CAPool), identity)(context.Background(), "127.0.0.1:1")
			var idErr *ErrClientIdentityRequired
			if !errors.As(err, &idErr) {
				t.Fatalf("err = %v, want *ErrClientIdentityRequired", err)
			}
		})
	}
}

func TestWithClientIdentity_PropagatesServerFailures(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	boom := errors.New("no trust anchor")
	failing := func(context.Context, string) (*tls.Config, error) { return nil, boom }
	if _, err := WithClientIdentity(failing, bundle.ClientCert)(context.Background(), "x"); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the server failure", err)
	}

	empty := func(context.Context, string) (*tls.Config, error) { return nil, nil }
	var trustErr *ErrTrustRequired
	if _, err := WithClientIdentity(empty, bundle.ClientCert)(context.Background(), "x"); !errors.As(err, &trustErr) {
		t.Fatalf("err = %v, want *ErrTrustRequired for a nil server config", err)
	}
}
