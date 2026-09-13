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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdksecrets "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
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
