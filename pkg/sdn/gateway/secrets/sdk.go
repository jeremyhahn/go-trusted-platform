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

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdksecrets "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/sdkclient"
)

// TLSFunc produces the TLS configuration the store session is dialled
// with. gatewayd supplies its platform anchor, which anchors verification
// of the STORE: the returned config carries the platform CA as its root
// pool, so the gateway talks to a peer the platform vouches for and to no
// one else. WithClientIdentity adds the gateway's side: the provisioned
// node certificate the store authenticates the caller by (#658).
type TLSFunc func(ctx context.Context, endpoint string) (*tls.Config, error)

// WithClientIdentity returns a TLSFunc that dials with server's
// verification config and presents identity as the client certificate, so
// the store session is mutually authenticated: the gateway verifies the
// store against server's roots, and a store that requires a client
// certificate (quicbaasd's ClientAuth) learns which node is reading.
//
// A nil server yields a nil TLSFunc, which QuicBaaSDial refuses with
// ErrTrustRequired. An identity without a certificate or private key is
// refused at dial time with ErrClientIdentityRequired rather than dialled
// one-way. The config server returns is cloned, never modified.
func WithClientIdentity(server TLSFunc, identity tls.Certificate) TLSFunc {
	if server == nil {
		return nil
	}
	return func(ctx context.Context, endpoint string) (*tls.Config, error) {
		if len(identity.Certificate) == 0 || identity.PrivateKey == nil {
			return nil, &ErrClientIdentityRequired{}
		}
		serverCfg, err := server(ctx, endpoint)
		if err != nil {
			return nil, err
		}
		if serverCfg == nil {
			return nil, &ErrTrustRequired{}
		}
		tlsCfg := serverCfg.Clone()
		tlsCfg.Certificates = []tls.Certificate{identity}
		return tlsCfg, nil
	}
}

// QuicBaaSDial returns the production DialFunc: a go-quicbaas SDK client to
// quicbaasd at cfg.QuicBaaSAddr, authenticated by tlsFn. A nil tlsFn is
// refused at dial time with ErrTrustRequired — the SDK does not open
// unauthenticated connections, and the store must not try.
func QuicBaaSDial(cfg Config, tlsFn TLSFunc) DialFunc {
	return func(ctx context.Context) (Session, error) {
		if tlsFn == nil {
			return nil, &ErrTrustRequired{}
		}
		tlsCfg, err := tlsFn(ctx, cfg.QuicBaaSAddr)
		if err != nil {
			return nil, err
		}
		client, err := sdkclient.Dial(cfg.QuicBaaSAddr, cfg.QuicBaaSTransport, tlsCfg)
		if err != nil {
			return nil, err
		}
		return newSDKSession(client)
	}
}

// newSDKSession wraps a connected SDK client as a Session. A client
// carrying no secrets service has nothing to read references from, so the
// connection is closed and the dial fails rather than handing back a
// session that panics on first use.
func newSDKSession(client quicbaassdk.Client) (Session, error) {
	secretsClient := client.Security().Secrets()
	if secretsClient == nil {
		if cerr := client.Close(); cerr != nil {
			return nil, &ErrStoreUnavailable{Cause: cerr}
		}
		return nil, &ErrNilSecretsClient{}
	}
	return &sdkSession{client: client, secrets: secretsClient}, nil
}

// sdkSession is the production Session over a go-quicbaas SDK client.
type sdkSession struct {
	client  quicbaassdk.Client
	secrets sdksecrets.Client
}

func (s *sdkSession) Get(ctx context.Context, path string) (*sdksecrets.Secret, error) {
	return s.secrets.Get(ctx, path)
}

func (s *sdkSession) Close() error { return s.client.Close() }
