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
// with. gatewayd supplies its trust resolver's internal class, which
// anchors verification of the STORE: the returned config carries the
// platform CA as its root pool, so the gateway talks to a peer the
// platform vouches for and to no one else.
//
// It does NOT carry a client certificate — the trust resolver is a
// server-verification resolver and returns no Certificates — so the
// session is one-way authenticated. Which credential should identify the
// gateway TO the store (its provisioned mTLS identity, or an IAM token)
// is an open question tracked as #658; quicbaasd's gRPC client-certificate
// requirement is operator-configured (ClientAuth, off by default), so a
// store that requires one refuses this session today rather than serving
// it to an unidentified caller.
type TLSFunc func(ctx context.Context, endpoint string) (*tls.Config, error)

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
