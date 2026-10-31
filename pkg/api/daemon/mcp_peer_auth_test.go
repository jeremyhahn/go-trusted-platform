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

package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// Under mTLS the MCP transport admits the operator certificate as REST, gRPC
// and QUIC do: the principal of the certificate's tenant holding the operator
// grant. A certificate from another CA authenticates nobody.
func TestNewMCPPeerAuthenticator_MTLS_AdmitsTheOperatorCertificate(t *testing.T) {
	t.Parallel()
	trusted := testutil.GenerateTestTLSBundle(t)
	foreign := testutil.GenerateTestTLSBundle(t)
	config := failClosedConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = trusted.CAPool

	peers, err := newMCPPeerAuthenticator(config, nil, logging.DefaultLogger())
	require.NoError(t, err)
	require.NotNil(t, peers)

	leaf := leafOf(t, trusted.ClientCert)
	authCtx, err := peers.AuthenticatePeer(context.Background(), []*x509.Certificate{leaf, trusted.CACert})
	require.NoError(t, err)
	require.NotEmpty(t, leaf.Subject.Organization)
	assert.Equal(t, leaf.Subject.Organization[0], authCtx.TenantID, "the tenant is the certificate's")
	assert.Equal(t, []string{mtlsOperatorScope}, authCtx.Scopes)

	_, err = peers.AuthenticatePeer(context.Background(), []*x509.Certificate{leafOf(t, foreign.ClientCert)})
	assert.Error(t, err, "a certificate from another CA is not the operator")
}

// Without mTLS there is no certificate to authenticate: only bearer tokens do.
func TestNewMCPPeerAuthenticator_NoMTLS_ReturnsNil(t *testing.T) {
	t.Parallel()
	peers, err := newMCPPeerAuthenticator(failClosedConfig(), nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.Nil(t, peers)
}

func TestNewMCPPeerAuthenticator_MTLSWithoutClientCAPool_ReturnsTypedError(t *testing.T) {
	t.Parallel()
	config := failClosedConfig()
	config.EnableMTLS = true

	peers, err := newMCPPeerAuthenticator(config, nil, logging.DefaultLogger())
	require.Error(t, err)
	assert.Nil(t, peers)
	var want ErrTransportAuthRequired
	require.True(t, errors.As(err, &want), "error is %T, want ErrTransportAuthRequired", err)
	assert.Equal(t, transportMCP, want.Transport)
}
