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

package channelbind

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

func TestQualifyingData_BindsTheNonceToTheConnection(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	state := testutil.ServerConnectionState(t)

	got, err := QualifyingData(state, "REST", nonce)
	require.NoError(t, err)

	binding, err := state.ExportKeyingMaterial(xkmssdk.PeerChannelBindingExporterLabel, nil, xkmssdk.PeerChannelBindingLength)
	require.NoError(t, err)
	assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), got)
	assert.NotEqual(t, nonce, got, "the bare nonce must never be what is quoted")
}

func TestQualifyingData_DiffersPerConnection(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")

	first, err := QualifyingData(testutil.ServerConnectionState(t), "REST", nonce)
	require.NoError(t, err)
	second, err := QualifyingData(testutil.ServerConnectionState(t), "REST", nonce)
	require.NoError(t, err)

	assert.NotEqual(t, first, second,
		"the same nonce over a second connection must yield a different value, or a relay passes")
}

func TestQualifyingData_RefusesAConnectionWithNoBinding(t *testing.T) {
	cases := map[string]*tls.ConnectionState{
		"no TLS":                 nil,
		"handshake not complete": {Version: tls.VersionTLS12},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := QualifyingData(state, "Unix", []byte("0123456789abcdef"))
			require.Error(t, err)
			assert.Nil(t, got)

			var required ErrChannelBindingRequired
			require.ErrorAs(t, err, &required)
			assert.Equal(t, "Unix", required.Transport)
			assert.Error(t, errors.Unwrap(err), "the exporter's refusal is kept as the cause")
			assert.Contains(t, err.Error(), "Unix")
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		})
	}
}

func TestBind_ReturnsTheBindingAndWhatToQuote(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	state := testutil.ServerConnectionState(t)

	bound, err := Bind(state, "gRPC", nonce)
	require.NoError(t, err)

	binding, err := xkmssdk.PeerChannelBinding(state)
	require.NoError(t, err)
	assert.Equal(t, binding, bound.Binding, "the caller compares this with its own end's exporter")
	assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), bound.QualifyingData)
}

func TestBind_RefusesAConnectionWithNoBinding(t *testing.T) {
	bound, err := Bind(nil, "MCP", []byte("0123456789abcdef"))

	var required ErrChannelBindingRequired
	require.ErrorAs(t, err, &required)
	assert.Equal(t, "MCP", required.Transport)
	assert.Empty(t, bound.Binding)
	assert.Empty(t, bound.QualifyingData, "nothing is handed back to quote")
}

func TestExpectedQualifyingData_BindsWhenABindingIsGiven(t *testing.T) {
	nonce := []byte("0123456789abcdef")
	binding := []byte("0123456789abcdef0123456789abcdef")

	bound, err := ExpectedQualifyingData(nonce, binding)
	require.NoError(t, err)
	assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), bound)

	bare, err := ExpectedQualifyingData(nonce, nil)
	require.NoError(t, err)
	assert.Equal(t, nonce, bare, "with no binding the quote carries the nonce itself")
}

func TestExpectedQualifyingData_RefusesABindingWithoutANonce(t *testing.T) {
	got, err := ExpectedQualifyingData(nil, []byte("binding"))

	require.ErrorAs(t, err, &ErrBindingWithoutNonce{})
	assert.Nil(t, got)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestConnectionTLS_ReturnsTheRecordedState(t *testing.T) {
	state := testutil.ServerConnectionState(t)

	got, transport, ok := ConnectionTLS(WithConnectionTLS(context.Background(), "MCP", state))

	assert.True(t, ok)
	assert.Same(t, state, got)
	assert.Equal(t, "MCP", transport)
}

func TestConnectionTLS_TellsPlainHTTPFromUnrecorded(t *testing.T) {
	got, _, ok := ConnectionTLS(context.Background())
	assert.False(t, ok, "nothing recorded")
	assert.Nil(t, got)

	got, transport, ok := ConnectionTLS(WithConnectionTLS(context.Background(), "REST", nil))
	assert.True(t, ok, "a request recorded without TLS is still recorded")
	assert.Nil(t, got)
	assert.Equal(t, "REST", transport)
}
