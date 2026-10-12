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

package device

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdevice "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// errBindingCaptured stops a call once its connection's binding is recorded.
var errBindingCaptured = errors.New("binding captured")

// dialBootREST opens a new SDK REST connection to the control plane as the
// enrolled node.
func (f *bootFixture) dialBootREST(t *testing.T, serverURL string) *sdkdevice.Client {
	t.Helper()
	adapter, err := sdkrest.Connect(context.Background(), &platform.Options{
		RESTAddr: serverURL,
		TLSConfig: &tls.Config{
			RootCAs:      f.serverRoots,
			Certificates: []tls.Certificate{{Certificate: [][]byte{f.pki.leaf.Raw}, PrivateKey: f.pki.leafKey}},
			MinVersion:   tls.VersionTLS13,
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
	return sdkdevice.NewClientFromGRPC(platformv1.NewDeviceServiceClient(adapter.Connection()))
}

func (f *bootFixture) signOver(_ context.Context, binding []byte) ([]byte, error) {
	return provisioning.SignBootCertificateProof(f.pki.leafKey, "node-1.example", binding)
}

// otherRESTBinding is the binding of a fresh REST connection, recorded by a
// call that stops before anything is sent.
func (f *bootFixture) otherRESTBinding(t *testing.T, serverURL string) []byte {
	t.Helper()
	var captured []byte
	_, err := f.dialBootREST(t, serverURL).BootCertificate(context.Background(), "node-1.example", func(_ context.Context, binding []byte) ([]byte, error) {
		captured = bytes.Clone(binding)
		return nil, errBindingCaptured
	})
	require.ErrorIs(t, err, errBindingCaptured)
	require.Len(t, captured, provisioning.BootChannelNonceSize)
	return captured
}

// The SDK's REST transport makes each proof on the connection that carries
// it; the real handler and boot service accept that proof and refuse one
// made for another connection.
func TestBootHandler_SDKProofsAreMadeOnTheLiveRESTConnection(t *testing.T) {
	f := newBootFixture(t)
	server := startBootControlPlane(t, f)

	t.Run("certificate proof made on the live connection is accepted", func(t *testing.T) {
		resp, err := f.dialBootREST(t, server.URL).BootCertificate(context.Background(), "node-1.example", f.signOver)
		require.NoError(t, err)
		assert.Equal(t, f.pki.chainPEM, resp.GetIdevidChain())
	})
	t.Run("certificate proof made for another connection is refused", func(t *testing.T) {
		other := f.otherRESTBinding(t, server.URL)
		_, err := f.dialBootREST(t, server.URL).BootCertificate(context.Background(), "node-1.example", func(ctx context.Context, _ []byte) ([]byte, error) {
			return f.signOver(ctx, other)
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
	})
	t.Run("delivery quote made on the live connection is accepted", func(t *testing.T) {
		resp, err := f.dialBootREST(t, server.URL).BootDelivery(context.Background(), func(_ context.Context, binding []byte) ([]byte, error) {
			return bootEvidence(t, binding), nil
		})
		require.NoError(t, err)
		assert.Equal(t, "SN-42", resp.GetSerial())
	})
	t.Run("delivery quote made for another connection is refused", func(t *testing.T) {
		other := f.otherRESTBinding(t, server.URL)
		f.attestor.gotEvidence = nil
		_, err := f.dialBootREST(t, server.URL).BootDelivery(context.Background(), func(context.Context, []byte) ([]byte, error) {
			return bootEvidence(t, other), nil
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
		assert.Nil(t, f.attestor.gotEvidence, "a quote for another connection never reaches the verifier")
	})
}
