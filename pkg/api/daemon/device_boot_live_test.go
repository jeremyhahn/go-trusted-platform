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

package daemon

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdevice "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	sdkquic "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	sdkunix "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// These tests boot a diskless node through the SDK against real listeners:
// the proof and the quote are made by the callback on the connection the
// call travels on, and the real boot service checks them against that
// connection's exporter.

const liveBootDeviceID = 42

// errBindingCaptured stops a call once its connection's binding is recorded.
var errBindingCaptured = errors.New("binding captured")

// liveBootAttestor answers for the enrolled node the way the shared
// verifier does once its quote verifies.
type liveBootAttestor struct{}

func (liveBootAttestor) AttestDevice(context.Context, *platformv1.AttestDeviceRequest) (*platformv1.AttestDeviceResponse, error) {
	return &platformv1.AttestDeviceResponse{DeviceId: liveBootDeviceID, Verified: true}, nil
}

// newLiveBootService is the real boot service with pki's client leaf
// recorded as the IDevID of the node named gateNodeName.
func newLiveBootService(t *testing.T, pki gatePKI) *restdevice.BootService {
	t.Helper()
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.client.Certificate[0]})
	boot := restdevice.NewBootService(
		bootDevices{dev: &entities.Device{
			ID:         liveBootDeviceID,
			Serial:     "SN-42",
			Hostname:   gateNodeName,
			IDevIDCert: string(append(chain, pki.caPEM...)),
		}},
		bootFinder{},
		liveBootAttestor{},
		bootCA{pem: pki.caPEM},
	)
	require.NotNil(t, boot)
	return boot
}

// liveNodeTLS is the node's side of the connection: it trusts the control
// plane and presents its IDevID.
func liveNodeTLS(pki gatePKI) *tls.Config {
	return &tls.Config{
		RootCAs:      pki.pool,
		Certificates: []tls.Certificate{pki.client},
		MinVersion:   tls.VersionTLS13,
	}
}

// liveDial opens a new SDK connection to the listener under test.
type liveDial func(t *testing.T) *sdkdevice.Client

func dialLiveGRPC(pki gatePKI, addr string) liveDial {
	return func(t *testing.T) *sdkdevice.Client {
		t.Helper()
		adapter, err := sdkgrpc.Connect(context.Background(), &platform.Options{GRPCAddr: addr, TLSConfig: liveNodeTLS(pki)})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
		return sdkdevice.NewClientFromGRPC(platformv1.NewDeviceServiceClient(adapter.Connection()))
	}
}

func dialLiveQUIC(pki gatePKI, addr string) liveDial {
	return func(t *testing.T) *sdkdevice.Client {
		t.Helper()
		adapter, err := sdkquic.Connect(context.Background(), &platform.Options{QUICAddr: addr, TLSConfig: liveNodeTLS(pki)})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
		return sdkdevice.NewClientFromGRPC(platformv1.NewDeviceServiceClient(adapter.Connection()))
	}
}

// serveLiveQUIC serves the boot service on a real QUIC listener configured
// the way platformd configures it.
func serveLiveQUIC(t *testing.T, pki gatePKI, boot BootProvider) string {
	t.Helper()
	reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := reserved.LocalAddr().String()
	require.NoError(t, reserved.Close())

	handler := newQUICBootHandler(t, boot)
	config := quic.DefaultServerConfig()
	config.ListenAddr = addr
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		NextProtos:   []string{quicwire.ALPNProtocol},
		MinVersion:   tls.VersionTLS13,
	}
	// The daemon's own QUIC mTLS step, so this test breaks if the listener
	// goes back to requiring a client certificate at the handshake.
	daemonConfig := DefaultConfig()
	daemonConfig.EnableMTLS = true
	daemonConfig.MTLSClientCAPool = pki.pool
	require.NoError(t, quicServerMTLS(daemonConfig, config.TLSConfig, handler, logging.DefaultLogger()))
	server, err := quic.NewServer(config, quic.WithHandler(handler))
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(func() { assert.NoError(t, server.Stop()) })
	return addr
}

// signLive signs the boot-certificate proof over whatever binding it is
// handed, as the CLI's --key callback does.
func signLive(pki gatePKI) sdkdevice.BootProofFunc {
	return func(_ context.Context, binding []byte) ([]byte, error) {
		return provisioning.SignBootCertificateProof(pki.client.PrivateKey.(crypto.Signer), gateNodeName, binding)
	}
}

// quoteLive returns quote evidence over whatever binding it is handed, as
// the CLI's --quote-command callback does.
func quoteLive(_ context.Context, binding []byte) ([]byte, error) {
	return json.Marshal(vm.QuoteEvidence{Quote: []byte("quote"), Signature: []byte("sig"), Nonce: binding})
}

// otherConnectionBinding is the binding of a fresh connection, recorded by
// a call that stops before anything is sent.
func otherConnectionBinding(t *testing.T, dial liveDial) []byte {
	t.Helper()
	var captured []byte
	_, err := dial(t).BootCertificate(context.Background(), gateNodeName, func(_ context.Context, binding []byte) ([]byte, error) {
		captured = bytes.Clone(binding)
		return nil, errBindingCaptured
	})
	require.ErrorIs(t, err, errBindingCaptured)
	require.Len(t, captured, provisioning.BootChannelNonceSize)
	return captured
}

// assertLiveBoot runs both boot calls over dial: each is accepted with a
// proof made on its own connection and refused with one made for another.
func assertLiveBoot(t *testing.T, pki gatePKI, dial liveDial) {
	t.Run("certificate proof made on the live connection is accepted", func(t *testing.T) {
		resp, err := dial(t).BootCertificate(context.Background(), gateNodeName, signLive(pki))
		require.NoError(t, err)
		assert.Equal(t, gateNodeName, resp.GetIdentity())
		assert.Contains(t, resp.GetIdevidChain(), "BEGIN CERTIFICATE")
	})
	t.Run("certificate proof made for another connection is refused", func(t *testing.T) {
		other := otherConnectionBinding(t, dial)
		_, err := dial(t).BootCertificate(context.Background(), gateNodeName, func(ctx context.Context, binding []byte) ([]byte, error) {
			require.NotEqual(t, other, binding, "two connections never share a binding")
			return signLive(pki)(ctx, other)
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
	})
	t.Run("delivery quote made on the live connection is accepted", func(t *testing.T) {
		resp, err := dial(t).BootDelivery(context.Background(), quoteLive)
		require.NoError(t, err)
		assert.Equal(t, "SN-42", resp.GetSerial())
		assert.Equal(t, string(pki.caPEM), resp.GetCaBundle())
	})
	t.Run("delivery quote made for another connection is refused", func(t *testing.T) {
		other := otherConnectionBinding(t, dial)
		_, err := dial(t).BootDelivery(context.Background(), func(ctx context.Context, _ []byte) ([]byte, error) {
			return quoteLive(ctx, other)
		})
		assert.Equal(t, codes.PermissionDenied, status.Code(err), "err = %v", err)
	})
}

func TestDeviceBootLive_GRPC(t *testing.T) {
	pki := newGatePKI(t)
	addr := serveDeviceGated(t, pki, newBootGRPC(newLiveBootService(t, pki)))

	assertLiveBoot(t, pki, dialLiveGRPC(pki, addr))
}

func TestDeviceBootLive_QUIC(t *testing.T) {
	pki := newGatePKI(t)
	addr := serveLiveQUIC(t, pki, newLiveBootService(t, pki))

	assertLiveBoot(t, pki, dialLiveQUIC(pki, addr))

	// A booting device has no client certificate yet: the handshake must
	// admit it, and only BootCertificate may run on that connection.
	t.Run("device without a client certificate", func(t *testing.T) {
		adapter, err := sdkquic.Connect(context.Background(), &platform.Options{
			QUICAddr:  addr,
			TLSConfig: &tls.Config{RootCAs: pki.pool, MinVersion: tls.VersionTLS13},
		})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
		anon := sdkdevice.NewClientFromGRPC(platformv1.NewDeviceServiceClient(adapter.Connection()))

		resp, err := anon.BootCertificate(context.Background(), gateNodeName, signLive(pki))
		require.NoError(t, err)
		assert.Equal(t, gateNodeName, resp.GetIdentity())

		_, err = anon.BootDelivery(context.Background(), quoteLive)
		assert.Equal(t, codes.Unauthenticated, status.Code(err), "err = %v", err)
	})
}

// A Unix socket has no TLS connection, so there is nothing to bind a proof
// to: the SDK refuses with a typed error before sending, and a client that
// sends anyway is refused by the daemon before the boot service is called.
func TestDeviceBootLive_UnixIsRefused(t *testing.T) {
	dir, err := os.MkdirTemp("", "boot")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	stub := &stubBoot{}
	srv := grpc.NewServer()
	platformv1.RegisterDeviceServiceServer(srv, newBootGRPC(stub))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	t.Run("the SDK refuses before sending", func(t *testing.T) {
		adapter, err := sdkunix.Connect(context.Background(), &platform.Options{UnixSocket: socket})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
		client := sdkdevice.NewClientFromGRPC(platformv1.NewDeviceServiceClient(adapter.Connection()))
		called := false
		proof := func(context.Context, []byte) ([]byte, error) {
			called = true
			return nil, nil
		}

		_, certErr := client.BootCertificate(context.Background(), gateNodeName, proof)
		_, deliveryErr := client.BootDelivery(context.Background(), proof)

		for _, err := range []error{certErr, deliveryErr} {
			var unavailable *transport.ErrChannelBindingUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, platform.ProtocolUnix.String(), unavailable.Transport)
		}
		assert.False(t, called, "no proof is made where there is no connection to bind it to")
	})
	t.Run("the daemon refuses a call that bypasses the SDK", func(t *testing.T) {
		adapter, err := sdkunix.Connect(context.Background(), &platform.Options{UnixSocket: socket})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
		raw := platformv1.NewDeviceServiceClient(adapter.Connection())

		_, certErr := raw.BootCertificate(context.Background(), &platformv1.BootCertificateRequest{Identity: gateNodeName, Signature: []byte("sig")})
		_, deliveryErr := raw.BootDelivery(context.Background(), &platformv1.BootDeliveryRequest{Evidence: []byte("evidence")})

		assert.Equal(t, codes.FailedPrecondition, status.Code(certErr), "err = %v", certErr)
		assert.Equal(t, codes.FailedPrecondition, status.Code(deliveryErr), "err = %v", deliveryErr)
		assert.Equal(t, restdevice.BootCertificateInput{}, stub.certIn, "the boot service was not called")
		assert.Equal(t, restdevice.BootDeliveryInput{}, stub.deliverIn, "the boot service was not called")
	})
}
