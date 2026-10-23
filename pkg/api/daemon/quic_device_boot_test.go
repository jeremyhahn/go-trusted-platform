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
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func newQUICBootHandler(t *testing.T, boot BootProvider) *QUICServiceHandler {
	t.Helper()
	// The middleware accepts no credential at all, so these requests reach
	// the boot service only through the pre-auth catalog, as a diskless node's do.
	handler, err := NewQUICServiceHandler(
		logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware()),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(newMockProfileService()),
	)
	require.NoError(t, err)
	handler.deviceGRPC.boot = boot
	return handler
}

// quicBootCtx is the context the QUIC server hands a handler for a request
// on a TLS 1.3 connection.
func quicBootCtx(t *testing.T) context.Context {
	t.Helper()
	return quic.WithConnectionTLS(context.Background(), &newBootNode(t).serverState)
}

func TestQUICDeviceBoot_RefusedWithoutAChannel(t *testing.T) {
	stub := &stubBoot{}
	handler := newQUICBootHandler(t, stub)
	tls12 := quic.WithConnectionTLS(context.Background(), &tls.ConnectionState{Version: tls.VersionTLS12})

	for _, sub := range []byte{quicwire.DeviceSubBootCertificate, quicwire.DeviceSubBootDelivery} {
		req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, sub, &platformv1.BootDeliveryRequest{})
		resp := handler.HandleRequest(tls12, req)
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "sub-opcode %#x", sub)
		assert.Contains(t, string(resp.Payload), "this QUIC request has none", "sub-opcode %#x", sub)
	}
	assert.Equal(t, restdevice.BootCertificateInput{}, stub.certIn, "the boot service was not called")
	assert.Equal(t, restdevice.BootDeliveryInput{}, stub.deliverIn, "the boot service was not called")
}

func TestQUICDeviceBootCertificate_Success(t *testing.T) {
	stub := &stubBoot{certResp: &provisioning.BootCertificateResponse{
		Identity:    "node-1.example",
		IDevIDChain: "chain",
	}}
	handler := newQUICBootHandler(t, stub)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubBootCertificate,
		&platformv1.BootCertificateRequest{Identity: "node-1.example", Signature: []byte("sig")})
	resp := handler.HandleRequest(quicBootCtx(t), req)

	var out platformv1.BootCertificateResponse
	decodeQUICResponse(t, resp, &out)
	assert.Equal(t, "node-1.example", out.GetIdentity())
	assert.Equal(t, "chain", out.GetIdevidChain())
	assert.Equal(t, "node-1.example", stub.certIn.Identity)
	assert.Equal(t, []byte("sig"), stub.certIn.Signature)
}

func TestQUICDeviceBootCertificate_BindsToTheQUICConnection(t *testing.T) {
	node := newBootNode(t)
	stub := &stubBoot{certResp: &provisioning.BootCertificateResponse{}}
	handler := newQUICBootHandler(t, stub)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubBootCertificate,
		&platformv1.BootCertificateRequest{Identity: "node-1.example"})
	resp := handler.HandleRequest(quic.WithConnectionTLS(context.Background(), &node.serverState), req)
	require.Equal(t, quicwire.StatusOK, resp.Status)

	want, err := provisioning.BootChannelNonce(&node.serverState)
	require.NoError(t, err)
	assert.Equal(t, want, stub.certIn.ChannelNonce)
}

func TestQUICDeviceBootDelivery_Success(t *testing.T) {
	stub := &stubBoot{delResp: &restdevice.BootDeliveryResponse{Serial: "SN-1"}}
	handler := newQUICBootHandler(t, stub)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubBootDelivery,
		&platformv1.BootDeliveryRequest{Evidence: []byte("evidence")})
	resp := handler.HandleRequest(quicBootCtx(t), req)

	var out platformv1.BootDeliveryResponse
	decodeQUICResponse(t, resp, &out)
	assert.Equal(t, "SN-1", out.GetSerial())
	assert.Equal(t, []byte("evidence"), stub.deliverIn.Evidence)
}

func TestQUICDeviceBoot_UnavailableWithoutAService(t *testing.T) {
	handler := newQUICBootHandler(t, nil)

	for _, sub := range []byte{quicwire.DeviceSubBootCertificate, quicwire.DeviceSubBootDelivery} {
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{sub},
		})
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "sub-opcode %#x", sub)
	}
}

func TestQUICDeviceBoot_MalformedPayload(t *testing.T) {
	handler := newQUICBootHandler(t, &stubBoot{})

	for _, sub := range []byte{quicwire.DeviceSubBootCertificate, quicwire.DeviceSubBootDelivery} {
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{sub, 0xff, 0xfe, 0xfd},
		})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "sub-opcode %#x", sub)
	}
}

func TestQUICDeviceBoot_RefusalIsMapped(t *testing.T) {
	stub := &stubBoot{err: restdevice.ErrBootIdentityRequired{}}
	handler := newQUICBootHandler(t, stub)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubBootDelivery,
		&platformv1.BootDeliveryRequest{})
	resp := handler.HandleRequest(quicBootCtx(t), req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestQUICDeviceBoot_RefusedIsPermissionDenied(t *testing.T) {
	stub := &stubBoot{err: restdevice.ErrBootRefused{Serial: "SN-1", Reason: "pcr mismatch"}}
	handler := newQUICBootHandler(t, stub)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubBootDelivery,
		&platformv1.BootDeliveryRequest{Evidence: []byte("evidence")})
	resp := handler.HandleRequest(quicBootCtx(t), req)

	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
}
