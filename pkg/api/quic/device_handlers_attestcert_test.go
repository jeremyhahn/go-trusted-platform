// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

// createTestDeviceHandler and EncodePayload live behind the same constraint in
// device_handlers_test.go; without it the untagged lint compile of this
// package cannot see them.
//go:build codec_msgpack

package quic

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const testAttestCertPEM = "-----BEGIN CERTIFICATE-----\nenrolled-iak\n-----END CERTIFICATE-----\n"

func quicDeviceCall(t *testing.T, handler *DeviceHandler, opcode uint8, in interface{}, out interface{}) {
	t.Helper()
	payload, err := EncodePayload(in)
	require.NoError(t, err)
	resp := handler.HandleRequest(context.Background(), &Request{Opcode: opcode, Payload: payload})
	require.Equal(t, StatusOK, resp.Status, "payload: %s", string(resp.Payload))
	require.NoError(t, DecodePayload(resp.Payload, out))
}

// TestDeviceHandler_AttestCert_SurvivesUpdateWithoutIt is the QUIC round
// trip: register with a certificate, get, update without it, get again.
// This handler merges the update onto the stored record itself, so the
// preservation under test is the handler's own.
func TestDeviceHandler_AttestCert_SurvivesUpdateWithoutIt(t *testing.T) {
	handler, _, _ := createTestDeviceHandler()

	var registered DeviceRegisterResponse
	quicDeviceCall(t, handler, OpDeviceRegister, &DeviceRegisterRequest{
		Serial: "SN-404", Model: "X10SDV", AttestPub: "pub", AttestCert: testAttestCertPEM,
	}, &registered)
	require.NotNil(t, registered.Device)
	assert.Equal(t, testAttestCertPEM, registered.Device.AttestCert)
	id := registered.Device.ID

	var got DeviceGetResponse
	quicDeviceCall(t, handler, OpDeviceGet, &DeviceGetRequest{ID: id}, &got)
	assert.Equal(t, testAttestCertPEM, got.Device.AttestCert)

	var updated DeviceUpdateResponse
	quicDeviceCall(t, handler, OpDeviceUpdate, &DeviceUpdateRequest{ID: id, Model: "X10SDV-TP8F"}, &updated)
	assert.Equal(t, "X10SDV-TP8F", updated.Device.Model)
	assert.Equal(t, testAttestCertPEM, updated.Device.AttestCert)

	var again DeviceGetResponse
	quicDeviceCall(t, handler, OpDeviceGet, &DeviceGetRequest{ID: id}, &again)
	assert.Equal(t, testAttestCertPEM, again.Device.AttestCert, "an update that omits attest_cert must not erase it")
	assert.Equal(t, "pub", again.Device.AttestPub)
}

// TestDeviceHandler_AttestCert_UpdateReplaces proves a caller that does
// name the field still wins, mirroring attest_pub.
func TestDeviceHandler_AttestCert_UpdateReplaces(t *testing.T) {
	handler, service, _ := createTestDeviceHandler()
	service.devices[9] = &entities.Device{ID: 9, Serial: "SN-9", AttestCert: "old"}

	var updated DeviceUpdateResponse
	quicDeviceCall(t, handler, OpDeviceUpdate, &DeviceUpdateRequest{ID: 9, AttestCert: testAttestCertPEM}, &updated)
	assert.Equal(t, testAttestCertPEM, updated.Device.AttestCert)
	assert.Equal(t, testAttestCertPEM, service.devices[9].AttestCert)
}

// TestDeviceToInfo_CarriesAttestCert pins the serialiser used by every
// device reply.
func TestDeviceToInfo_CarriesAttestCert(t *testing.T) {
	handler, _, _ := createTestDeviceHandler()
	info := handler.deviceToInfo(&entities.Device{ID: 1, AttestCert: testAttestCertPEM})
	require.NotNil(t, info)
	assert.Equal(t, testAttestCertPEM, info.AttestCert)
	assert.Empty(t, handler.deviceToInfo(&entities.Device{ID: 2}).AttestCert)
}
