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
package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const testAttestCertPEM = "-----BEGIN CERTIFICATE-----\nenrolled-iak\n-----END CERTIFICATE-----\n"

// newRealDeviceService builds the production device service over the
// in-memory storage mock, so the round trip below exercises the service's
// server-owned-field preservation rather than a test double's.
func newRealDeviceService(t *testing.T) *device.Service {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	svc, err := device.NewService(device.NewDatastore(storage, logging.DefaultLogger()))
	require.NoError(t, err)
	return svc
}

// TestDeviceGRPCService_Conversions_CarryAttestCert pins that the pb↔entity
// conversions behind gRPC, Unix and QUIC carry the attestation certificate in
// both directions (#404).
func TestDeviceGRPCService_Conversions_CarryAttestCert(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)

	entity := svc.pbToDevice(&platformv1.Device{Id: 1, AttestPub: "pub", AttestCert: testAttestCertPEM})
	require.NotNil(t, entity)
	assert.Equal(t, testAttestCertPEM, entity.AttestCert)

	pb := svc.deviceToPb(&entities.Device{ID: 1, AttestPub: "pub", AttestCert: testAttestCertPEM})
	require.NotNil(t, pb)
	assert.Equal(t, testAttestCertPEM, pb.GetAttestCert())
}

// TestDeviceGRPCService_Conversions_EmptyAttestCert proves an absent
// certificate stays absent: the conversions never invent one.
func TestDeviceGRPCService_Conversions_EmptyAttestCert(t *testing.T) {
	svc := NewDeviceGRPCService(newMockDeviceService(), newMockProfileService(), nil)
	assert.Empty(t, svc.pbToDevice(&platformv1.Device{Id: 1}).AttestCert)
	assert.Empty(t, svc.deviceToPb(&entities.Device{ID: 1}).GetAttestCert())
}

// TestDeviceGRPCService_AttestCert_SurvivesUpdateWithoutIt is the transport
// round trip the issue asks for: register with a certificate, read it back,
// update without naming it, read it back again. The shared gRPC service is
// what Unix and QUIC dispatch to, so one round trip covers all three.
func TestDeviceGRPCService_AttestCert_SurvivesUpdateWithoutIt(t *testing.T) {
	ctx := context.Background()
	svc := NewDeviceGRPCService(newRealDeviceService(t), newMockProfileService(), nil)

	created, err := svc.CreateDevice(ctx, &platformv1.CreateDeviceRequest{Device: &platformv1.Device{
		Id: 4040, Serial: "SN-4040", Model: "X10SDV", AttestPub: "pub", AttestCert: testAttestCertPEM,
	}})
	require.NoError(t, err)
	assert.Equal(t, testAttestCertPEM, created.GetDevice().GetAttestCert())

	got, err := svc.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: 4040})
	require.NoError(t, err)
	assert.Equal(t, testAttestCertPEM, got.GetDevice().GetAttestCert(), "the certificate must be readable after registration")

	// A dashboard-shaped update names only the editable identity fields.
	updated, err := svc.UpdateDevice(ctx, &platformv1.UpdateDeviceRequest{Device: &platformv1.Device{
		Id: 4040, Serial: "SN-4040", Model: "X10SDV-TP8F",
	}})
	require.NoError(t, err)
	assert.Equal(t, "X10SDV-TP8F", updated.GetDevice().GetModel())
	assert.Equal(t, testAttestCertPEM, updated.GetDevice().GetAttestCert(), "the update response must report the preserved certificate")

	again, err := svc.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: 4040})
	require.NoError(t, err)
	assert.Equal(t, testAttestCertPEM, again.GetDevice().GetAttestCert(), "an update that omits attest_cert must not erase the trust anchor")
	assert.Equal(t, "pub", again.GetDevice().GetAttestPub())
}
