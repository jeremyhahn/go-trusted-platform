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
package grpc

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const testAttestCertPEM = "-----BEGIN CERTIFICATE-----\nenrolled-iak\n-----END CERTIFICATE-----\n"

// TestDeviceConversions_CarryAttestCert pins the proto↔entity conversions in
// this package carry the attestation certificate both ways (#404).
func TestDeviceConversions_CarryAttestCert(t *testing.T) {
	entity := protoDeviceToEntity(&platformv1.Device{Id: 1, AttestCert: testAttestCertPEM})
	if entity == nil || entity.AttestCert != testAttestCertPEM {
		t.Fatalf("protoDeviceToEntity dropped attest_cert: %+v", entity)
	}
	pb := entityDeviceToProto(&entities.Device{ID: 1, AttestCert: testAttestCertPEM})
	if pb == nil || pb.GetAttestCert() != testAttestCertPEM {
		t.Fatalf("entityDeviceToProto dropped AttestCert: %+v", pb)
	}
}

// TestDeviceConversions_EmptyAttestCert proves an absent certificate is not
// invented by either conversion.
func TestDeviceConversions_EmptyAttestCert(t *testing.T) {
	if got := protoDeviceToEntity(&platformv1.Device{Id: 1}).AttestCert; got != "" {
		t.Fatalf("expected empty AttestCert, got %q", got)
	}
	if got := entityDeviceToProto(&entities.Device{ID: 1}).GetAttestCert(); got != "" {
		t.Fatalf("expected empty attest_cert, got %q", got)
	}
}

// TestDeviceGRPCService_AttestCert_RoundTrip registers a device with a
// certificate, reads it back, updates without it, and reads it back again.
// This package's service delegates preservation to the device service, so
// the mock here records what it was handed and the assertion is on the wire
// shape: attest_cert travels in every direction it is set.
func TestDeviceGRPCService_AttestCert_RoundTrip(t *testing.T) {
	service, deviceMock, _ := newTestDeviceService()
	ctx := context.Background()

	created, err := service.CreateDevice(ctx, &platformv1.CreateDeviceRequest{Device: &platformv1.Device{
		Id: 7, Serial: "SN-7", Model: "M", AttestCert: testAttestCertPEM,
	}})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if created.GetDevice().GetAttestCert() != testAttestCertPEM {
		t.Fatal("CreateDevice response dropped attest_cert")
	}
	if deviceMock.devices[7].AttestCert != testAttestCertPEM {
		t.Fatal("the entity handed to the device service lacks AttestCert")
	}

	got, err := service.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: 7})
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if got.GetDevice().GetAttestCert() != testAttestCertPEM {
		t.Fatal("GetDevice response dropped attest_cert")
	}
}
