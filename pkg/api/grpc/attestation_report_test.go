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

package grpc

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestAttestationReportToProto_Success(t *testing.T) {
	ts := time.Now()
	report := &container.AttestationReport{
		ContainerID:   "test-id",
		ContainerName: "test-name",
		Timestamp:     ts,
		Verified:      true,
		ImageDigest:   []byte("image-digest"),
		ConfigDigest:  []byte("config-digest"),
		Quote:         []byte("quote"),
		Signature:     []byte("signature"),
		PCRValues: map[int][]byte{
			14: []byte("pcr-value"),
		},
		AIKCertificate: []byte("aik-cert"),
	}

	result := AttestationReportToProto(report, platformv1.PCRBank_PCR_BANK_SHA256)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.GetContainerId() != "test-id" {
		t.Errorf("unexpected container_id: %s", result.GetContainerId())
	}
	if result.GetContainerName() != "test-name" {
		t.Errorf("unexpected container_name: %s", result.GetContainerName())
	}
	if !result.GetVerified() {
		t.Error("expected verified=true")
	}
	if !result.GetStatus().GetSuccess() {
		t.Error("expected success status for verified report")
	}
	if string(result.GetQuote()) != "quote" {
		t.Errorf("unexpected quote: %s", result.GetQuote())
	}
	if string(result.GetSignature()) != "signature" {
		t.Errorf("unexpected signature: %s", result.GetSignature())
	}
	if string(result.GetImageDigest()) != "image-digest" {
		t.Errorf("unexpected image_digest: %s", result.GetImageDigest())
	}
	if string(result.GetConfigDigest()) != "config-digest" {
		t.Errorf("unexpected config_digest: %s", result.GetConfigDigest())
	}
	if string(result.GetAkPublic()) != "aik-cert" {
		t.Errorf("unexpected ak_public: %s", result.GetAkPublic())
	}
	if len(result.GetPcrValues()) != 1 {
		t.Fatalf("expected 1 PCR value, got: %d", len(result.GetPcrValues()))
	}
	if result.GetPcrValues()[0].GetIndex() != 14 {
		t.Errorf("unexpected PCR index: %d", result.GetPcrValues()[0].GetIndex())
	}
	if result.GetPcrValues()[0].GetBank() != platformv1.PCRBank_PCR_BANK_SHA256 {
		t.Errorf("unexpected PCR bank: %v", result.GetPcrValues()[0].GetBank())
	}
	if !result.GetTimestamp().AsTime().Equal(ts.UTC().Truncate(time.Nanosecond)) {
		t.Errorf("unexpected timestamp: %v", result.GetTimestamp().AsTime())
	}
}

func TestAttestationReportToProto_NotVerified(t *testing.T) {
	report := &container.AttestationReport{
		ContainerID: "test-id",
		Verified:    false,
		Timestamp:   time.Now(),
	}

	result := AttestationReportToProto(report, platformv1.PCRBank_PCR_BANK_UNSPECIFIED)
	if result.GetVerified() {
		t.Error("expected verified=false")
	}
	if result.GetStatus().GetSuccess() {
		t.Error("expected non-success status for unverified report")
	}
}

func TestAttestationReportToProto_Nil(t *testing.T) {
	result := AttestationReportToProto(nil, platformv1.PCRBank_PCR_BANK_SHA256)
	if result != nil {
		t.Error("expected nil result for nil report")
	}
}
