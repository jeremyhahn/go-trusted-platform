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

package entities

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestBMCEnrollment_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := &BMCEnrollment{
		EnrolledAt:        now,
		PinSPKISHA256:     strings.Repeat("ab", 32),
		CertSerial:        "12345678901234567890",
		CertNotAfter:      now.Add(90 * 24 * time.Hour),
		DNSName:           "lab-node-1-bmc.internal.",
		TLSAPublished:     true,
		FactoryCertSHA256: strings.Repeat("cd", 32),
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded BMCEnrollment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !decoded.EnrolledAt.Equal(orig.EnrolledAt) {
		t.Errorf("EnrolledAt: got %v, want %v", decoded.EnrolledAt, orig.EnrolledAt)
	}
	if decoded.PinSPKISHA256 != orig.PinSPKISHA256 {
		t.Errorf("PinSPKISHA256 = %q, want %q", decoded.PinSPKISHA256, orig.PinSPKISHA256)
	}
	if decoded.CertSerial != orig.CertSerial {
		t.Errorf("CertSerial = %q, want %q", decoded.CertSerial, orig.CertSerial)
	}
	if !decoded.CertNotAfter.Equal(orig.CertNotAfter) {
		t.Errorf("CertNotAfter: got %v, want %v", decoded.CertNotAfter, orig.CertNotAfter)
	}
	if decoded.DNSName != orig.DNSName {
		t.Errorf("DNSName = %q, want %q", decoded.DNSName, orig.DNSName)
	}
	if decoded.TLSAPublished != orig.TLSAPublished {
		t.Errorf("TLSAPublished = %v, want %v", decoded.TLSAPublished, orig.TLSAPublished)
	}
	if decoded.FactoryCertSHA256 != orig.FactoryCertSHA256 {
		t.Errorf("FactoryCertSHA256 = %q, want %q", decoded.FactoryCertSHA256, orig.FactoryCertSHA256)
	}
}

func TestBMCEnrollment_YAMLRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := &BMCEnrollment{
		EnrolledAt:        now,
		PinSPKISHA256:     strings.Repeat("ef", 32),
		CertSerial:        "9876",
		CertNotAfter:      now.Add(30 * 24 * time.Hour),
		DNSName:           "lab-node-2-bmc.internal.",
		TLSAPublished:     false,
		FactoryCertSHA256: strings.Repeat("12", 32),
	}

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var decoded BMCEnrollment
	if err := yaml.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	if !decoded.EnrolledAt.Equal(orig.EnrolledAt) {
		t.Errorf("EnrolledAt: got %v, want %v", decoded.EnrolledAt, orig.EnrolledAt)
	}
	if decoded.PinSPKISHA256 != orig.PinSPKISHA256 {
		t.Errorf("PinSPKISHA256 = %q", decoded.PinSPKISHA256)
	}
	if decoded.CertSerial != orig.CertSerial {
		t.Errorf("CertSerial = %q", decoded.CertSerial)
	}
	if decoded.DNSName != orig.DNSName {
		t.Errorf("DNSName = %q", decoded.DNSName)
	}
	if decoded.TLSAPublished != orig.TLSAPublished {
		t.Errorf("TLSAPublished = %v", decoded.TLSAPublished)
	}
	if decoded.FactoryCertSHA256 != orig.FactoryCertSHA256 {
		t.Errorf("FactoryCertSHA256 = %q", decoded.FactoryCertSHA256)
	}
}

func TestDevice_BMCEnrollmentField(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	enroll := &BMCEnrollment{
		EnrolledAt:        now,
		PinSPKISHA256:     strings.Repeat("ab", 32),
		CertSerial:        "42",
		CertNotAfter:      now.Add(90 * 24 * time.Hour),
		DNSName:           "lab-node-3-bmc.internal.",
		TLSAPublished:     true,
		FactoryCertSHA256: strings.Repeat("ff", 32),
	}
	dev := &Device{
		ID:            1,
		BMCEnrollment: enroll,
	}

	data, err := json.Marshal(dev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded Device
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if decoded.BMCEnrollment == nil {
		t.Fatal("BMCEnrollment is nil after round-trip")
	}
	if decoded.BMCEnrollment.PinSPKISHA256 != enroll.PinSPKISHA256 {
		t.Errorf("PinSPKISHA256 = %q, want %q", decoded.BMCEnrollment.PinSPKISHA256, enroll.PinSPKISHA256)
	}
	if decoded.BMCEnrollment.DNSName != enroll.DNSName {
		t.Errorf("DNSName = %q, want %q", decoded.BMCEnrollment.DNSName, enroll.DNSName)
	}
}

func TestDevice_NilBMCEnrollment_RoundTrip(t *testing.T) {
	dev := &Device{
		ID:            2,
		BMCEnrollment: nil,
	}

	data, err := json.Marshal(dev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(data), "bmc_enrollment") {
		t.Error("nil BMCEnrollment should be omitted from JSON")
	}

	var decoded Device
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if decoded.BMCEnrollment != nil {
		t.Error("BMCEnrollment should remain nil after round-trip of absent field")
	}
}
