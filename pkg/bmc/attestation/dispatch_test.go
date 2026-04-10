// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"

	// Blank-imported to register vendor factories for dispatch tests.
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation/dell"
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation/hpe"
)

func TestDetectVendor(t *testing.T) {
	cases := []struct {
		in   string
		want attestation.Vendor
	}{
		{"Supermicro", attestation.VendorSupermicro},
		{"  SUPERMICRO ", attestation.VendorSupermicro},
		{"Super Micro Computer, Inc.", attestation.VendorSupermicro},
		{"Dell Inc.", attestation.VendorDell},
		{"DELL", attestation.VendorDell},
		{"HPE", attestation.VendorHPE},
		{"Hewlett Packard Enterprise", attestation.VendorHPE},
		{"HP ProLiant", attestation.VendorHPE},
		{"Lenovo", attestation.VendorUnknown},
		{"", attestation.VendorUnknown},
	}
	for _, tc := range cases {
		if got := attestation.DetectVendor(tc.in); got != tc.want {
			t.Errorf("DetectVendor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRegisterNilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil factory")
		}
	}()
	attestation.Register(attestation.Vendor("bogus-panic-test"), nil)
}

func TestRegisterAndDispatch(t *testing.T) {
	const testVendor = attestation.Vendor("dell") // reuse dell, already registered stub
	client := bmc.NewMockClient()
	client.System = &bmc.SystemInfo{Manufacturer: "Dell Inc."}
	p, err := attestation.NewProvider(context.Background(), client, attestation.Target{})
	if err != nil {
		t.Fatalf("dispatch failed: %v", err)
	}
	if p == nil {
		t.Fatal("nil provider")
	}
	_ = testVendor
}

func TestNewProviderUnknownVendor(t *testing.T) {
	client := bmc.NewMockClient()
	client.System = &bmc.SystemInfo{Manufacturer: "Lenovo"}
	_, err := attestation.NewProvider(context.Background(), client, attestation.Target{})
	if err == nil {
		t.Fatal("expected ErrUnsupportedVendor")
	}
	var unsup attestation.ErrUnsupportedVendor
	if !errors.As(err, &unsup) {
		t.Fatalf("want ErrUnsupportedVendor, got %T: %v", err, err)
	}
}

func TestNewProviderGetSystemInfoFailure(t *testing.T) {
	client := bmc.NewMockClient()
	client.GetSystemInfoErr = errors.New("transport reset")
	_, err := attestation.NewProvider(context.Background(), client, attestation.Target{})
	if err == nil {
		t.Fatal("expected error")
	}
	var wrapped attestation.ErrAttestationFailed
	if !errors.As(err, &wrapped) {
		t.Fatalf("want ErrAttestationFailed, got %T", err)
	}
}

func TestNewProviderNilClientNoManufacturer(t *testing.T) {
	_, err := attestation.NewProvider(context.Background(), nil, attestation.Target{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewProviderExplicitManufacturerSkipsClient(t *testing.T) {
	client := bmc.NewMockClient()
	client.GetSystemInfoErr = errors.New("should not be called")
	_, err := attestation.NewProvider(context.Background(), client, attestation.Target{
		Manufacturer: "Dell",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client.GetSystemInfoCalls() != 0 {
		t.Errorf("GetSystemInfo should not be called when manufacturer explicit")
	}
}
