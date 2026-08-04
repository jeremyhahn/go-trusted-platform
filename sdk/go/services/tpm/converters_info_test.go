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

package tpm

import (
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
)

func TestInfoResponseFromProto_Lossless(t *testing.T) {
	resp := InfoResponseFromProto(&platformv1.TPMInfoResponse{
		Version: platformv1.TPMVersion_TPM_VERSION_2_0,
		Manufacturer: &platformv1.TPMManufacturer{
			Name:            "IBM",
			Id:              0x49424d20,
			Model:           "swtpm",
			FirmwareVersion: "2.0.1",
		},
		Capabilities: []*platformv1.TPMCapability{
			{Name: "hierarchies", Supported: true, Value: "owner,endorsement,platform"},
		},
		PcrBanks:     []platformv1.PCRBank{platformv1.PCRBank_PCR_BANK_SHA1, platformv1.PCRBank_PCR_BANK_SHA256},
		MaxNvramSize: 2048,
		IsSimulator:  true,
		FipsMode:     true,
		Properties:   map[string]string{"info": "TPM 2.0 details"},
		NvIndexes: []*platformv1.NVIndex{
			{Handle: 0x01800001, Type: "counter", Size: 8, AuthRead: true, AuthWrite: true},
		},
	})

	if resp.Version != TPMVersion20 {
		t.Errorf("expected version 2.0, got: %s", resp.Version)
	}
	if resp.Manufacturer == nil {
		t.Fatal("expected manufacturer")
	}
	if resp.Manufacturer.Name != "IBM" || resp.Manufacturer.ID != 0x49424d20 {
		t.Errorf("unexpected manufacturer: %+v", resp.Manufacturer)
	}
	if resp.Manufacturer.Model != "swtpm" || resp.Manufacturer.FirmwareVersion != "2.0.1" {
		t.Errorf("unexpected manufacturer model/firmware: %+v", resp.Manufacturer)
	}
	if len(resp.Capabilities) != 1 || !resp.Capabilities[0].Supported || resp.Capabilities[0].Name != "hierarchies" {
		t.Errorf("unexpected capabilities: %+v", resp.Capabilities)
	}
	if len(resp.PCRBanks) != 2 || resp.PCRBanks[0] != PCRBankSHA1 || resp.PCRBanks[1] != PCRBankSHA256 {
		t.Errorf("unexpected PCR banks: %v", resp.PCRBanks)
	}
	if resp.MaxNVRAMSize != 2048 {
		t.Errorf("expected max NVRAM size 2048, got: %d", resp.MaxNVRAMSize)
	}
	if !resp.FIPSMode {
		t.Error("expected FIPS mode true")
	}
	if !resp.IsSimulator {
		t.Error("expected simulator true")
	}
	if resp.Properties["info"] != "TPM 2.0 details" {
		t.Errorf("unexpected properties: %v", resp.Properties)
	}
	if len(resp.NVIndexes) != 1 {
		t.Fatalf("expected 1 NV index, got: %d", len(resp.NVIndexes))
	}
	nv := resp.NVIndexes[0]
	if nv.Handle != 0x01800001 || nv.Type != "counter" || nv.Size != 8 || !nv.AuthRead || !nv.AuthWrite {
		t.Errorf("unexpected NV index: %+v", nv)
	}
}

func TestInfoResponseFromProto_Nil(t *testing.T) {
	if resp := InfoResponseFromProto(nil); resp != nil {
		t.Errorf("expected nil response, got: %+v", resp)
	}
}

func TestInfoResponseFromProto_EmptyOptionalFields(t *testing.T) {
	resp := InfoResponseFromProto(&platformv1.TPMInfoResponse{})
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Version != TPMVersionUnspecified {
		t.Errorf("expected unspecified version, got: %s", resp.Version)
	}
	if resp.Manufacturer != nil {
		t.Errorf("expected nil manufacturer, got: %+v", resp.Manufacturer)
	}
	if len(resp.Capabilities) != 0 || len(resp.PCRBanks) != 0 || len(resp.NVIndexes) != 0 {
		t.Error("expected empty capability/bank/index slices")
	}
}

func TestTPMVersionFromProto(t *testing.T) {
	cases := []struct {
		proto    platformv1.TPMVersion
		expected TPMVersion
	}{
		{platformv1.TPMVersion_TPM_VERSION_UNSPECIFIED, TPMVersionUnspecified},
		{platformv1.TPMVersion_TPM_VERSION_1_2, TPMVersion12},
		{platformv1.TPMVersion_TPM_VERSION_2_0, TPMVersion20},
		{platformv1.TPMVersion(99), TPMVersionUnspecified},
	}
	for _, tc := range cases {
		if got := TPMVersionFromProto(tc.proto); got != tc.expected {
			t.Errorf("TPMVersionFromProto(%v): expected %s, got: %s", tc.proto, tc.expected, got)
		}
	}
}

func TestTPMVersionToProto(t *testing.T) {
	cases := []struct {
		domain   TPMVersion
		expected platformv1.TPMVersion
	}{
		{TPMVersionUnspecified, platformv1.TPMVersion_TPM_VERSION_UNSPECIFIED},
		{TPMVersion12, platformv1.TPMVersion_TPM_VERSION_1_2},
		{TPMVersion20, platformv1.TPMVersion_TPM_VERSION_2_0},
		{TPMVersion("bogus"), platformv1.TPMVersion_TPM_VERSION_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := TPMVersionToProto(tc.domain); got != tc.expected {
			t.Errorf("TPMVersionToProto(%s): expected %v, got: %v", tc.domain, tc.expected, got)
		}
	}
}

func TestPCRBankFromProto(t *testing.T) {
	cases := []struct {
		proto    platformv1.PCRBank
		expected PCRBank
	}{
		{platformv1.PCRBank_PCR_BANK_SHA1, PCRBankSHA1},
		{platformv1.PCRBank_PCR_BANK_SHA256, PCRBankSHA256},
		{platformv1.PCRBank_PCR_BANK_SHA384, PCRBankSHA384},
		{platformv1.PCRBank_PCR_BANK_SHA512, PCRBankSHA512},
		{platformv1.PCRBank_PCR_BANK_SM3_256, PCRBankSM3256},
		{platformv1.PCRBank_PCR_BANK_UNSPECIFIED, PCRBankSHA256},
		{platformv1.PCRBank(99), PCRBankSHA256},
	}
	for _, tc := range cases {
		if got := PCRBankFromProto(tc.proto); got != tc.expected {
			t.Errorf("PCRBankFromProto(%v): expected %s, got: %s", tc.proto, tc.expected, got)
		}
	}
}

// fakeTPMClient is a test double for platformv1.TPMServiceClient. It embeds
// the interface so only the methods under test need implementations.
type fakeTPMClient struct {
	platformv1.TPMServiceClient
	infoResp *platformv1.TPMInfoResponse
	infoErr  error
}

func (f *fakeTPMClient) Info(ctx context.Context, in *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
	if f.infoErr != nil {
		return nil, f.infoErr
	}
	return f.infoResp, nil
}

func TestInfoDomain_Success(t *testing.T) {
	fake := &fakeTPMClient{
		infoResp: &platformv1.TPMInfoResponse{
			Version:      platformv1.TPMVersion_TPM_VERSION_2_0,
			Manufacturer: &platformv1.TPMManufacturer{Name: "IBM"},
			PcrBanks:     []platformv1.PCRBank{platformv1.PCRBank_PCR_BANK_SHA256},
			MaxNvramSize: 4096,
			FipsMode:     true,
		},
	}
	client := NewClientFromGRPC(fake)

	resp, err := client.InfoDomain(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Version != TPMVersion20 {
		t.Errorf("expected version 2.0, got: %s", resp.Version)
	}
	if resp.Manufacturer == nil || resp.Manufacturer.Name != "IBM" {
		t.Errorf("unexpected manufacturer: %+v", resp.Manufacturer)
	}
	if len(resp.PCRBanks) != 1 || resp.PCRBanks[0] != PCRBankSHA256 {
		t.Errorf("unexpected PCR banks: %v", resp.PCRBanks)
	}
	if resp.MaxNVRAMSize != 4096 {
		t.Errorf("expected max NVRAM size 4096, got: %d", resp.MaxNVRAMSize)
	}
	if !resp.FIPSMode {
		t.Error("expected FIPS mode true")
	}
}

func TestInfoDomain_Error(t *testing.T) {
	fake := &fakeTPMClient{infoErr: errors.New("rpc failed")}
	client := NewClientFromGRPC(fake)

	_, err := client.InfoDomain(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var infoErr *ErrInfoFailed
	if !errors.As(err, &infoErr) {
		t.Fatalf("expected ErrInfoFailed, got: %T", err)
	}
}
