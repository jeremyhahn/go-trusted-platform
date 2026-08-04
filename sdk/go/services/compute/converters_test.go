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

package compute

import (
	"bytes"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCreateContainerParamsToProto_UserAndAttestOnCreate(t *testing.T) {
	req := createContainerParamsToProto(&CreateContainerParams{
		Name:           "web",
		Image:          "nginx:latest",
		User:           "1000:1000",
		AttestOnCreate: true,
		Start:          true,
	})

	if req.GetConfig().GetUser() != "1000:1000" {
		t.Errorf("expected user 1000:1000, got: %s", req.GetConfig().GetUser())
	}
	if !req.GetAttestOnCreate() {
		t.Error("expected attest_on_create true")
	}
	if !req.GetStart() {
		t.Error("expected start true")
	}
}

func TestCreateContainerParamsToProto_DefaultsOmitted(t *testing.T) {
	req := createContainerParamsToProto(&CreateContainerParams{
		Name:  "web",
		Image: "nginx:latest",
	})

	if req.GetConfig().GetUser() != "" {
		t.Errorf("expected empty user, got: %s", req.GetConfig().GetUser())
	}
	if req.GetAttestOnCreate() {
		t.Error("expected attest_on_create false by default")
	}
}

func TestListContainersParamsToProto_NameFilter(t *testing.T) {
	req := listContainersParamsToProto(&ListContainersParams{
		NameFilter: "web",
	})
	if req.GetNameFilter() != "web" {
		t.Errorf("expected name_filter web, got: %s", req.GetNameFilter())
	}
}

func TestListContainersParamsToProto_NoNameFilter(t *testing.T) {
	req := listContainersParamsToProto(&ListContainersParams{})
	if req.GetNameFilter() != "" {
		t.Errorf("expected empty name_filter, got: %s", req.GetNameFilter())
	}
}

func TestContainerConfigFromProto_User(t *testing.T) {
	cfg := ContainerConfigFromProto(&platformv1.ContainerConfig{
		Name:  "web",
		Image: "nginx:latest",
		User:  "nobody",
	})
	if cfg.User != "nobody" {
		t.Errorf("expected user nobody, got: %s", cfg.User)
	}
}

func TestContainerConfigFromProto_Nil(t *testing.T) {
	if cfg := ContainerConfigFromProto(nil); cfg != nil {
		t.Errorf("expected nil config, got: %+v", cfg)
	}
}

func TestContainerAttestationFromProto_Full(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second)
	report := ContainerAttestationFromProto(&platformv1.AttestContainerResponse{
		Status:        &platformv1.Status{Success: true},
		ContainerId:   "c-1",
		ContainerName: "web",
		ImageDigest:   []byte("image"),
		ConfigDigest:  []byte("config"),
		Quote:         []byte("quote"),
		Signature:     []byte("sig"),
		EventLog:      []byte("log"),
		AkPublic:      []byte("ak"),
		Verified:      true,
		Timestamp:     timestamppb.New(ts),
		PcrValues: []*platformv1.PCRValue{
			{Index: 14, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte("pcr")},
			nil,
		},
	})

	if report.ContainerID != "c-1" || report.ContainerName != "web" {
		t.Errorf("unexpected identity: %s/%s", report.ContainerID, report.ContainerName)
	}
	if !bytes.Equal(report.Quote, []byte("quote")) || !bytes.Equal(report.Signature, []byte("sig")) {
		t.Error("unexpected quote/signature")
	}
	if !bytes.Equal(report.ImageDigest, []byte("image")) || !bytes.Equal(report.ConfigDigest, []byte("config")) {
		t.Error("unexpected digests")
	}
	if !bytes.Equal(report.EventLog, []byte("log")) || !bytes.Equal(report.AKPublic, []byte("ak")) {
		t.Error("unexpected event log / ak public")
	}
	if !report.Verified {
		t.Error("expected verified")
	}
	if !report.Timestamp.Equal(ts) {
		t.Errorf("unexpected timestamp: %v", report.Timestamp)
	}
	if report.Status == nil || !report.Status.Success {
		t.Error("expected success status")
	}
	if len(report.PCRValues) != 2 {
		t.Fatalf("expected 2 PCR entries, got: %d", len(report.PCRValues))
	}
	if report.PCRValues[0].Index != 14 || report.PCRValues[0].Bank != "sha256" {
		t.Errorf("unexpected PCR value: %+v", report.PCRValues[0])
	}
	if report.PCRValues[1] != nil {
		t.Error("expected nil PCR entry preserved as nil")
	}
}

func TestContainerAttestationFromProto_Nil(t *testing.T) {
	if report := ContainerAttestationFromProto(nil); report != nil {
		t.Errorf("expected nil report, got: %+v", report)
	}
}

func TestPCRValueFromProto(t *testing.T) {
	pv := pcrValueFromProto(&platformv1.PCRValue{
		Index: 7,
		Bank:  platformv1.PCRBank_PCR_BANK_SHA384,
		Value: []byte("value"),
	})
	if pv.Index != 7 || pv.Bank != "sha384" || !bytes.Equal(pv.Value, []byte("value")) {
		t.Errorf("unexpected PCR value: %+v", pv)
	}
}

func TestPCRValueFromProto_Nil(t *testing.T) {
	if pv := pcrValueFromProto(nil); pv != nil {
		t.Errorf("expected nil, got: %+v", pv)
	}
}
