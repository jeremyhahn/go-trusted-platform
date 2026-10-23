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
	"context"
	"errors"
	"io"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeComputeClient is a test double for platformv1.ComputeServiceClient. It
// embeds the interface so only the methods under test need implementations;
// calling any other method panics, which fails the test loudly.
type fakeComputeClient struct {
	platformv1.ComputeServiceClient

	attestReq  *platformv1.AttestContainerRequest
	attestResp *platformv1.AttestContainerResponse
	attestErr  error

	logsReq     *platformv1.GetContainerLogsRequest
	logsEntries []*platformv1.LogEntry
	logsErr     error

	createResp *platformv1.CreateContainerResponse
}

func (f *fakeComputeClient) CreateContainer(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error) {
	return f.createResp, nil
}

func (f *fakeComputeClient) AttestContainer(ctx context.Context, in *platformv1.AttestContainerRequest, opts ...grpc.CallOption) (*platformv1.AttestContainerResponse, error) {
	f.attestReq = in
	if f.attestErr != nil {
		return nil, f.attestErr
	}
	return f.attestResp, nil
}

// fakeLogsStream implements platformv1.ComputeService_GetContainerLogsClient.
type fakeLogsStream struct {
	grpc.ClientStream
	entries []*platformv1.LogEntry
	pos     int
}

func (f *fakeLogsStream) Recv() (*platformv1.LogEntry, error) {
	if f.pos >= len(f.entries) {
		return nil, io.EOF
	}
	entry := f.entries[f.pos]
	f.pos++
	return entry, nil
}

func (f *fakeComputeClient) GetContainerLogs(ctx context.Context, in *platformv1.GetContainerLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[platformv1.LogEntry], error) {
	f.logsReq = in
	if f.logsErr != nil {
		return nil, f.logsErr
	}
	return &fakeLogsStream{entries: f.logsEntries}, nil
}

func TestAttestContainer_Success(t *testing.T) {
	fake := &fakeComputeClient{
		attestResp: &platformv1.AttestContainerResponse{
			ContainerId: "c-1",
			Quote:       []byte("quote"),
		},
	}
	client := NewClientFromGRPC(fake)

	resp, err := client.AttestContainer(context.Background(), "c-1",
		[]byte("nonce"), []uint32{14}, platformv1.PCRBank_PCR_BANK_SHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetContainerId() != "c-1" {
		t.Errorf("unexpected container_id: %s", resp.GetContainerId())
	}
	if fake.attestReq.GetId() != "c-1" {
		t.Errorf("unexpected request id: %s", fake.attestReq.GetId())
	}
	if !bytes.Equal(fake.attestReq.GetNonce(), []byte("nonce")) {
		t.Errorf("unexpected request nonce: %v", fake.attestReq.GetNonce())
	}
	if len(fake.attestReq.GetPcrIndices()) != 1 || fake.attestReq.GetPcrIndices()[0] != 14 {
		t.Errorf("unexpected request pcr indices: %v", fake.attestReq.GetPcrIndices())
	}
	if fake.attestReq.GetPcrBank() != platformv1.PCRBank_PCR_BANK_SHA256 {
		t.Errorf("unexpected request pcr bank: %v", fake.attestReq.GetPcrBank())
	}
}

func TestAttestContainer_MissingID(t *testing.T) {
	client := NewClientFromGRPC(&fakeComputeClient{})

	_, err := client.AttestContainer(context.Background(), "", nil, nil,
		platformv1.PCRBank_PCR_BANK_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for missing container ID")
	}
	var attestErr *ErrAttestContainerFailed
	if !errors.As(err, &attestErr) {
		t.Fatalf("expected ErrAttestContainerFailed, got: %T", err)
	}
	if !errors.Is(err, ErrContainerIDRequired) {
		t.Errorf("expected ErrContainerIDRequired cause, got: %v", err)
	}
}

func TestAttestContainer_RPCError(t *testing.T) {
	fake := &fakeComputeClient{attestErr: errors.New("rpc failed")}
	client := NewClientFromGRPC(fake)

	_, err := client.AttestContainer(context.Background(), "c-1", nil, nil,
		platformv1.PCRBank_PCR_BANK_SHA256)
	if err == nil {
		t.Fatal("expected error")
	}
	var attestErr *ErrAttestContainerFailed
	if !errors.As(err, &attestErr) {
		t.Fatalf("expected ErrAttestContainerFailed, got: %T", err)
	}
	if attestErr.ID != "c-1" {
		t.Errorf("expected error ID c-1, got: %s", attestErr.ID)
	}
}

func TestAttestContainerDomain_Success(t *testing.T) {
	ts := time.Now().UTC().Truncate(time.Second)
	fake := &fakeComputeClient{
		attestResp: &platformv1.AttestContainerResponse{
			Status:        &platformv1.Status{Success: true, Message: "attestation completed"},
			ContainerId:   "c-1",
			ContainerName: "web",
			ImageDigest:   []byte("image-digest"),
			ConfigDigest:  []byte("config-digest"),
			Quote:         []byte("quote"),
			Signature:     []byte("signature"),
			EventLog:      []byte("event-log"),
			AkPublic:      []byte("ak"),
			Verified:      true,
			Timestamp:     timestamppb.New(ts),
			PcrValues: []*platformv1.PCRValue{
				{Index: 14, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte("pcr")},
			},
		},
	}
	client := NewClientFromGRPC(fake)

	report, err := client.AttestContainerDomain(context.Background(), &AttestContainerParams{
		ID:         "c-1",
		Nonce:      []byte("nonce"),
		PCRIndices: []uint32{14},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.ContainerID != "c-1" || report.ContainerName != "web" {
		t.Errorf("unexpected identity: %s/%s", report.ContainerID, report.ContainerName)
	}
	if !bytes.Equal(report.Quote, []byte("quote")) {
		t.Errorf("unexpected quote: %v", report.Quote)
	}
	if !bytes.Equal(report.Signature, []byte("signature")) {
		t.Errorf("unexpected signature: %v", report.Signature)
	}
	if !bytes.Equal(report.ConfigDigest, []byte("config-digest")) {
		t.Errorf("unexpected config digest: %v", report.ConfigDigest)
	}
	if !bytes.Equal(report.ImageDigest, []byte("image-digest")) {
		t.Errorf("unexpected image digest: %v", report.ImageDigest)
	}
	if !report.Verified {
		t.Error("expected verified report")
	}
	if !report.Timestamp.Equal(ts) {
		t.Errorf("unexpected timestamp: %v", report.Timestamp)
	}
	if len(report.PCRValues) != 1 {
		t.Fatalf("expected 1 PCR value, got: %d", len(report.PCRValues))
	}
	if report.PCRValues[0].Index != 14 || report.PCRValues[0].Bank != "sha256" {
		t.Errorf("unexpected PCR value: %+v", report.PCRValues[0])
	}
	if report.Status == nil || !report.Status.Success {
		t.Error("expected success status")
	}
	if !bytes.Equal(fake.attestReq.GetNonce(), []byte("nonce")) {
		t.Errorf("unexpected request nonce: %v", fake.attestReq.GetNonce())
	}
}

func TestAttestContainerDomain_NilParams(t *testing.T) {
	client := NewClientFromGRPC(&fakeComputeClient{})

	if _, err := client.AttestContainerDomain(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil params")
	}
	if _, err := client.AttestContainerDomain(context.Background(), &AttestContainerParams{}); err == nil {
		t.Fatal("expected error for missing container ID")
	}
}

func TestAttestContainerDomain_RPCError(t *testing.T) {
	fake := &fakeComputeClient{attestErr: errors.New("rpc failed")}
	client := NewClientFromGRPC(fake)

	_, err := client.AttestContainerDomain(context.Background(), &AttestContainerParams{ID: "c-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	var attestErr *ErrAttestContainerFailed
	if !errors.As(err, &attestErr) {
		t.Fatalf("expected ErrAttestContainerFailed, got: %T", err)
	}
}

func TestCreateContainerDomain_SuccessStatusReturnsTheContainer(t *testing.T) {
	fake := &fakeComputeClient{createResp: &platformv1.CreateContainerResponse{
		Container: &platformv1.Container{Id: "c-1"},
		Status:    &platformv1.Status{Success: true, Message: "Container created successfully"},
	}}
	client := NewClientFromGRPC(fake)

	container, err := client.CreateContainerDomain(context.Background(), &CreateContainerParams{Name: "web", Image: "alpine"})
	if err != nil {
		t.Fatalf("CreateContainerDomain: %v", err)
	}
	if container == nil || container.ID != "c-1" {
		t.Fatalf("container = %+v, want ID c-1", container)
	}
}

func TestCreateContainerDomain_FailedStatusIsAnErrorNamingTheContainer(t *testing.T) {
	fake := &fakeComputeClient{createResp: &platformv1.CreateContainerResponse{
		Container: &platformv1.Container{Id: "c-2"},
		Status:    &platformv1.Status{Success: false, Message: "Container created but attestation failed: no TPM"},
	}}
	client := NewClientFromGRPC(fake)

	container, err := client.CreateContainerDomain(context.Background(), &CreateContainerParams{Name: "web", Image: "alpine", AttestOnCreate: true})
	var incomplete *ErrContainerCreateIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("error = %v, want ErrContainerCreateIncomplete", err)
	}
	if incomplete.ID != "c-2" || incomplete.Message != "Container created but attestation failed: no TPM" {
		t.Errorf("error = %+v, want ID c-2 and the daemon's message", incomplete)
	}
	if container == nil || container.ID != "c-2" {
		t.Errorf("container = %+v, want the created container c-2 returned with the error", container)
	}
}
