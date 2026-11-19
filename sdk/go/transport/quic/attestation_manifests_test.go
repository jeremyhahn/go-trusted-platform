// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
package quic

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Test-local copies of the server's manifest wire shape
// (pkg/api/quic/attestation_handlers.go), with the same codec tags.
type testPCRValueData struct {
	Index     int    `codec:"index"`
	Value     []byte `codec:"value"`
	Algorithm string `codec:"algorithm"`
}

type testHostAttestationData struct {
	QuoteData      []byte             `codec:"quote_data"`
	PCRs           []testPCRValueData `codec:"pcrs"`
	Timestamp      int64              `codec:"timestamp"`
	TimestampNanos int64              `codec:"timestamp_nanos"`
	HashAlgorithm  string             `codec:"hash_algorithm"`
}

type testVMAttestationData struct {
	VMID           string `codec:"vm_id"`
	HostID         string `codec:"host_id"`
	Timestamp      int64  `codec:"timestamp"`
	TimestampNanos int64  `codec:"timestamp_nanos"`
}

type testContainerAttestData struct {
	ContainerID    string `codec:"container_id"`
	Timestamp      int64  `codec:"timestamp"`
	TimestampNanos int64  `codec:"timestamp_nanos"`
}

type testManifestData struct {
	ID             string                    `codec:"id"`
	HostID         string                    `codec:"host_id"`
	Timestamp      int64                     `codec:"timestamp"`
	TimestampNanos int64                     `codec:"timestamp_nanos"`
	Nonce          []byte                    `codec:"nonce"`
	Host           *testHostAttestationData  `codec:"host"`
	VMs            []testVMAttestationData   `codec:"vms"`
	Containers     []testContainerAttestData `codec:"containers"`
	Signature      []byte                    `codec:"signature"`
	Version        string                    `codec:"version"`
}

type testGetManifestResponse struct {
	Manifest  *testManifestData `codec:"manifest"`
	Timestamp int64             `codec:"timestamp"`
}

// manifestSender answers OpAttestGetManifest, the server's manifest-get
// opcode (pkg/api/quic/attestation_handlers.go), with an encoded server
// wire response, and records the request.
type manifestSender struct {
	opcodes   []byte
	ids       []string
	listReqs  []testListManifestsRequest
	deleteIDs []string
}

// testListManifestsRequest mirrors the server's ListManifestsRequest
// (pkg/api/quic/attestation_handlers.go): time bounds cross as RFC 3339
// nano strings, "" meaning no bound.
type testListManifestsRequest struct {
	HostID    string `codec:"host_id"`
	StartTime string `codec:"start_time"`
	EndTime   string `codec:"end_time"`
	Limit     int    `codec:"limit"`
	Offset    int    `codec:"offset"`
}

type testListManifestsResponse struct {
	Manifests []*testManifestData `codec:"manifests"`
	Total     int                 `codec:"total"`
	Timestamp int64               `codec:"timestamp"`
}

type testDeleteManifestResponse struct {
	Success bool   `codec:"success"`
	Message string `codec:"message"`
}

// answerManifestListOrDelete answers OpAttestListManifests and
// OpAttestDeleteManifest; ok is false for any other opcode.
func (s *manifestSender) answerManifestListOrDelete(opcode byte, payload []byte) (*quicwire.Response, bool, error) {
	var v interface{}
	switch opcode {
	case quicwire.OpAttestListManifests:
		var req testListManifestsRequest
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return nil, true, err
		}
		s.listReqs = append(s.listReqs, req)
		v = &testListManifestsResponse{
			Manifests: []*testManifestData{
				{ID: "m-1", HostID: req.HostID, Timestamp: 1700000000},
				{ID: "m-2", HostID: req.HostID, Timestamp: 1700000100},
			},
			Total:     2,
			Timestamp: 1700000300,
		}
	case quicwire.OpAttestDeleteManifest:
		var req struct {
			ID string `codec:"id"`
		}
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return nil, true, err
		}
		s.deleteIDs = append(s.deleteIDs, req.ID)
		v = &testDeleteManifestResponse{Success: true, Message: "manifest deleted successfully"}
	default:
		return nil, false, nil
	}
	p, err := quicwire.EncodePayload(v)
	if err != nil {
		return nil, true, err
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: p}, true, nil
}

func (s *manifestSender) Send(context.Context, byte, interface{}, interface{}) error {
	return &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected codec request"}
}

func (s *manifestSender) SendRequest(_ context.Context, opcode byte, payload []byte) (*quicwire.Response, error) {
	s.opcodes = append(s.opcodes, opcode)
	if resp, ok, err := s.answerManifestListOrDelete(opcode, payload); ok {
		return resp, err
	}
	if opcode != quicwire.OpAttestGetManifest {
		return nil, &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected opcode"}
	}
	// The server decodes into pkg/api/quic GetManifestRequest; decode the
	// same shape so a protobuf-shaped payload (field Id) records "".
	var req struct {
		ID string `codec:"id"`
	}
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return nil, err
	}
	s.ids = append(s.ids, req.ID)
	p, err := quicwire.EncodePayload(&testGetManifestResponse{
		Manifest: &testManifestData{
			ID:             req.ID,
			HostID:         "host-a",
			Timestamp:      1700000000,
			TimestampNanos: 123456789,
			Nonce:          []byte{1, 2},
			Host: &testHostAttestationData{
				QuoteData:      []byte{9},
				PCRs:           []testPCRValueData{{Index: 7, Value: []byte{5}, Algorithm: "sha256"}},
				Timestamp:      1700000100,
				TimestampNanos: 111111111,
				HashAlgorithm:  "sha256",
			},
			VMs: []testVMAttestationData{{VMID: "vm-1", HostID: "host-a", Timestamp: 1700000200, TimestampNanos: 222222222}},
			Containers: []testContainerAttestData{
				{ContainerID: "c-1"},
				{ContainerID: "c-2", Timestamp: 1700000300, TimestampNanos: 333333333},
			},
			Signature: []byte{3, 4},
			Version:   "1",
		},
		Timestamp: 1700000300,
	})
	if err != nil {
		return nil, err
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: p}, nil
}

func (s *manifestSender) SendBoundRequest(context.Context, byte, func(*tls.ConnectionState) ([]byte, error)) (*quicwire.Response, error) {
	return nil, &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected channel-bound request"}
}

func TestGetManifestOverQUIC(t *testing.T) {
	sender := &manifestSender{}
	a := &Adapter{client: &quicwire.Client{}, timeout: 8 * time.Second}
	a.connected.Store(true)
	conn := &quicClientConn{adapter: a, sender: sender}

	resp, err := platformv1.NewAttestationServiceClient(conn).
		GetManifest(context.Background(), &platformv1.GetManifestRequest{Id: "m-1"})
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if len(sender.opcodes) != 1 || sender.opcodes[0] != quicwire.OpAttestGetManifest || sender.ids[0] != "m-1" {
		t.Fatalf("opcodes = %x ids = %q, want one OpAttestGetManifest for m-1", sender.opcodes, sender.ids)
	}
	m := resp.GetManifest()
	if m.GetId() != "m-1" || m.GetHostId() != "host-a" || m.GetVersion() != "1" ||
		string(m.GetNonce()) != "\x01\x02" || string(m.GetSignature()) != "\x03\x04" {
		t.Fatalf("manifest = %+v", m)
	}
	if got, want := m.GetTimestamp().AsTime(), time.Unix(1700000000, 123456789); !got.Equal(want) {
		t.Fatalf("manifest timestamp = %v, want %v", got, want)
	}
	h := m.GetHost()
	if !h.GetTimestamp().AsTime().Equal(time.Unix(1700000100, 111111111)) || string(h.GetQuoteData()) != "\x09" ||
		h.GetHashAlgorithm() != platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256 {
		t.Fatalf("host attestation = %+v", h)
	}
	if len(h.GetPcrs()) != 1 || h.GetPcrs()[0].GetIndex() != 7 ||
		h.GetPcrs()[0].GetAlgorithm() != platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256 {
		t.Fatalf("host pcrs = %+v", h.GetPcrs())
	}
	// Nested evidence keeps its sub-second time (#1686, Codex round 5).
	if len(m.GetVms()) != 1 || m.GetVms()[0].GetVmId() != "vm-1" ||
		!m.GetVms()[0].GetTimestamp().AsTime().Equal(time.Unix(1700000200, 222222222)) {
		t.Fatalf("vms = %+v", m.GetVms())
	}
	if len(m.GetContainers()) != 2 || m.GetContainers()[0].GetContainerId() != "c-1" ||
		m.GetContainers()[0].GetTimestamp() != nil {
		t.Fatalf("containers = %+v", m.GetContainers())
	}
	if c := m.GetContainers()[1]; c.GetContainerId() != "c-2" ||
		!c.GetTimestamp().AsTime().Equal(time.Unix(1700000300, 333333333)) {
		t.Fatalf("container c-2 = %+v", c)
	}
}

func newManifestConn(sender *manifestSender) *quicClientConn {
	a := &Adapter{client: &quicwire.Client{}, timeout: 8 * time.Second}
	a.connected.Store(true)
	return &quicClientConn{adapter: a, sender: sender}
}

// TestListManifestsOverQUIC: manifest list rides its own opcode 0x66
// (#1686, ruling 931) with RFC 3339 nano time bounds.
func TestListManifestsOverQUIC(t *testing.T) {
	sender := &manifestSender{}
	conn := newManifestConn(sender)
	start := time.Unix(1700000000, 123456789).UTC()

	resp, err := platformv1.NewAttestationServiceClient(conn).ListManifests(context.Background(),
		&platformv1.ListManifestsRequest{HostId: "host-a", StartTime: timestamppb.New(start), Limit: 5})
	if err != nil {
		t.Fatalf("ListManifests: %v", err)
	}
	if len(sender.opcodes) != 1 || sender.opcodes[0] != 0x66 || sender.opcodes[0] != quicwire.OpAttestListManifests {
		t.Fatalf("opcodes = %x, want one 0x66", sender.opcodes)
	}
	if len(sender.listReqs) != 1 {
		t.Fatalf("list requests = %+v", sender.listReqs)
	}
	got := sender.listReqs[0]
	if got.HostID != "host-a" || got.StartTime != start.Format(time.RFC3339Nano) || got.EndTime != "" ||
		got.Limit != 5 || got.Offset != 0 {
		t.Fatalf("list request = %+v", got)
	}
	if len(resp.GetManifests()) != 2 || resp.GetTotal() != 2 ||
		resp.GetManifests()[0].GetId() != "m-1" || resp.GetManifests()[1].GetHostId() != "host-a" {
		t.Fatalf("list reply = %+v", resp)
	}
}

// TestDeleteManifestOverQUIC: manifest delete rides its own opcode 0x67.
func TestDeleteManifestOverQUIC(t *testing.T) {
	sender := &manifestSender{}
	conn := newManifestConn(sender)

	resp, err := platformv1.NewAttestationServiceClient(conn).DeleteManifest(context.Background(),
		&platformv1.DeleteManifestRequest{Id: "m-9"})
	if err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if len(sender.opcodes) != 1 || sender.opcodes[0] != 0x67 || sender.opcodes[0] != quicwire.OpAttestDeleteManifest {
		t.Fatalf("opcodes = %x, want one 0x67", sender.opcodes)
	}
	if len(sender.deleteIDs) != 1 || sender.deleteIDs[0] != "m-9" {
		t.Fatalf("delete ids = %q", sender.deleteIDs)
	}
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "manifest deleted successfully" {
		t.Fatalf("delete reply = %+v", resp)
	}
}
