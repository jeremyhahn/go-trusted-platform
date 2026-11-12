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
)

// Test-local copies of the server's manifest wire shape
// (pkg/api/quic/attestation_handlers.go), with the same codec tags.
type testPCRValueData struct {
	Index     int    `codec:"index"`
	Value     []byte `codec:"value"`
	Algorithm string `codec:"algorithm"`
}

type testHostAttestationData struct {
	QuoteData     []byte             `codec:"quote_data"`
	PCRs          []testPCRValueData `codec:"pcrs"`
	Timestamp     int64              `codec:"timestamp"`
	HashAlgorithm string             `codec:"hash_algorithm"`
}

type testVMAttestationData struct {
	VMID      string `codec:"vm_id"`
	HostID    string `codec:"host_id"`
	Timestamp int64  `codec:"timestamp"`
}

type testContainerAttestData struct {
	ContainerID string `codec:"container_id"`
	Timestamp   int64  `codec:"timestamp"`
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
	opcodes []byte
	ids     []string
}

func (s *manifestSender) Send(context.Context, byte, interface{}, interface{}) error {
	return &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected codec request"}
}

func (s *manifestSender) SendRequest(_ context.Context, opcode byte, payload []byte) (*quicwire.Response, error) {
	s.opcodes = append(s.opcodes, opcode)
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
				QuoteData:     []byte{9},
				PCRs:          []testPCRValueData{{Index: 7, Value: []byte{5}, Algorithm: "sha256"}},
				Timestamp:     1700000100,
				HashAlgorithm: "sha256",
			},
			VMs:        []testVMAttestationData{{VMID: "vm-1", HostID: "host-a", Timestamp: 1700000200}},
			Containers: []testContainerAttestData{{ContainerID: "c-1"}},
			Signature:  []byte{3, 4},
			Version:    "1",
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
	if h.GetTimestamp().AsTime().Unix() != 1700000100 || string(h.GetQuoteData()) != "\x09" ||
		h.GetHashAlgorithm() != platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256 {
		t.Fatalf("host attestation = %+v", h)
	}
	if len(h.GetPcrs()) != 1 || h.GetPcrs()[0].GetIndex() != 7 ||
		h.GetPcrs()[0].GetAlgorithm() != platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256 {
		t.Fatalf("host pcrs = %+v", h.GetPcrs())
	}
	if len(m.GetVms()) != 1 || m.GetVms()[0].GetVmId() != "vm-1" ||
		m.GetVms()[0].GetTimestamp().AsTime().Unix() != 1700000200 {
		t.Fatalf("vms = %+v", m.GetVms())
	}
	if len(m.GetContainers()) != 1 || m.GetContainers()[0].GetContainerId() != "c-1" ||
		m.GetContainers()[0].GetTimestamp() != nil {
		t.Fatalf("containers = %+v", m.GetContainers())
	}
}
