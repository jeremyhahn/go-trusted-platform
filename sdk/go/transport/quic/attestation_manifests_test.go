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

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// manifestSender answers OpAttestGetManifest, the server's manifest-get
// opcode (pkg/api/quic/attestation_handlers.go), and records the request.
type manifestSender struct {
	opcodes []byte
	ids     []string
}

func (s *manifestSender) Send(_ context.Context, opcode byte, reqData, respData interface{}) error {
	s.opcodes = append(s.opcodes, opcode)
	if opcode != quicwire.OpAttestGetManifest {
		return &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected opcode"}
	}
	s.ids = append(s.ids, reqData.(*platformv1.GetManifestRequest).GetId())
	proto.Merge(respData.(proto.Message), &platformv1.GetManifestResponse{
		Manifest: &platformv1.HostManifest{Id: "m-1", Nonce: []byte{1, 2}, Signature: []byte{3, 4}},
	})
	return nil
}

func (s *manifestSender) SendRequest(context.Context, byte, []byte) (*quicwire.Response, error) {
	return nil, &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected raw request"}
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
	if m.GetId() != "m-1" || string(m.GetNonce()) != "\x01\x02" || string(m.GetSignature()) != "\x03\x04" {
		t.Fatalf("manifest = %+v", m)
	}
}
