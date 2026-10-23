// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package quic

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// verdictSender answers OpAttestPollVerdicts from a script of pages and
// records each poll.
type verdictSender struct {
	pages []*platformv1.PollDeviceVerdictsResponse
	polls []*platformv1.PollDeviceVerdictsRequest
}

func (s *verdictSender) Send(_ context.Context, opcode byte, reqData, respData interface{}) error {
	if opcode != quicwire.OpAttestPollVerdicts {
		return &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected opcode"}
	}
	s.polls = append(s.polls, proto.Clone(reqData.(*platformv1.PollDeviceVerdictsRequest)).(*platformv1.PollDeviceVerdictsRequest))
	if len(s.pages) == 0 {
		return &quicwire.ErrProtocol{Status: quicwire.StatusResourceExhausted, Message: "verdicts were missed"}
	}
	proto.Merge(respData.(proto.Message), s.pages[0])
	s.pages = s.pages[1:]
	return nil
}

func (s *verdictSender) SendRequest(context.Context, byte, []byte) (*quicwire.Response, error) {
	return nil, &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected raw request"}
}

func (s *verdictSender) SendBoundRequest(context.Context, byte, func(*tls.ConnectionState) ([]byte, error)) (*quicwire.Response, error) {
	return nil, &quicwire.ErrProtocol{Status: quicwire.StatusNotFound, Message: "unexpected channel-bound request"}
}

// TestStreamDeviceVerdictsOverQUIC opens StreamDeviceVerdicts through the
// generated client: the adapter long-polls OpAttestPollVerdicts, each poll
// waiting half the transport timeout, until a poll fails.
func TestStreamDeviceVerdictsOverQUIC(t *testing.T) {
	sender := &verdictSender{pages: []*platformv1.PollDeviceVerdictsResponse{
		{Cursor: "18f.0"},
		{Cursor: "18f.1", Verdicts: []*platformv1.DeviceVerdictEvent{{EventId: "ev-1", DeviceId: 7}}},
	}}
	a := &Adapter{client: &quicwire.Client{}, timeout: 8 * time.Second}
	a.connected.Store(true)
	conn := &quicClientConn{adapter: a, sender: sender}

	stream, err := platformv1.NewAttestationServiceClient(conn).
		StreamDeviceVerdicts(context.Background(), &platformv1.StreamDeviceVerdictsRequest{})
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	got, err := stream.Recv()
	if err != nil || got.GetEventId() != "ev-1" || got.GetDeviceId() != 7 {
		t.Fatalf("Recv = %+v, %v", got, err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Recv = %v, want ResourceExhausted", err)
	}
	if len(sender.polls) != 3 || sender.polls[0].GetWaitMs() != 0 ||
		sender.polls[1].GetCursor() != "18f.0" || sender.polls[1].GetWaitMs() != 4000 ||
		sender.polls[2].GetCursor() != "18f.1" {
		t.Fatalf("polls = %+v", sender.polls)
	}
}

func TestQUICNewStreamRefusesOtherStreams(t *testing.T) {
	a := &Adapter{client: &quicwire.Client{}}
	a.connected.Store(true)
	conn := &quicClientConn{adapter: a, sender: &verdictSender{}}
	if _, err := conn.NewStream(context.Background(), nil, "/platform.v1.PlatformDaemon/StreamEvents"); status.Code(err) != codes.Unimplemented {
		t.Fatalf("NewStream = %v, want Unimplemented", err)
	}
}
