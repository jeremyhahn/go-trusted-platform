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
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// verdictPolls answers attestation_device_verdicts_poll from a script of
// pages, as the server tool renders them, and records each poll's arguments.
// An exhausted script answers the tool error the daemon sends a caller that
// missed verdicts.
type verdictPolls struct {
	mu    sync.Mutex
	pages []map[string]interface{}
	polls []map[string]interface{}
}

func (p *verdictPolls) serve(w http.ResponseWriter, r *http.Request) {
	var req mcpwire.JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp := mcpwire.JSONRPCResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{"protocolVersion": "2024-11-05", "capabilities": map[string]interface{}{}}
	case "tools/call":
		params, _ := req.Params.(map[string]interface{})
		args, _ := params["arguments"].(map[string]interface{})
		p.mu.Lock()
		p.polls = append(p.polls, args)
		switch {
		case params["name"] != "attestation_device_verdicts_poll":
			resp.Error = &mcpwire.JSONRPCError{Code: mcpwire.MethodNotFound, Message: "unknown tool"}
		case len(p.pages) == 0:
			resp.Error = &mcpwire.JSONRPCError{Code: mcpwire.InternalError,
				Message: "rpc error: code = ResourceExhausted desc = attestation: verdicts were missed"}
		default:
			resp.Result = p.pages[0]
			p.pages = p.pages[1:]
		}
		p.mu.Unlock()
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func verdictAdapter(t *testing.T, polls *verdictPolls, timeout time.Duration) *Adapter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(polls.serve))
	t.Cleanup(server.Close)
	adapter, err := Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(server.URL), platform.WithTimeout(timeout)))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return adapter.(*Adapter)
}

// verdictAdapterWithoutRetries is verdictAdapter with a client that does not
// retry a failed call, so a stream's final poll error arrives at once.
func verdictAdapterWithoutRetries(t *testing.T, polls *verdictPolls, timeout time.Duration) *Adapter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(polls.serve))
	t.Cleanup(server.Close)
	config := mcpwire.DefaultClientConfig(server.URL)
	config.Timeout = timeout
	config.MaxRetries = 0
	client, err := mcpwire.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	a := &Adapter{client: client, address: server.URL, timeout: timeout}
	a.connected.Store(true)
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestAttestationVerdictsMCP_ToolMappingParity checks the SDK side: the poll
// method is mapped to its tool and has a reply decoder. That the mapped tool
// is registered by the server is checked in pkg/api/mcp against MethodTools.
func TestAttestationVerdictsMCP_ToolMappingParity(t *testing.T) {
	method := platformv1.AttestationService_PollDeviceVerdicts_FullMethodName
	if tool := grpcMethodToMCPToolMap[method]; tool != "attestation_device_verdicts_poll" {
		t.Fatalf("%s maps to %q, want attestation_device_verdicts_poll", method, tool)
	}
	if _, has := mcpReplyDecoders[method]; !has {
		t.Fatalf("%s has no reply decoder", method)
	}
}

func TestAttestationVerdictsMCP_Poll_ArgsAndDecode(t *testing.T) {
	polls := &verdictPolls{pages: []map[string]interface{}{{
		"cursor": "18f.4",
		"verdicts": []interface{}{map[string]interface{}{"event_id": "ev-1", "device_id": "7", "tenant_id": "t1",
			"passed": true, "recorded_at": "2026-10-09T12:00:00Z"}},
	}}}
	a := verdictAdapter(t, polls, 5*time.Second)
	if a.timeout != 5*time.Second {
		t.Fatalf("timeout = %s, want the transport timeout the stream's polls wait half of", a.timeout)
	}

	resp := &platformv1.PollDeviceVerdictsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_PollDeviceVerdicts_FullMethodName,
		&platformv1.PollDeviceVerdictsRequest{Cursor: "18f.3", WaitMs: 2500}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(polls.polls) != 1 || polls.polls[0]["cursor"] != "18f.3" || polls.polls[0]["wait_ms"] != float64(2500) {
		t.Fatalf("polls = %+v, want the cursor and wait as arguments", polls.polls)
	}
	if resp.GetCursor() != "18f.4" || len(resp.GetVerdicts()) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	v := resp.GetVerdicts()[0]
	if v.GetEventId() != "ev-1" || v.GetDeviceId() != 7 || v.GetTenantId() != "t1" || !v.GetPassed() ||
		v.GetRecordedAt().AsTime().Year() != 2026 {
		t.Fatalf("verdict = %+v", v)
	}
}

// TestAttestationVerdictsMCP_StreamLongPolls opens StreamDeviceVerdicts over
// MCP through the generated client: the adapter follows the feed by
// long-polling the tool, each poll waiting half the transport timeout, until
// a poll fails.
func TestAttestationVerdictsMCP_StreamLongPolls(t *testing.T) {
	polls := &verdictPolls{pages: []map[string]interface{}{
		{"cursor": "18f.0"},
		{"cursor": "18f.1", "verdicts": []interface{}{map[string]interface{}{"event_id": "ev-1", "device_id": "7"}}},
	}}
	a := verdictAdapterWithoutRetries(t, polls, 8*time.Second)

	stream, err := platformv1.NewAttestationServiceClient(a.Connection()).
		StreamDeviceVerdicts(context.Background(), &platformv1.StreamDeviceVerdictsRequest{})
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	got, err := stream.Recv()
	if err != nil || got.GetEventId() != "ev-1" || got.GetDeviceId() != 7 {
		t.Fatalf("Recv = %+v, %v", got, err)
	}
	// JSON-RPC has no code for ResourceExhausted, so the daemon's missed
	// verdicts reach the stream as Internal with its message.
	if _, err := stream.Recv(); status.Code(err) != codes.Internal {
		t.Fatalf("Recv = %v, want Internal", err)
	}
	if len(polls.polls) != 3 || polls.polls[0]["wait_ms"] != nil ||
		polls.polls[1]["cursor"] != "18f.0" || polls.polls[1]["wait_ms"] != float64(4000) ||
		polls.polls[2]["cursor"] != "18f.1" {
		t.Fatalf("polls = %+v", polls.polls)
	}
}

func TestAttestationVerdictsMCP_StreamRefusesOtherStreams(t *testing.T) {
	a := verdictAdapter(t, &verdictPolls{}, 5*time.Second)
	_, err := a.Connection().NewStream(context.Background(), nil, "/platform.v1.PlatformDaemon/StreamEvents")
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("NewStream = %v, want Unimplemented", err)
	}
}

func TestAttestationVerdictsMCP_DecoderRejectsWrongReplyAndBadShape(t *testing.T) {
	var wrong ErrUnexpectedReplyType
	if err := decodeDeviceVerdictsResult(map[string]interface{}{}, &platformv1.GetNonceResponse{}); !errors.As(err, &wrong) {
		t.Fatalf("wrong reply type: err = %v, want ErrUnexpectedReplyType", err)
	}
	var bad ErrUnmarshalFailed
	if err := decodeDeviceVerdictsResult([]interface{}{"not", "an", "object"}, &platformv1.PollDeviceVerdictsResponse{}); !errors.As(err, &bad) {
		t.Fatalf("bad shape: err = %v, want ErrUnmarshalFailed", err)
	}
}
