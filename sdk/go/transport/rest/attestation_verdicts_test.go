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
package rest

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictPolls answers GET /api/v1/attestation/verdicts from a script of
// envelope bodies and records each poll's query.
type verdictPolls struct {
	mu      sync.Mutex
	bodies  []string
	queries []string
}

func (p *verdictPolls) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health/live" {
		w.WriteHeader(http.StatusOK)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Method != http.MethodGet || r.URL.Path != "/api/v1/attestation/verdicts" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	p.queries = append(p.queries, r.URL.RawQuery)
	if len(p.bodies) == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body := p.bodies[0]
	p.bodies = p.bodies[1:]
	w.Header().Set("Content-Type", "application/json")
	if body == "" {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":429,"error":"attestation: verdicts were missed","success":false}`))
		return
	}
	_, _ = w.Write([]byte(envelope(body)))
}

func TestAttestationVerdicts_Poll_RouteAndDecode(t *testing.T) {
	polls := &verdictPolls{bodies: []string{`{"cursor":"18f.4","verdicts":[{"event_id":"ev-1","device_id":"7",
"tenant_id":"t1","passed":true,"recorded_at":"2026-10-09T12:00:00Z"}]}`}}
	a, _ := adapterAgainst(t, polls.serve)

	resp := &platformv1.PollDeviceVerdictsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_PollDeviceVerdicts_FullMethodName,
		&platformv1.PollDeviceVerdictsRequest{Cursor: "18f.3", WaitMs: 2500}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(polls.queries) != 1 || polls.queries[0] != "cursor=18f.3&wait_ms=2500" {
		t.Fatalf("queries = %q, want the cursor and wait as query parameters", polls.queries)
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

// TestAttestationVerdicts_StreamLongPolls opens StreamDeviceVerdicts over
// REST through the generated client: the adapter follows the feed by
// long-polling the verdicts route, and a missed-verdicts 429 ends the stream
// as ResourceExhausted.
func TestAttestationVerdicts_StreamLongPolls(t *testing.T) {
	polls := &verdictPolls{bodies: []string{
		`{"cursor":"18f.0"}`,
		`{"cursor":"18f.1","verdicts":[{"event_id":"ev-1","device_id":"7"}]}`,
		"",
	}}
	a, _ := adapterAgainst(t, polls.serve)

	stream, err := platformv1.NewAttestationServiceClient(a.Connection()).
		StreamDeviceVerdicts(context.Background(), &platformv1.StreamDeviceVerdictsRequest{})
	if err != nil {
		t.Fatalf("StreamDeviceVerdicts: %v", err)
	}
	got, err := stream.Recv()
	if err != nil || got.GetEventId() != "ev-1" {
		t.Fatalf("Recv = %+v, %v", got, err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("Recv = %v, want ResourceExhausted", err)
	}
	// The default 5s transport timeout lets each poll wait 2.5s.
	want := []string{"", "cursor=18f.0&wait_ms=2500", "cursor=18f.1&wait_ms=2500"}
	if len(polls.queries) != len(want) {
		t.Fatalf("queries = %q, want %q", polls.queries, want)
	}
	for i := range want {
		if polls.queries[i] != want[i] {
			t.Fatalf("queries = %q, want %q", polls.queries, want)
		}
	}
}

func TestAttestationVerdicts_StreamRefusesOtherStreams(t *testing.T) {
	a, _ := adapterAgainst(t, (&verdictPolls{}).serve)
	_, err := a.Connection().NewStream(context.Background(), nil, "/platform.v1.PlatformDaemon/StreamEvents")
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("NewStream = %v, want Unimplemented", err)
	}
}
