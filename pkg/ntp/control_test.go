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

package ntp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// syncedTrackingCSV is a real `chronyc -c tracking` line from a converged
// node (14 fields).
const syncedTrackingCSV = "CB00710F,10.4.200.1,3,1755000000.500000000," +
	"-0.000012345,-0.000009876,0.000021000,-1.234,0.001,0.100,0.023000,0.045000,64.2,Normal\n"

// unsyncedTrackingCSV is what chronyd reports before it has a reference.
const unsyncedTrackingCSV = "7F7F0101,,0,0.000000000," +
	"0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,0.000000,0.000000,0.0,Not synchronised\n"

// sourcesCSV is a real `chronyc -c sources` capture: one selected server, one
// unreachable pool member.
const sourcesCSV = "^,*,10.4.200.1,2,6,377,23,-0.000021,-0.000019,0.000110\n" +
	"^,?,203.0.113.9,0,6,0,0,0.000000,0.000000,0.000000\n"

// fakeCall records one CommandRunner invocation.
type fakeCall struct {
	Name string
	Args []string
}

// fakeRunner is a scripted CommandRunner. Responses are keyed by the last
// argument (the chronyc/rc-service verb) so tests stay readable.
type fakeRunner struct {
	responses map[string]fakeResponse
	fallback  fakeResponse
	calls     []fakeCall
}

// fakeResponse is one scripted command result.
type fakeResponse struct {
	Output string
	Err    error
}

// newFakeRunner builds a runner with the given scripted responses.
func newFakeRunner(responses map[string]fakeResponse) *fakeRunner {
	return &fakeRunner{responses: responses}
}

// Run records the call and returns the scripted response.
func (r *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, fakeCall{Name: name, Args: args})
	key := name
	if len(args) > 0 {
		key = args[len(args)-1]
	}
	if resp, ok := r.responses[key]; ok {
		return []byte(resp.Output), resp.Err
	}
	return []byte(r.fallback.Output), r.fallback.Err
}

// callFor returns the first recorded call whose last argument matches verb.
func (r *fakeRunner) callFor(verb string) (fakeCall, bool) {
	for _, call := range r.calls {
		if len(call.Args) > 0 && call.Args[len(call.Args)-1] == verb {
			return call, true
		}
	}
	return fakeCall{}, false
}

func TestControllerReadsTrackingAndSources(t *testing.T) {
	runner := newFakeRunner(map[string]fakeResponse{
		"tracking": {Output: syncedTrackingCSV},
		"sources":  {Output: sourcesCSV},
		"makestep": {Output: "200 OK\n"},
	})
	controller := NewController("/run/chrony/chronyd.sock", runner)
	ctx := context.Background()

	tracking, err := controller.Tracking(ctx)
	if err != nil {
		t.Fatalf("Tracking() error = %v", err)
	}
	if !tracking.Synced() {
		t.Fatal("Synced() = false, want true")
	}
	if tracking.Stratum != 3 {
		t.Fatalf("Stratum = %d, want 3", tracking.Stratum)
	}
	if tracking.ReferenceName != "10.4.200.1" {
		t.Fatalf("ReferenceName = %q, want 10.4.200.1", tracking.ReferenceName)
	}
	if tracking.RootDispersion != 0.045 {
		t.Fatalf("RootDispersion = %v, want 0.045", tracking.RootDispersion)
	}
	if tracking.RootDelay != 0.023 {
		t.Fatalf("RootDelay = %v, want 0.023", tracking.RootDelay)
	}
	if tracking.RefTime.IsZero() {
		t.Fatal("RefTime is zero, want the parsed reference timestamp")
	}

	sources, err := controller.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources() error = %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("len(sources) = %d, want 2", len(sources))
	}
	if sources[0].State != SourceStateSelected || sources[0].Mode != SourceModeServer {
		t.Fatalf("source[0] = %+v, want selected server", sources[0])
	}
	if !sources[0].Reachable || sources[0].Reach != 377 {
		t.Fatalf("source[0] reachability = %v/%d, want true/377", sources[0].Reachable, sources[0].Reach)
	}
	if sources[0].PollSeconds != 64 {
		t.Fatalf("source[0].PollSeconds = %d, want 64 (log2 poll 6)", sources[0].PollSeconds)
	}
	if sources[1].State != SourceStateUnreachable || sources[1].Reachable {
		t.Fatalf("source[1] = %+v, want unreachable", sources[1])
	}

	if err := controller.MakeStep(ctx); err != nil {
		t.Fatalf("MakeStep() error = %v", err)
	}

	// The control client must talk to the Unix socket in CSV mode with
	// reverse DNS disabled, never over the network.
	call, ok := runner.callFor("tracking")
	if !ok {
		t.Fatal("no tracking call recorded")
	}
	joined := strings.Join(call.Args, " ")
	for _, want := range []string{"-c", "-n", "-h /run/chrony/chronyd.sock"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("chronyc args %q missing %q", joined, want)
		}
	}
}

func TestControllerSurfacesUnavailableSocket(t *testing.T) {
	runner := newFakeRunner(nil)
	runner.fallback = fakeResponse{Output: "506 Cannot talk to daemon", Err: errors.New("exit status 1")}
	controller := NewController("", runner)
	ctx := context.Background()

	var unavailable ErrControlUnavailable
	if _, err := controller.Tracking(ctx); !errors.As(err, &unavailable) {
		t.Fatalf("Tracking() error = %v, want ErrControlUnavailable", err)
	}
	if unavailable.Command != "tracking" {
		t.Fatalf("Command = %q, want tracking", unavailable.Command)
	}
	if _, err := controller.Sources(ctx); !errors.As(err, &unavailable) {
		t.Fatalf("Sources() error = %v, want ErrControlUnavailable", err)
	}
	if err := controller.MakeStep(ctx); !errors.As(err, &unavailable) {
		t.Fatalf("MakeStep() error = %v, want ErrControlUnavailable", err)
	}

	// With no socket configured chronyc must fall back to its own default
	// rather than being handed an empty -h.
	call, ok := runner.callFor("tracking")
	if !ok {
		t.Fatal("no tracking call recorded")
	}
	if strings.Contains(strings.Join(call.Args, " "), "-h") {
		t.Fatalf("args %v should omit -h when no socket is configured", call.Args)
	}
}

func TestParseTrackingRejectsMalformedOutput(t *testing.T) {
	cases := map[string]string{
		"empty output":  "",
		"short record":  "CB00710F,10.4.200.1,3\n",
		"header only\n": "\n",
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			tracking, err := parseTracking(payload)
			if err == nil {
				t.Fatalf("parseTracking() = %+v, want error", tracking)
			}
			var malformed ErrMalformedControlOutput
			if !errors.As(err, &malformed) {
				t.Fatalf("error = %v, want ErrMalformedControlOutput", err)
			}
			if malformed.Want != trackingFieldCount {
				t.Fatalf("Want = %d, want %d", malformed.Want, trackingFieldCount)
			}
		})
	}
}

func TestParseTrackingReportsUnsynchronizedClock(t *testing.T) {
	tracking, err := parseTracking(unsyncedTrackingCSV)
	if err != nil {
		t.Fatalf("parseTracking() error = %v", err)
	}
	if tracking.Synced() {
		t.Fatal("Synced() = true, want false for 'Not synchronised'")
	}
	if !tracking.RefTime.IsZero() {
		t.Fatalf("RefTime = %v, want zero for an unsynchronized clock", tracking.RefTime)
	}

	var nilTracking *Tracking
	if nilTracking.Synced() {
		t.Fatal("nil Tracking.Synced() = true, want false")
	}
}

func TestParseSourcesHandlesEmptyAndMalformedOutput(t *testing.T) {
	sources, err := parseSources("\n")
	if err != nil {
		t.Fatalf("parseSources() error = %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("len(sources) = %d, want 0", len(sources))
	}

	if _, err := parseSources("^,*,10.4.200.1,2\n"); err == nil {
		t.Fatal("parseSources() = nil error, want ErrMalformedControlOutput")
	}
}

func TestParseSourceModeAndStateCoverUnknownValues(t *testing.T) {
	if got := parseSourceMode("@"); got != SourceModeUnknown {
		t.Fatalf("parseSourceMode(@) = %q, want unknown", got)
	}
	if got := parseSourceState("@"); got != SourceStateUnknown {
		t.Fatalf("parseSourceState(@) = %q, want unknown", got)
	}
	if got := parseSourceMode("="); got != SourceModePeer {
		t.Fatalf("parseSourceMode(=) = %q, want peer", got)
	}
	if got := parseSourceState("x"); got != SourceStateFalseTicker {
		t.Fatalf("parseSourceState(x) = %q, want falseticker", got)
	}
}

func TestNumericParsersTolerateGarbage(t *testing.T) {
	if got := parseUint32("not-a-number"); got != 0 {
		t.Fatalf("parseUint32 = %d, want 0", got)
	}
	if got := parseInt64("not-a-number"); got != 0 {
		t.Fatalf("parseInt64 = %d, want 0", got)
	}
	if got := parseFloat("not-a-number"); got != 0 {
		t.Fatalf("parseFloat = %v, want 0", got)
	}
	if got := parseUnixFloat("-1"); !got.IsZero() {
		t.Fatalf("parseUnixFloat(-1) = %v, want zero time", got)
	}
	if got := pollIntervalSeconds("99"); got != 0 {
		t.Fatalf("pollIntervalSeconds(99) = %d, want 0", got)
	}
	if got := pollIntervalSeconds("0"); got != 1 {
		t.Fatalf("pollIntervalSeconds(0) = %d, want 1", got)
	}
}
