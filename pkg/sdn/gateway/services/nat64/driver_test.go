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

package nat64

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The scripted outputs below are the jool 4.1.14 tool's real output, read
// from the Alpine 3.22 kernel the integration VM boots
// (test/integration/nat64): the CSV column orders, the per-address pool4
// rows, and the refusal to change a NAT64 instance's pool6.
const (
	instanceHeader  = "Namespace,Name,Framework\n"
	instancePresent = instanceHeader + "b0970040,tp-nat64,netfilter\n"
	globalDisplay   = "Field,Value\nmanually-enabled,TRUE\npool6,64:ff9b::/96\ntcp-est-timeout,2:00:00\n"
)

// recordingRunner records every command line and answers from an ordered
// script: the first rule whose substring the command contains wins, so a
// test reads its answers in the order it declared them.
type recordingRunner struct {
	mu    sync.Mutex
	cmds  []string
	rules []runRule
}

type runRule struct {
	contains string
	out      string
	err      error
}

func newRecordingRunner(rules ...runRule) *recordingRunner {
	return &recordingRunner{rules: rules}
}

func (r *recordingRunner) Run(_ context.Context, cmd Command) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := cmd.String()
	r.cmds = append(r.cmds, line)
	for _, rule := range r.rules {
		if strings.Contains(line, rule.contains) {
			return []byte(rule.out), rule.err
		}
	}
	return nil, nil
}

func (r *recordingRunner) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cmds...)
}

// matching returns the recorded commands containing sub.
func (r *recordingRunner) matching(sub string) []string {
	var out []string
	for _, c := range r.recorded() {
		if strings.Contains(c, sub) {
			out = append(out, c)
		}
	}
	return out
}

// testInstance is the instance every driver test programs.
func testInstance() Instance {
	return Instance{
		Name:  "tp-nat64",
		Pool6: "64:ff9b::/96",
		Pool4: []Pool4Range{
			{Addresses: "203.0.113.64-203.0.113.71", PortStart: 61001, PortEnd: 65535},
		},
		Timeouts: SessionTimeouts{}.WithDefaults(),
	}
}

// pool4Rows renders `jool pool4 display --<proto> --csv --no-headers` rows
// for the given addresses on one protocol: the tool shows one protocol's
// table per call, and TCP's when none is named.
func pool4Rows(proto string, addrs []string, ports string) string {
	var b strings.Builder
	for _, a := range addrs {
		b.WriteString("0," + proto + "," + a + "," + strings.Replace(ports, "-", ",", 1) + ",1024,0\n")
	}
	return b.String()
}

// pool4Display answers the three per-protocol pool4 reads.
func pool4Display(addrs []string, ports string) []runRule {
	return []runRule{
		{contains: "pool4 display --tcp", out: pool4Rows("TCP", addrs, ports)},
		{contains: "pool4 display --udp", out: pool4Rows("UDP", addrs, ports)},
		{contains: "pool4 display --icmp", out: pool4Rows("ICMP", addrs, ports)},
	}
}

func testAddrs() []string {
	var out []string
	for i := 64; i <= 71; i++ {
		out = append(out, "203.0.113."+strconv.Itoa(i))
	}
	return out
}

func TestJoolTimeout_RendersTheOnlyFormatJoolParses(t *testing.T) {
	// A Go duration string ("2h4m0s") is rejected by jool, so the H:MM:SS
	// rendering is load-bearing, not cosmetic.
	tests := []struct {
		in   time.Duration
		want string
	}{
		{5 * time.Minute, "0:05:00"},
		{2*time.Hour + 4*time.Minute, "2:04:00"},
		{4 * time.Minute, "0:04:00"},
		{60 * time.Second, "0:01:00"},
		{90 * time.Second, "0:01:30"},
		{25 * time.Hour, "25:00:00"},
	}
	for _, tc := range tests {
		if got := joolTimeout(tc.in); got != tc.want {
			t.Fatalf("joolTimeout(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRangePrefixes_TilesARangeWithTheFewestPrefixes(t *testing.T) {
	// jool refuses "a-b" ("too long for this poor, limited parser"), so a
	// configured range must become the exact CIDR tiling.
	tests := []struct {
		first, last string
		want        []string
	}{
		{"203.0.113.64", "203.0.113.71", []string{"203.0.113.64/29"}},
		{"203.0.113.64", "203.0.113.64", []string{"203.0.113.64/32"}},
		{"203.0.113.65", "203.0.113.70", []string{"203.0.113.65/32", "203.0.113.66/31", "203.0.113.68/31", "203.0.113.70/32"}},
		{"10.0.0.0", "10.0.1.255", []string{"10.0.0.0/23"}},
		{"255.255.255.254", "255.255.255.255", []string{"255.255.255.254/31"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
	}
	for _, tc := range tests {
		got := rangePrefixes(netip.MustParseAddr(tc.first), netip.MustParseAddr(tc.last))
		var gotS []string
		for _, p := range got {
			gotS = append(gotS, p.String())
		}
		if strings.Join(gotS, " ") != strings.Join(tc.want, " ") {
			t.Fatalf("rangePrefixes(%s, %s) = %v, want %v", tc.first, tc.last, gotS, tc.want)
		}
	}
}

func TestRenderCreate_IsTheFullInstanceBringUp(t *testing.T) {
	got, err := RenderCreate(testInstance())
	if err != nil {
		t.Fatalf("RenderCreate() = %v", err)
	}
	want := []string{
		"jool instance add tp-nat64 --netfilter --pool6 64:ff9b::/96",
		"jool --instance tp-nat64 pool4 add --tcp 203.0.113.64/29 61001-65535",
		"jool --instance tp-nat64 pool4 add --udp 203.0.113.64/29 61001-65535",
		"jool --instance tp-nat64 pool4 add --icmp 203.0.113.64/29 61001-65535",
		"jool --instance tp-nat64 global update udp-timeout 0:05:00",
		"jool --instance tp-nat64 global update tcp-est-timeout 2:04:00",
		"jool --instance tp-nat64 global update tcp-trans-timeout 0:04:00",
		"jool --instance tp-nat64 global update icmp-timeout 0:01:00",
	}
	if len(got) != len(want) {
		t.Fatalf("RenderCreate() produced %d commands, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Fatalf("command %d = %q, want %q", i, got[i].String(), want[i])
		}
	}
}

func TestRenderCreate_RefusesARangeThatDoesNotParse(t *testing.T) {
	inst := testInstance()
	inst.Pool4 = []Pool4Range{{Addresses: "not-an-address", PortStart: 1, PortEnd: 2}}
	if _, err := RenderCreate(inst); !errors.Is(err, ErrInvalidPool4Range) {
		t.Fatalf("RenderCreate() = %v, want %v", err, ErrInvalidPool4Range)
	}
	if _, err := RenderPool4(inst); !errors.Is(err, ErrInvalidPool4Range) {
		t.Fatalf("RenderPool4() = %v, want %v", err, ErrInvalidPool4Range)
	}
}

func TestRenderPool4_RegistersEveryProtocol(t *testing.T) {
	// A protocol with no pool4 addresses has nothing to translate to, and
	// its traffic is dropped, so all three are registered per prefix.
	inst := testInstance()
	inst.Pool4 = append(inst.Pool4, Pool4Range{Addresses: "203.0.113.80", PortStart: 1024, PortEnd: 2048})
	got, err := RenderPool4(inst)
	if err != nil {
		t.Fatalf("RenderPool4() = %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("RenderPool4() produced %d commands for 2 prefixes, want 6", len(got))
	}
	for _, proto := range []string{"--tcp", "--udp", "--icmp"} {
		var seen int
		for _, cmd := range got {
			if strings.Contains(cmd.String(), proto+" ") {
				seen++
			}
		}
		if seen != 2 {
			t.Fatalf("protocol %s registered %d times, want once per prefix", proto, seen)
		}
	}
}

func TestJoolDriverApply_CreatesAnInstanceThatIsNotThere(t *testing.T) {
	runner := newRecordingRunner(runRule{contains: "instance display", out: instanceHeader})
	d := newJoolDriverWithRunner(runner)

	created, err := d.Apply(context.Background(), testInstance())
	if err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if !created {
		t.Fatal("Apply() created the instance but reported it adopted")
	}
	if len(runner.matching("instance add tp-nat64")) != 1 {
		t.Fatalf("Apply() on a missing instance did not create it: %v", runner.recorded())
	}
}

func TestJoolDriverApply_KeepsTheSessionsOfAnInstanceThatIsAlreadyThere(t *testing.T) {
	// Recreating the instance would drop every live translation.
	runner := newRecordingRunner(append([]runRule{
		{contains: "instance display", out: instancePresent},
		{contains: "global display", out: globalDisplay},
	}, pool4Display(testAddrs(), "61001-65535")...)...)
	d := newJoolDriverWithRunner(runner)

	created, err := d.Apply(context.Background(), testInstance())
	if err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if created {
		t.Fatal("Apply() reported an adopted instance as created")
	}
	if c := runner.matching("instance add"); len(c) != 0 {
		t.Fatalf("Apply() recreated a live instance: %v", c)
	}
	if c := runner.matching("instance remove"); len(c) != 0 {
		t.Fatalf("Apply() tore down a live instance: %v", c)
	}
	if c := runner.matching("pool4 add"); len(c) != 0 {
		t.Fatalf("Apply() re-added entries the kernel already holds: %v", c)
	}
	if c := runner.matching("global update"); len(c) != 4 {
		t.Fatalf("Apply() did not re-set the four timeouts: %v", runner.recorded())
	}
}

func TestJoolDriverApply_ConvergesPool4ByDifference(t *testing.T) {
	// The kernel holds .64 and a stray .99; the configuration names .64
	// and .65. The stray goes, the missing one comes, .64 is untouched.
	// Removals run first: jool merges an added port range into an
	// overlapping one and a removal then takes both.
	inst := testInstance()
	inst.Pool4 = []Pool4Range{{Addresses: "203.0.113.64-203.0.113.65", PortStart: 61001, PortEnd: 65535}}
	display := pool4Display([]string{"203.0.113.64", "203.0.113.99"}, "61001-65535")
	display[0].out += "7,TCP,198.51.100.1,1,2,1024,0\n"
	runner := newRecordingRunner(append([]runRule{
		{contains: "instance display", out: instancePresent},
		{contains: "global display", out: globalDisplay},
	}, display...)...)
	d := newJoolDriverWithRunner(runner)

	if _, err := d.Apply(context.Background(), inst); err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	adds := runner.matching("pool4 add")
	if len(adds) != 3 {
		t.Fatalf("adds = %v, want .65 for each of three protocols", adds)
	}
	for _, a := range adds {
		if !strings.Contains(a, "203.0.113.65 61001-65535") {
			t.Fatalf("unexpected add %q", a)
		}
	}
	removes := runner.matching("pool4 remove")
	if len(removes) != 3 {
		t.Fatalf("removes = %v, want .99 for each of three protocols", removes)
	}
	for _, r := range removes {
		if !strings.Contains(r, "203.0.113.99 61001-65535") {
			t.Fatalf("unexpected remove %q", r)
		}
	}
	all := strings.Join(runner.recorded(), "\n")
	if strings.LastIndex(all, "pool4 remove") > strings.Index(all, "pool4 add") {
		t.Fatalf("an addition ran before every removal: %v", runner.recorded())
	}
	if strings.Contains(all, "203.0.113.64 ") {
		t.Fatalf("an unchanged entry was touched: %v", runner.recorded())
	}
	if strings.Contains(all, "198.51.100.1") {
		t.Fatalf("an entry under another mark was touched: %v", runner.recorded())
	}
}

func TestJoolDriverApply_RecreatesAnInstanceWhosePrefixChanged(t *testing.T) {
	// jool refuses to change a NAT64 instance's pool6, and every session
	// maps a client through the prefix, so a new prefix means a new
	// instance.
	inst := testInstance()
	inst.Pool6 = "2001:db8:64::/96"
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "global display", out: globalDisplay},
	)
	d := newJoolDriverWithRunner(runner)

	created, err := d.Apply(context.Background(), inst)
	if err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if !created {
		t.Fatal("a recreated instance must be reported created")
	}
	all := strings.Join(runner.recorded(), "\n")
	rm := strings.Index(all, "jool instance remove tp-nat64")
	add := strings.Index(all, "jool instance add tp-nat64 --netfilter --pool6 2001:db8:64::/96")
	if rm < 0 || add < 0 || rm > add {
		t.Fatalf("want remove then add with the new prefix: %v", runner.recorded())
	}
}

func TestJoolDriverApply_ReportsAnUnreadablePrefix(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "global display", out: "Field,Value\nmanually-enabled,TRUE\n"},
	)
	_, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance())
	if !errors.Is(err, ErrPool6Unreadable) {
		t.Fatalf("Apply() = %v, want %v", err, ErrPool6Unreadable)
	}

	failing := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "global display", out: "Error", err: errors.New("exit status 1")},
	)
	var op *OpError
	if _, err := newJoolDriverWithRunner(failing).Apply(context.Background(), testInstance()); !errors.As(err, &op) {
		t.Fatalf("Apply() = %v, want *OpError", err)
	}
}

func TestJoolDriverApply_ReportsAFailedPool4Read(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "global display", out: globalDisplay},
		runRule{contains: "pool4 display", out: "Error", err: errors.New("exit status 3")},
	)
	var op *OpError
	if _, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance()); !errors.As(err, &op) || op.Op != "read" {
		t.Fatalf("Apply() = %v, want *OpError{Op: read}", err)
	}
}

func TestJoolDriverApply_ReportsAFailedConvergenceStep(t *testing.T) {
	for _, step := range []string{"pool4 add", "pool4 remove", "global update"} {
		t.Run(step, func(t *testing.T) {
			runner := newRecordingRunner(append(append([]runRule{
				{contains: "instance display", out: instancePresent},
				{contains: "global display", out: globalDisplay},
			}, pool4Display([]string{"203.0.113.99"}, "61001-65535")...),
				runRule{contains: step, out: "Error: nope", err: errors.New("exit status 1")})...)
			_, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance())
			var cmdErr *CommandError
			if !errors.As(err, &cmdErr) || !strings.Contains(cmdErr.Error(), "Error: nope") {
				t.Fatalf("Apply() = %v, want the failing command and its output", err)
			}
		})
	}
}

func TestJoolDriverApply_RefusesTheSectionWhenTheModuleIsAbsent(t *testing.T) {
	// A kernel upgrade that outruns the module package must show up as a
	// refused section, never as silent pass-through.
	runner := newRecordingRunner(runRule{
		contains: "instance display",
		out:      "modprobe: FATAL: Module jool not found",
		err:      errors.New("exit status 1"),
	})
	_, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance())
	var typed *ErrNAT64ModuleUnavailable
	if !errors.As(err, &typed) {
		t.Fatalf("Apply() = %v, want *ErrNAT64ModuleUnavailable", err)
	}
	if typed.Instance != "tp-nat64" {
		t.Fatalf("error names instance %q, want tp-nat64", typed.Instance)
	}
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || !strings.Contains(cmdErr.Error(), "Module jool not found") {
		t.Fatalf("error drops the tool's own output: %v", err)
	}
}

func TestJoolDriverApply_AnInstanceTheModuleRefusesIsModuleUnavailable(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instanceHeader},
		runRule{contains: "instance add", out: "Error: pool6 prefix is not supported", err: errors.New("exit status 1")},
	)
	_, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance())
	var typed *ErrNAT64ModuleUnavailable
	if !errors.As(err, &typed) {
		t.Fatalf("Apply() = %v, want *ErrNAT64ModuleUnavailable", err)
	}
	if c := runner.matching("instance remove"); len(c) != 0 {
		t.Fatalf("nothing was created, so nothing may be removed: %v", c)
	}
}

func TestJoolDriverApply_RemovesAHalfBuiltInstance(t *testing.T) {
	// The instance came up but a pool4 registration failed: the half-built
	// instance is removed, and the failure is reported as the command's.
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instanceHeader},
		runRule{contains: "pool4 add --udp", out: "Error: overlap", err: errors.New("exit status 1")},
	)
	_, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance())
	var op *OpError
	if !errors.As(err, &op) || op.Op != "apply" {
		t.Fatalf("Apply() = %v, want *OpError{Op: apply}", err)
	}
	if c := runner.matching("jool instance remove tp-nat64"); len(c) != 1 {
		t.Fatalf("the half-built instance was not removed: %v", runner.recorded())
	}
}

func TestJoolDriverApply_ReportsAHalfBuiltInstanceItCouldNotRemove(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instanceHeader},
		runRule{contains: "pool4 add --udp", out: "Error: overlap", err: errors.New("exit status 1")},
		runRule{contains: "instance remove", out: "Error: busy", err: errors.New("exit status 1")},
	)
	_, err := newJoolDriverWithRunner(runner).Apply(context.Background(), testInstance())
	if err == nil || !strings.Contains(err.Error(), "overlap") || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("Apply() = %v, want both the cause and the failed cleanup", err)
	}
}

func TestJoolDriverRemove_IsIdempotent(t *testing.T) {
	runner := newRecordingRunner(runRule{contains: "instance display", out: instanceHeader})
	if err := newJoolDriverWithRunner(runner).Remove(context.Background(), "tp-nat64"); err != nil {
		t.Fatalf("Remove() of an absent instance = %v, want nil", err)
	}
	if c := runner.matching("instance remove"); len(c) != 0 {
		t.Fatalf("Remove() tried to delete an instance that was not there: %v", c)
	}
}

func TestJoolDriverRemove_DeletesAnInstanceThatIsThere(t *testing.T) {
	runner := newRecordingRunner(runRule{contains: "instance display", out: instancePresent})
	if err := newJoolDriverWithRunner(runner).Remove(context.Background(), "tp-nat64"); err != nil {
		t.Fatalf("Remove() = %v", err)
	}
	if c := runner.matching("jool instance remove tp-nat64"); len(c) != 1 {
		t.Fatalf("Remove() did not delete the instance: %v", runner.recorded())
	}
}

func TestJoolDriverRemove_ReportsAFailedDeletion(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "instance remove", out: "Error: permission denied", err: errors.New("exit status 1")},
	)
	err := newJoolDriverWithRunner(runner).Remove(context.Background(), "tp-nat64")
	var typed *OpError
	if !errors.As(err, &typed) || typed.Op != "remove" {
		t.Fatalf("Remove() = %v, want *OpError{Op: remove}", err)
	}
}

func TestJoolDriverInstancePresent_MatchesTheNameColumnOnly(t *testing.T) {
	// A namespace id equal to the instance name is not the instance.
	runner := newRecordingRunner(runRule{contains: "instance display", out: instanceHeader + "tp-nat64,other,netfilter\n"})
	present, err := newJoolDriverWithRunner(runner).instancePresent(context.Background(), "tp-nat64")
	if err != nil {
		t.Fatalf("instancePresent() = %v", err)
	}
	if present {
		t.Fatal("a namespace column was taken for the instance name")
	}
}

func TestJoolDriverStats_ReportsWhatTheKernelHolds(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "stats display", out: "Stat,Value\nJSTAT_RECEIVED6,1200\nJSTAT_SESSIONS,42\nJSTAT_BIB_ENTRIES,17\nJSTAT_UNKNOWN_FUTURE_COUNTER,9\n"},
		runRule{contains: "--version", out: "4.1.14.0\n"},
	)
	stats, err := newJoolDriverWithRunner(runner).Stats(context.Background(), "tp-nat64")
	if err != nil {
		t.Fatalf("Stats() = %v", err)
	}
	if !stats.Present || stats.Sessions != 42 || stats.Pool4Used != 17 || stats.ModuleVersion != "4.1.14.0" {
		t.Fatalf("Stats() = %+v", stats)
	}
}

func TestJoolDriverStats_ReportsAnAbsentInstanceRatherThanFailing(t *testing.T) {
	// A started service whose instance has gone must be reported unhealthy,
	// which needs Stats to answer rather than error.
	runner := newRecordingRunner(runRule{contains: "instance display", out: instanceHeader})
	stats, err := newJoolDriverWithRunner(runner).Stats(context.Background(), "tp-nat64")
	if err != nil {
		t.Fatalf("Stats() = %v", err)
	}
	if stats.Present {
		t.Fatal("Stats() reported an absent instance as present")
	}
}

func TestJoolDriverStats_ReportsAFailedRead(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "stats display", out: "Error: could not read stats", err: errors.New("exit status 1")},
	)
	_, err := newJoolDriverWithRunner(runner).Stats(context.Background(), "tp-nat64")
	var typed *OpError
	if !errors.As(err, &typed) || typed.Op != "stats" {
		t.Fatalf("Stats() = %v, want *OpError{Op: stats}", err)
	}
}

func TestJoolDriverStats_SurvivesAVersionItCannotRead(t *testing.T) {
	runner := newRecordingRunner(
		runRule{contains: "instance display", out: instancePresent},
		runRule{contains: "stats display", out: "JSTAT_SESSIONS,3\n"},
		runRule{contains: "--version", err: errors.New("exit status 127")},
	)
	stats, err := newJoolDriverWithRunner(runner).Stats(context.Background(), "tp-nat64")
	if err != nil {
		t.Fatalf("Stats() = %v, want an unreadable version tolerated", err)
	}
	if stats.ModuleVersion != "" || stats.Sessions != 3 {
		t.Fatalf("Stats() = %+v", stats)
	}
}

func TestParseStatsCSV_IgnoresGarbageAndUnknownCounters(t *testing.T) {
	// Jool adds counters between releases; an unknown one is not a reason
	// to call the translator unhealthy.
	sessions, used := parseStatsCSV([]byte(
		"\nnot-a-line\nJSTAT_SESSIONS,not-a-number\nJSTAT_FUTURE,1\nJSTAT_BIB_ENTRIES,5\n"))
	if sessions != 0 {
		t.Fatalf("sessions = %d, want 0 for an unparseable value", sessions)
	}
	if used != 5 {
		t.Fatalf("pool4Used = %d, want 5", used)
	}
}

func TestExecRunner_RefusesAnEmptyCommand(t *testing.T) {
	if _, err := (execRunner{}).Run(context.Background(), Command{}); !errors.Is(err, ErrEmptyCommand) {
		t.Fatalf("Run(empty) = %v, want %v", err, ErrEmptyCommand)
	}
}

func TestNewJoolDriver_RunsTheRealTool(t *testing.T) {
	if NewJoolDriver().run == nil {
		t.Fatal("NewJoolDriver() built a driver with no runner")
	}
}

func TestJoolDriverPool4_ReadsEveryProtocolTable(t *testing.T) {
	// `jool pool4 display` with no protocol shows TCP alone; reading it
	// once made UDP and ICMP look absent, so every reconcile re-added them
	// and a stale UDP or ICMP entry was never removed.
	runner := newRecordingRunner(pool4Display([]string{"203.0.113.64"}, "61001-65535")...)
	have, err := newJoolDriverWithRunner(runner).pool4(context.Background(), "tp-nat64")
	if err != nil {
		t.Fatalf("pool4() = %v", err)
	}
	if len(have) != 3 {
		t.Fatalf("pool4() = %v, want one entry per protocol", have)
	}
	for _, flag := range []string{"--tcp", "--udp", "--icmp"} {
		if len(runner.matching("pool4 display "+flag)) != 1 {
			t.Fatalf("protocol table %s was not read: %v", flag, runner.recorded())
		}
	}
}

func TestParsePool4Row_RefusesWhatIsNotAnEntry(t *testing.T) {
	for _, line := range []string{
		"",
		"Mark,Protocol,Address,Min port,Max port,Iterations,Iterations fixed",
		"0,TCP,not-an-address,1,2,1024,0",
		"0,TCP,192.0.2.1,x,2,1024,0",
		"0,TCP,192.0.2.1,1,y,1024,0",
		"0,TCP,192.0.2.1",
	} {
		if _, ok := parsePool4Row(line); ok {
			t.Fatalf("parsePool4Row(%q) accepted a row that is not an entry", line)
		}
	}
	e, ok := parsePool4Row("0,UDP,192.0.2.1,61001,65535,1024,0")
	if !ok || e.proto != "UDP" || e.addr != netip.MustParseAddr("192.0.2.1") || e.portStart != 61001 || e.portEnd != 65535 {
		t.Fatalf("parsePool4Row() = %+v, %v", e, ok)
	}
}
