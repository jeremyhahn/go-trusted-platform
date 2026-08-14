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

package ovs

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The fixtures below are hand-built from the OVS 3.3 output formats of
// dpctl/show -s, dpctl/dump-flows, dpctl/dump-conntrack, and
// coverage/show. They are not captures of a live system; field layout and
// key names follow the upstream ovs-dpctl / ovs-appctl man pages.
const (
	fixtureDatapathStats = `system@ovs-system:
  lookups: hit:1319107 missed:2874 lost:3
  flows: 34
  masks: hit:1397295 total:5 hit/pkt:1.06
  port 0: ovs-system (internal)
    RX packets:0 errors:0 dropped:0 overruns:0 frame:0
    TX packets:0 errors:0 dropped:0 aborted:0 carrier:0
    collisions:0
    RX bytes:0  TX bytes:0
  port 1: br-test (internal)
    RX packets:187 errors:0 dropped:2 overruns:0 frame:0
    TX packets:0 errors:0 dropped:0 aborted:0 carrier:0
    collisions:0
    RX bytes:15043 (14.7 KiB)  TX bytes:0`

	fixtureOffloadedFlows = `recirc_id(0),in_port(2),eth(src=0e:aa:00:00:00:01,dst=0e:aa:00:00:00:02),eth_type(0x0800),ipv4(frag=no), packets:11278, bytes:829063, used:0.080s, offloaded:yes, dp:tc, actions:3
recirc_id(0),in_port(3),eth(src=0e:aa:00:00:00:02,dst=0e:aa:00:00:00:01),eth_type(0x0800),ipv4(frag=no), packets:11279, bytes:830131, used:0.080s, offloaded:yes, dp:tc, actions:2`

	fixtureConntrack = `tcp,orig=(src=10.0.1.5,dst=10.100.0.10,sport=44412,dport=443),reply=(src=10.0.2.7,dst=10.0.1.5,sport=8443,dport=44412),zone=12,protoinfo=(state=ESTABLISHED)
tcp,orig=(src=10.0.1.6,dst=10.100.0.10,sport=44413,dport=443),reply=(src=10.0.2.8,dst=10.0.1.6,sport=8443,dport=44413),zone=12,protoinfo=(state=ESTABLISHED)
udp,orig=(src=10.0.1.5,dst=10.0.3.9,sport=5353,dport=53),reply=(src=10.0.3.9,dst=10.0.1.5,sport=53,dport=5353),zone=7
icmp,orig=(src=10.0.1.5,dst=10.0.1.1,id=9,type=8,code=0),reply=(src=10.0.1.1,dst=10.0.1.5,id=9,type=0,code=0)`

	fixtureCoverage = `Event coverage, avg rate over last: 5 seconds, last minute, last hour,  hash=1a2b3c4d:
bridge_reconfigure         0.0/sec     0.000/sec        0.0017/sec   total: 6
ofproto_flush              0.0/sec     0.000/sec        0.0000/sec   total: 1
rev_flow_table             0.2/sec     0.017/sec        0.0106/sec   total: 39
110 events never hit`

	fixturePMDErrorReply = "dpif-netdev/pmd-stats-show: datapath not of type netdev"
)

// fakeUnixctlHandler produces the unixctl reply for one decoded request.
type fakeUnixctlHandler func(method string, params []string) (result string, errReply string)

// fakeUnixctlServer is an in-process unixctl (JSON-RPC over unix socket)
// server. It writes a pid file and listens on the exact control socket
// path ovs-appctl would compose, so Client.AppCtl discovery is exercised
// end-to-end against a real unix socket.
type fakeUnixctlServer struct {
	runDir   string
	listener net.Listener
	handlers map[string]fakeUnixctlHandler
	wg       sync.WaitGroup
}

// newFakeUnixctlServer starts a fake unixctl server in a temp run dir.
// The server is shut down automatically via t.Cleanup.
func newFakeUnixctlServer(t *testing.T, handlers map[string]fakeUnixctlHandler) *fakeUnixctlServer {
	t.Helper()

	runDir := t.TempDir()
	const pid = 4242

	pidPath := filepath.Join(runDir, appctlPidFile)
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	socketPath := filepath.Join(runDir, "ovs-vswitchd."+strconv.Itoa(pid)+".ctl")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen on control socket: %v", err)
	}

	srv := &fakeUnixctlServer{runDir: runDir, listener: listener, handlers: handlers}
	srv.wg.Add(1)
	go srv.acceptLoop()

	t.Cleanup(func() {
		listener.Close()
		srv.wg.Wait()
	})
	return srv
}

// acceptLoop serves connections until the listener closes.
func (s *fakeUnixctlServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(conn)
		}()
	}
}

// serveConn decodes one JSON-RPC request per read and answers it via the
// method handler map (unknown methods mirror ovs-vswitchd's error reply).
func (s *fakeUnixctlServer) serveConn(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)
	for {
		var req struct {
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
			ID     uint64        `json:"id"`
		}
		if err := decoder.Decode(&req); err != nil {
			return
		}

		params := make([]string, 0, len(req.Params))
		for _, p := range req.Params {
			if str, ok := p.(string); ok {
				params = append(params, str)
			}
		}

		reply := map[string]interface{}{"id": req.ID, "result": nil, "error": nil}
		if handler, ok := s.handlers[req.Method]; ok {
			result, errText := handler(req.Method, params)
			if errText != "" {
				reply["error"] = errText
			} else {
				reply["result"] = result
			}
		} else {
			reply["error"] = `"` + req.Method + `" is not a valid command`
		}
		if err := encoder.Encode(reply); err != nil {
			return
		}
	}
}

// newAppCtlClient creates an OVSDB client pointed at the fake server's
// run dir. The OVSDB socket path is never dialed by appctl calls.
func newAppCtlClient(t *testing.T, srv *fakeUnixctlServer) *Client {
	t.Helper()
	client, err := NewClient(filepath.Join(srv.runDir, "db.sock"), WithAppCtlRunDir(srv.runDir))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// staticReply returns a handler that always answers with result.
func staticReply(result string) fakeUnixctlHandler {
	return func(string, []string) (string, string) { return result, "" }
}

func TestAppCtlSuccess(t *testing.T) {
	var gotMethod string
	var gotParams []string
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"dpctl/dump-flows": func(method string, params []string) (string, string) {
			gotMethod = method
			gotParams = params
			return fixtureOffloadedFlows, ""
		},
	})
	client := newAppCtlClient(t, srv)

	out, err := client.AppCtl(context.Background(), "dpctl/dump-flows", "type=offloaded")
	if err != nil {
		t.Fatalf("AppCtl: %v", err)
	}
	if out != fixtureOffloadedFlows {
		t.Errorf("unexpected output: %q", out)
	}
	if gotMethod != "dpctl/dump-flows" {
		t.Errorf("method = %q", gotMethod)
	}
	if len(gotParams) != 1 || gotParams[0] != "type=offloaded" {
		t.Errorf("params = %v", gotParams)
	}
}

func TestAppCtlCommandError(t *testing.T) {
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{})
	client := newAppCtlClient(t, srv)

	_, err := client.AppCtl(context.Background(), "bogus/command")
	var cmdErr *ErrAppCtlCommandFailed
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected ErrAppCtlCommandFailed, got %v", err)
	}
	if cmdErr.Method != "bogus/command" {
		t.Errorf("Method = %q", cmdErr.Method)
	}
}

func TestAppCtlMissingPidFile(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient(filepath.Join(dir, "db.sock"), WithAppCtlRunDir(dir))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.AppCtl(context.Background(), "coverage/show")
	var pidErr *ErrAppCtlPidFileUnavailable
	if !errors.As(err, &pidErr) {
		t.Fatalf("expected ErrAppCtlPidFileUnavailable, got %v", err)
	}
}

func TestAppCtlInvalidPid(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, appctlPidFile), []byte("not-a-pid\n"), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	client, err := NewClient(filepath.Join(dir, "db.sock"), WithAppCtlRunDir(dir))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.AppCtl(context.Background(), "coverage/show")
	var pidErr *ErrAppCtlInvalidPid
	if !errors.As(err, &pidErr) {
		t.Fatalf("expected ErrAppCtlInvalidPid, got %v", err)
	}
	if pidErr.Contents != "not-a-pid" {
		t.Errorf("Contents = %q", pidErr.Contents)
	}
}

func TestAppCtlSocketUnavailable(t *testing.T) {
	dir := t.TempDir()
	// Valid pid file but no control socket behind it.
	if err := os.WriteFile(filepath.Join(dir, appctlPidFile), []byte("99999\n"), 0o644); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	client, err := NewClient(filepath.Join(dir, "db.sock"), WithAppCtlRunDir(dir))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.AppCtl(context.Background(), "coverage/show")
	var sockErr *ErrAppCtlSocketUnavailable
	if !errors.As(err, &sockErr) {
		t.Fatalf("expected ErrAppCtlSocketUnavailable, got %v", err)
	}
}

func TestAppCtlContextCanceled(t *testing.T) {
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"coverage/show": staticReply(fixtureCoverage),
	})
	client := newAppCtlClient(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.AppCtl(ctx, "coverage/show"); err == nil {
		t.Fatal("expected error from canceled context")
	}
}

func TestDumpDatapathFlowsFilter(t *testing.T) {
	var gotParams []string
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"dpctl/dump-flows": func(_ string, params []string) (string, string) {
			gotParams = params
			return fixtureOffloadedFlows, ""
		},
	})
	client := newAppCtlClient(t, srv)

	if _, err := client.DumpDatapathFlows(context.Background(), "type=offloaded"); err != nil {
		t.Fatalf("DumpDatapathFlows: %v", err)
	}
	if len(gotParams) != 1 || gotParams[0] != "type=offloaded" {
		t.Errorf("params = %v", gotParams)
	}

	if _, err := client.DumpDatapathFlows(context.Background(), ""); err != nil {
		t.Fatalf("DumpDatapathFlows without filter: %v", err)
	}
	if len(gotParams) != 0 {
		t.Errorf("params without filter = %v", gotParams)
	}
}

func TestDumpConntrackZones(t *testing.T) {
	var gotParams []string
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"dpctl/dump-conntrack": func(_ string, params []string) (string, string) {
			gotParams = params
			return fixtureConntrack, ""
		},
	})
	client := newAppCtlClient(t, srv)

	if _, err := client.DumpConntrack(context.Background(), -1); err != nil {
		t.Fatalf("DumpConntrack all zones: %v", err)
	}
	if len(gotParams) != 0 {
		t.Errorf("params for all zones = %v", gotParams)
	}

	if _, err := client.DumpConntrack(context.Background(), 12); err != nil {
		t.Fatalf("DumpConntrack zone 12: %v", err)
	}
	if len(gotParams) != 1 || gotParams[0] != "zone=12" {
		t.Errorf("params for zone 12 = %v", gotParams)
	}
}

func TestCoverageShow(t *testing.T) {
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"coverage/show": staticReply(fixtureCoverage),
	})
	client := newAppCtlClient(t, srv)

	out, err := client.CoverageShow(context.Background())
	if err != nil {
		t.Fatalf("CoverageShow: %v", err)
	}
	if out != fixtureCoverage {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestPMDStatsKernelDatapathError(t *testing.T) {
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"dpif-netdev/pmd-stats-show": func(string, []string) (string, string) {
			return "", fixturePMDErrorReply
		},
	})
	client := newAppCtlClient(t, srv)

	_, err := client.PMDStats(context.Background())
	var cmdErr *ErrAppCtlCommandFailed
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected ErrAppCtlCommandFailed, got %v", err)
	}
	if cmdErr.Reply != fixturePMDErrorReply {
		t.Errorf("Reply = %q", cmdErr.Reply)
	}
}

func TestDatapathStats(t *testing.T) {
	var gotParams []string
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"dpctl/show": func(_ string, params []string) (string, string) {
			gotParams = params
			return fixtureDatapathStats, ""
		},
	})
	client := newAppCtlClient(t, srv)

	out, err := client.DatapathStats(context.Background())
	if err != nil {
		t.Fatalf("DatapathStats: %v", err)
	}
	if out != fixtureDatapathStats {
		t.Errorf("unexpected output: %q", out)
	}
	if len(gotParams) != 1 || gotParams[0] != "-s" {
		t.Errorf("params = %v", gotParams)
	}
}

func TestParseDatapathStats(t *testing.T) {
	counters, err := ParseDatapathStats(fixtureDatapathStats)
	if err != nil {
		t.Fatalf("ParseDatapathStats: %v", err)
	}
	if counters.Hits != 1319107 {
		t.Errorf("Hits = %d, want 1319107", counters.Hits)
	}
	if counters.Missed != 2874 {
		t.Errorf("Missed = %d, want 2874", counters.Missed)
	}
	if counters.Lost != 3 {
		t.Errorf("Lost = %d, want 3", counters.Lost)
	}
}

func TestParseDatapathStatsMultipleDatapaths(t *testing.T) {
	output := fixtureDatapathStats + "\nnetdev@ovs-netdev:\n  lookups: hit:100 missed:10 lost:1\n  flows: 2"
	counters, err := ParseDatapathStats(output)
	if err != nil {
		t.Fatalf("ParseDatapathStats: %v", err)
	}
	if counters.Hits != 1319207 || counters.Missed != 2884 || counters.Lost != 4 {
		t.Errorf("summed counters = %+v", counters)
	}
}

func TestParseDatapathStatsUnparseable(t *testing.T) {
	_, err := ParseDatapathStats("no counters here")
	var parseErr *ErrDatapathStatsUnparseable
	if !errors.As(err, &parseErr) {
		t.Fatalf("expected ErrDatapathStatsUnparseable, got %v", err)
	}
}

func TestCountOffloadedFlows(t *testing.T) {
	if n := CountOffloadedFlows(fixtureOffloadedFlows); n != 2 {
		t.Errorf("CountOffloadedFlows = %d, want 2", n)
	}
	if n := CountOffloadedFlows(""); n != 0 {
		t.Errorf("CountOffloadedFlows(empty) = %d, want 0", n)
	}
	if n := CountOffloadedFlows("\n\n  \n"); n != 0 {
		t.Errorf("CountOffloadedFlows(blank lines) = %d, want 0", n)
	}
}

func TestParseConntrackSummary(t *testing.T) {
	summary := ParseConntrackSummary(fixtureConntrack)
	if summary.Total != 4 {
		t.Errorf("Total = %d, want 4", summary.Total)
	}
	if summary.PerZone[12] != 2 {
		t.Errorf("PerZone[12] = %d, want 2", summary.PerZone[12])
	}
	if summary.PerZone[7] != 1 {
		t.Errorf("PerZone[7] = %d, want 1", summary.PerZone[7])
	}
	// The icmp entry has no zone= key and lands in zone 0.
	if summary.PerZone[0] != 1 {
		t.Errorf("PerZone[0] = %d, want 1", summary.PerZone[0])
	}
}

func TestParseConntrackSummaryEmpty(t *testing.T) {
	summary := ParseConntrackSummary("")
	if summary.Total != 0 || len(summary.PerZone) != 0 {
		t.Errorf("empty dump summary = %+v", summary)
	}
}

func TestAppCtlTypedErrorMessages(t *testing.T) {
	cause := errors.New("cause")

	pidErr := &ErrAppCtlPidFileUnavailable{Path: "/run/x.pid", Cause: cause}
	if pidErr.Error() == "" || !errors.Is(pidErr, cause) {
		t.Errorf("pid error = %q", pidErr.Error())
	}

	invalidErr := &ErrAppCtlInvalidPid{Path: "/run/x.pid", Contents: "junk"}
	if invalidErr.Error() == "" {
		t.Error("invalid pid error message empty")
	}

	sockErr := &ErrAppCtlSocketUnavailable{Path: "/run/x.ctl", Cause: cause}
	if sockErr.Error() == "" || !errors.Is(sockErr, cause) {
		t.Errorf("socket error = %q", sockErr.Error())
	}

	cmdErr := &ErrAppCtlCommandFailed{Method: "dpctl/show", Reply: "nope"}
	if cmdErr.Error() == "" {
		t.Error("command error message empty")
	}

	protoErr := &ErrAppCtlProtocol{Method: "dpctl/show", Cause: cause}
	if protoErr.Error() == "" || !errors.Is(protoErr, cause) {
		t.Errorf("protocol error = %q", protoErr.Error())
	}
	bareProtoErr := &ErrAppCtlProtocol{Method: "dpctl/show"}
	if bareProtoErr.Error() == "" {
		t.Error("bare protocol error message empty")
	}

	parseErr := &ErrDatapathStatsUnparseable{Output: "x"}
	if parseErr.Error() == "" {
		t.Error("parse error message empty")
	}
}

func TestAppCtlDeadlinePropagation(t *testing.T) {
	srv := newFakeUnixctlServer(t, map[string]fakeUnixctlHandler{
		"coverage/show": staticReply(fixtureCoverage),
	})
	client := newAppCtlClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := client.AppCtl(ctx, "coverage/show"); err != nil {
		t.Fatalf("AppCtl with deadline: %v", err)
	}
}
