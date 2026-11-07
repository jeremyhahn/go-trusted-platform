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

//go:build integration

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// The supervised-process proof for #557: a real `gatewayd serve` with the
// `process:` section on, its proxy and routing services each in a supervised
// child, killed and starved under load. The harness builds the binary and
// delegates the cgroup controllers (prepare_gatewayd_supervision in
// build/docker/devcontainer/run-integration-tests.sh).

// EnvGatewaydPath names the gatewayd binary the devcontainer harness builds.
const EnvGatewaydPath = "GATEWAYD_PATH"

const (
	// cgroupRoot is the cgroup v2 mount gatewayd places its children under
	// (the `process.cgroup-root` default).
	cgroupRoot = "/sys/fs/cgroup"

	// supervisedReadyTimeout is the `process.ready-timeout` the suite
	// configures: how long a relaunched child has to answer.
	supervisedReadyTimeout = 10 * time.Second

	// relaunchBound is how long a killed child may stay down: the
	// supervisor's first restart backoff plus the ready timeout the relaunch
	// is allowed. docs/gateway/engineering.md names no tighter deadline.
	relaunchBound = process.DefaultRestartBackoff + supervisedReadyTimeout

	// loadWorkers is how many clients drive traffic through the proxy child
	// while its siblings, and the proxy itself, are killed.
	loadWorkers = 4
)

// supervisedConfig is the gatewayd configuration the suite runs. The proxy
// listener and the BGP port are fixed rather than ephemeral because a
// relaunched child must bind the same address its predecessor held. The load
// balancer is the datapath service: of the datapath services it alone needs
// no zone networks, and its config VIP gives the bridge flows and a group the
// suite can compare across a kill.
const supervisedConfig = `gateway:
  enabled: true
  id: gw-supervised
  bgp:
    asn: 64512
    router-id: 192.0.2.1
    listen-port: %s
    listen-addresses: [%s]
  load-balancer:
    enabled: true
    algorithm: hash
    health-check-interval: 1h
    health-check-timeout: 1s
    max-backends: 8
    vips:
      - address: 10.100.0.20
        port: 80
        protocol: tcp
        backends:
          - address: 10.0.1.7
            port: 8080
proxy:
  enabled: true
  tls:
    cert-file: %s
    key-file: %s
  listeners:
    - id: supervised
      address: %s
  routes:
    - id: echo
      path-prefix: /echo
      pool: echo
      auth:
        mode: public
  pools:
    - id: echo
      backends:
        - url: %s
process:
  enabled: true
  user: nobody
  group: nogroup
  runtime-dir: %s
  cgroup-parent: %s
  ready-timeout: %s
  stop-timeout: 10s
  restart-budget: 5
  restart-window: 5m
sdn:
  enabled: true
  environment:
    id: 4
  ovs:
    socket: /var/run/openvswitch/db.sock
    bridge: %s
`

// supervisedBridge is the OVS bridge the datapath child programs; the suite
// creates it, so nothing but that child writes to it.
const supervisedBridge = "br-gwsup"

// probes says how the suite tells each supervised child is serving again.
// A child the assembly starts that has no probe here fails the test, so a
// class added later cannot go unproven.
var probes = map[string]func(gw *supervisedGatewayd) bool{
	"datapath": (*supervisedGatewayd).datapathReconciled,
	"proxy":    (*supervisedGatewayd).proxyServes,
	"routing":  (*supervisedGatewayd).bgpListens,
}

// supervisedGatewayd is one running `gatewayd serve`.
type supervisedGatewayd struct {
	// binary, args and logFile start a supervisor; launch reuses them for a
	// successor.
	binary  string
	args    []string
	logFile *os.File

	cmd          *exec.Cmd
	exited       chan struct{}
	exitErr      error
	logPath      string
	baseURL      string
	bgpAddress   string
	cgroupParent string
	client       *http.Client

	// programmed is the bridge as the datapath child left it before the
	// current kill; datapathReconciled compares the successor against it.
	programmed bridgeState

	// oomKills is the memory.events oom_kill count a test caused on purpose,
	// by child name; teardown expects every other leaf to have none.
	oomKills map[string]int64
}

func TestGatewaydSupervisorKillUnderLoad(t *testing.T) {
	gw := startSupervisedGatewayd(t)
	load := gw.startLoad(t)
	load.waitForTraffic(t)

	started := gw.children(t)
	names := make([]string, 0, len(started))
	for name := range started {
		names = append(names, name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "datapath,proxy,routing" {
		t.Fatalf("supervised children = %v, want the datapath, proxy and routing processes", started)
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			probe, ok := probes[name]
			if !ok {
				t.Fatalf("no probe for supervised process %q", name)
			}
			before := gw.children(t)
			failedBefore := load.failed.Load()
			gw.programmed = gw.bridge(t)

			killedAt := time.Now()
			if err := syscall.Kill(before[name], syscall.SIGKILL); err != nil {
				t.Fatalf("kill %s (pid %d): %v", name, before[name], err)
			}
			after := gw.awaitRelaunch(t, name, before, probe)
			t.Logf("%s: pid %d killed, pid %d serving %v later", name, before[name], after[name], time.Since(killedAt).Round(time.Millisecond))

			// The successor reconciles the flows and groups its predecessor
			// left, under a generation of its own; a kill elsewhere leaves
			// the bridge untouched, generations and all.
			revalidate(t)
			bridge := gw.bridge(t)
			if !slices.Equal(bridge.rules, gw.programmed.rules) {
				t.Errorf("bridge after the %s kill:\n%s\nwant:\n%s", name,
					strings.Join(bridge.rules, "\n"), strings.Join(gw.programmed.rules, "\n"))
			}
			if name != "datapath" && !maps.Equal(bridge.generations, gw.programmed.generations) {
				t.Errorf("the %s kill moved the datapath generations %v -> %v", name,
					gw.programmed.generations, bridge.generations)
			}

			load.waitForTraffic(t)
			if name != "proxy" {
				// Only the proxy child carries the traffic; losing any other
				// child must not cost a single request.
				if failed := load.failed.Load(); failed != failedBefore {
					t.Errorf("%d proxied requests failed while %s restarted", failed-failedBefore, name)
				}
			}
		})
	}
}

func TestGatewaydSupervisorMemoryMaxRestartsOnlyThatChild(t *testing.T) {
	const victim = "routing"
	def, err := process.DefinitionByName(victim)
	if err != nil {
		t.Fatalf("definition %s: %v", victim, err)
	}

	gw := startSupervisedGatewayd(t)
	load := gw.startLoad(t)
	load.waitForTraffic(t)

	before := gw.children(t)
	leaf := filepath.Join(cgroupRoot, gw.cgroupParent, victim)
	membership := readTrimmed(t, fmt.Sprintf("/proc/%d/cgroup", before[victim]))
	if want := "0::/" + gw.cgroupParent + "/" + victim; membership != want {
		t.Fatalf("%s child cgroup = %q, want %q", victim, membership, want)
	}
	if limit := readTrimmed(t, filepath.Join(leaf, "memory.max")); limit != strconv.FormatInt(def.MemoryMax, 10) {
		t.Fatalf("%s memory.max = %s, want the class value %d", victim, limit, def.MemoryMax)
	}
	// An oom_score_adj of -1000 makes a task unkillable even inside its own
	// memory cgroup: the limit below would then stall the child instead of
	// killing it, and the wait for a relaunch would time out with no cause.
	if adj := readTrimmed(t, fmt.Sprintf("/proc/%d/oom_score_adj", before[victim])); adj == "-1000" {
		t.Fatalf("%s child oom_score_adj = %s: the OOM killer cannot kill it", victim, adj)
	}
	// The child's charge just before the limit drops is what the kernel
	// has to reclaim or kill to fit 1 MiB.
	usageBefore := leafMemory(t, gw.cgroups(), victim)
	logMemory(t, victim, before[victim], "before the 1 MiB limit", usageBefore)
	failedBefore := load.failed.Load()

	// Take swap away so reclaim cannot satisfy the limit, then set one far
	// below what any Go process needs: the kernel's OOM killer acts inside
	// the leaf, exactly as it would for a child that grew past MemoryMax.
	swapMax := filepath.Join(leaf, "memory.swap.max")
	if _, err := os.Stat(swapMax); err == nil {
		writeCgroupFile(t, swapMax, "0")
	}
	writeCgroupFile(t, filepath.Join(leaf, "memory.max"), strconv.Itoa(1<<20))

	// The write returns only once the leaf's usage is under the new limit or
	// it holds no task, and the kernel counts an OOM kill before the victim's
	// memory is freed. So the count has risen by now, or the child was never
	// killed and no relaunch can follow.
	usageAfter := leafMemory(t, gw.cgroups(), victim)
	logMemory(t, victim, before[victim], "after the 1 MiB limit", usageAfter)
	if usageAfter.OOMKill <= usageBefore.OOMKill {
		t.Fatalf("%s memory.events oom_kill = %d, want more than %d: the 1 MiB limit did not OOM-kill it", victim, usageAfter.OOMKill, usageBefore.OOMKill)
	}
	// memory.peak keeps the most the leaf ever held, so it still shows the
	// charge the kill took away: over the 1 MiB limit, and at least what the
	// child held just before the limit dropped.
	switch {
	case !usageAfter.HasPeak:
		t.Errorf(peakRequired, victim)
	case usageAfter.Peak <= 1<<20 || usageAfter.Peak < usageBefore.Current:
		t.Errorf("%s memory.peak = %d, want over 1 MiB and at least the %d memory.current before the limit", victim, usageAfter.Peak, usageBefore.Current)
	}
	gw.oomKills = map[string]int64{victim: usageAfter.OOMKill}

	after := gw.awaitRelaunch(t, victim, before, probes[victim])
	if limit := readTrimmed(t, filepath.Join(leaf, "memory.max")); limit != strconv.FormatInt(def.MemoryMax, 10) {
		t.Errorf("relaunched %s memory.max = %s, want the class value %d restored", victim, limit, def.MemoryMax)
	}
	t.Logf("%s: pid %d OOM-killed, pid %d relaunched", victim, before[victim], after[victim])
	// The leaf outlives the relaunch, so memory.peak stays the leaf's
	// all-time high; memory.current is the successor's own charge once it
	// serves again, what the class needs to come back.
	logMemory(t, victim, after[victim], "relaunched and serving", leafMemory(t, gw.cgroups(), victim))

	load.waitForTraffic(t)
	if failed := load.failed.Load(); failed != failedBefore {
		t.Errorf("%d proxied requests failed while %s was OOM-killed", failed-failedBefore, victim)
	}
}

// TestGatewaydSupervisorDeathLeavesTheDatapath kills the supervisor itself.
// The parent-death signal takes every child with it, so none outlives its
// supervisor, and because that signal is SIGKILL none runs its stop path: the
// bridge keeps every flow and group the datapath installed. A SIGTERM would
// have withdrawn them. The successor's datapath then adopts the bridge
// through the cookie-scoped reconcile, as it does after a datapath kill.
func TestGatewaydSupervisorDeathLeavesTheDatapath(t *testing.T) {
	gw := startSupervisedGatewayd(t)
	before := gw.children(t)
	gw.programmed = gw.bridge(t)

	supervisor := gw.cmd.Process.Pid
	if err := gw.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill gatewayd (pid %d): %v", supervisor, err)
	}
	deadline := time.NewTimer(relaunchBound)
	defer deadline.Stop()
	select {
	case <-gw.exited:
	case <-deadline.C:
		t.Fatalf("gatewayd (pid %d) did not exit within %v of SIGKILL", supervisor, relaunchBound)
	}
	WaitFor(t, relaunchBound, 50*time.Millisecond, "every child to die with its supervisor", func() bool {
		for _, pid := range before {
			if !processGone(pid) {
				return false
			}
		}
		return true
	})

	left := gw.bridge(t)
	if !slices.Equal(left.rules, gw.programmed.rules) {
		t.Fatalf("bridge after the supervisor's death:\n%s\nwant it untouched:\n%s",
			strings.Join(left.rules, "\n"), strings.Join(gw.programmed.rules, "\n"))
	}
	if !maps.Equal(left.generations, gw.programmed.generations) {
		t.Fatalf("the supervisor's death moved the datapath generations %v -> %v",
			gw.programmed.generations, left.generations)
	}

	gw.launch(t)
	WaitFor(t, relaunchBound, 50*time.Millisecond, "the successor's datapath to adopt the bridge", gw.datapathReconciled)
}

// processGone reports whether pid has exited: no /proc entry, or a zombie
// waiting for whichever process inherited it to reap it.
func processGone(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true
	}
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return false
	}
	fields := strings.Fields(string(stat[end+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

// startSupervisedGatewayd runs `gatewayd serve` with the process model on
// and waits until both supervised children serve.
func startSupervisedGatewayd(t *testing.T) *supervisedGatewayd {
	t.Helper()
	binary := os.Getenv(EnvGatewaydPath)
	if binary == "" {
		t.Fatalf("%s is unset: the devcontainer harness builds gatewayd for the proxy target", EnvGatewaydPath)
	}
	requireDelegatedControllers(t)
	uid, gid := serviceAccount(t)

	// The children read the configuration and TLS files after they drop to
	// the service account, so the directory cannot be t.TempDir (0700).
	dir, err := os.MkdirTemp("", "gatewayd-supervised-")
	if err != nil {
		t.Fatalf("create work dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove work dir: %v", err)
		}
	})
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("open work dir: %v", err)
	}

	gwTLS := GenerateGatewayTLS(t)
	certFile := copyFile(t, gwTLS.CertFile, filepath.Join(dir, "gatewayd.pem"), 0o644)
	keyFile := copyFile(t, gwTLS.KeyFile, filepath.Join(dir, "gatewayd-key.pem"), 0o400)
	if err := os.Chown(keyFile, uid, gid); err != nil {
		t.Fatalf("hand the key to the service account: %v", err)
	}
	dataDir := filepath.Join(dir, "data")
	if err := os.Mkdir(dataDir, 0o750); err != nil {
		t.Fatalf("create data dir: %v", err)
	}
	if err := os.Chown(dataDir, uid, gid); err != nil {
		t.Fatalf("hand the data dir to the service account: %v", err)
	}

	echo := StartEchoBackend(t)
	proxyAddress := freeLoopbackAddress(t)
	bgpAddress := freeLoopbackAddress(t)
	bgpHost, bgpPort, err := net.SplitHostPort(bgpAddress)
	if err != nil {
		t.Fatalf("split %s: %v", bgpAddress, err)
	}
	cgroupParent := UniqueID("gatewayd-it")
	createSupervisedBridge(t)
	config := fmt.Sprintf(supervisedConfig, bgpPort, bgpHost, certFile, keyFile, proxyAddress,
		echo.URL, filepath.Join(dir, "run"), cgroupParent, supervisedReadyTimeout, supervisedBridge)
	configPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	logPath := filepath.Join(dir, "gatewayd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	gw := &supervisedGatewayd{
		binary:       binary,
		args:         []string{"serve", "--config", configPath, "--data-dir", dataDir, "--log-format", "text"},
		logFile:      logFile,
		logPath:      logPath,
		baseURL:      "https://" + proxyAddress,
		bgpAddress:   bgpAddress,
		cgroupParent: cgroupParent,
		client: &http.Client{
			Timeout: 5 * time.Second,
			// A fresh connection per request: a pooled one to a killed
			// child would report the old process, not the new one.
			Transport: &http.Transport{
				DisableKeepAlives: true,
				TLSClientConfig:   &tls.Config{RootCAs: gwTLS.CAPool, MinVersion: tls.VersionTLS13},
			},
		},
	}
	t.Cleanup(func() {
		if err := logFile.Close(); err != nil {
			t.Errorf("close gatewayd log: %v", err)
		}
	})
	// stop reads the supervisor when the test ends, so it stops a successor
	// a test launched as well as this one.
	t.Cleanup(func() { gw.stop(t) })
	gw.launch(t)
	return gw
}

// launch starts a gatewayd supervisor on the prepared configuration and waits
// for its datapath, proxy and routing children to serve. It is also how a test
// starts the successor of a supervisor it killed: the configuration, bridge
// and cgroup parent are the predecessor's.
func (g *supervisedGatewayd) launch(t *testing.T) {
	t.Helper()
	cmd := exec.Command(g.binary, g.args...)
	cmd.Stdout = g.logFile
	cmd.Stderr = g.logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gatewayd: %v", err)
	}
	exited := make(chan struct{})
	g.cmd, g.exited, g.exitErr = cmd, exited, nil
	go func() {
		g.exitErr = cmd.Wait()
		close(exited)
	}()

	what := fmt.Sprintf("gatewayd (pid %d) datapath, proxy and routing children to serve", cmd.Process.Pid)
	waitUntil(t, 60*time.Second, what, func() string {
		g.requireRunning(t)
		children := g.children(t)
		for _, name := range []string{"datapath", "proxy", "routing"} {
			if children[name] == 0 {
				return "no " + name + " child running"
			}
		}
		switch {
		case !g.datapathProgrammed():
			return "datapath has not programmed bridge " + supervisedBridge
		case !g.proxyServes():
			return "proxy not answering at " + g.baseURL
		case !g.bgpListens():
			return "routing not listening on " + g.bgpAddress
		}
		return ""
	})
}

// waitUntil polls pending until it reports nothing left. On the deadline it
// fails naming the wait, the deadline and what was still pending, so a
// timed-out wait says why rather than only that it waited.
func waitUntil(t *testing.T, timeout time.Duration, what string, pending func() string) {
	t.Helper()
	last := pending()
	if last == "" {
		return
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("timed out after %v waiting for %s: still %s", timeout, what, last)
		case <-ticker.C:
			if last = pending(); last == "" {
				return
			}
		}
	}
}

// awaitRelaunch waits, within relaunchBound, for a new child of the given
// name that passes its probe, then checks the supervisor and every other
// child kept their PIDs. It returns the children afterwards.
func (g *supervisedGatewayd) awaitRelaunch(t *testing.T, name string, before map[string]int, probe func(*supervisedGatewayd) bool) map[string]int {
	t.Helper()
	var after map[string]int
	WaitFor(t, relaunchBound, 50*time.Millisecond, "a relaunched "+name+" child serving", func() bool {
		g.requireRunning(t)
		after = g.children(t)
		return after[name] != 0 && after[name] != before[name] && probe(g)
	})
	for other, pid := range before {
		if other != name && after[other] != pid {
			t.Errorf("%s pid %d -> %d: only %s was meant to restart", other, pid, after[other], name)
		}
	}
	return after
}

// children maps each live supervised child of this gatewayd to its PID.
func (g *supervisedGatewayd) children(t *testing.T) map[string]int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("list /proc: %v", err)
	}
	found := make(map[string]int)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a process directory
		}
		if name, ok := supervisedChild(pid, g.cmd.Process.Pid); ok {
			found[name] = pid
		}
	}
	return found
}

// supervisedChild reports the process name a child of parent runs
// (`gatewayd service run <name> ...`). A process that exits between the
// listing and these reads, or a reaped-pending zombie with no command line,
// is not a live child.
func supervisedChild(pid, parent int) (string, bool) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", false
	}
	// The command name in parentheses may hold spaces; the fields after the
	// closing parenthesis are state, then ppid.
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return "", false
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 2 {
		return "", false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid != parent {
		return "", false
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "", false
	}
	args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	for i := 0; i+2 < len(args); i++ {
		if args[i] == "service" && args[i+1] == "run" {
			return args[i+2], true
		}
	}
	return "", false
}

// proxyServes reports whether one request through the proxy child reaches
// the echo backend.
func (g *supervisedGatewayd) proxyServes() bool {
	return g.proxyRequest(context.Background())
}

func (g *supervisedGatewayd) proxyRequest(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.baseURL+"/echo/load", nil)
	if err != nil {
		return false
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK
}

// bgpListens reports whether the routing child's BGP speaker accepts a TCP
// connection on its configured port.
func (g *supervisedGatewayd) bgpListens() bool {
	conn, err := net.DialTimeout("tcp", g.bgpAddress, time.Second)
	if err != nil {
		return false
	}
	return conn.Close() == nil
}

// datapathProgrammed reports whether the running datapath child has
// programmed the suite bridge: the VIP's group, and flows under a generation
// of its own. A launch over a bridge a killed datapath child left starts with
// g.programmed holding that child's bridge, whose generations it must not
// count.
func (g *supervisedGatewayd) datapathProgrammed() bool {
	state, err := readBridge()
	if err != nil {
		return false
	}
	return state.programmedSince(g.programmed)
}

// programmedSince reports whether s holds the VIP's group and a flow
// generation predecessor does not. A predecessor's leftover flows and groups
// say nothing about whether its successor has programmed anything.
func (s bridgeState) programmedSince(predecessor bridgeState) bool {
	hasGroup := slices.ContainsFunc(s.rules, func(rule string) bool {
		return strings.HasPrefix(rule, "group_id=")
	})
	if !hasGroup {
		return false
	}
	for cookie := range s.generations {
		if !predecessor.generations[cookie] {
			return true
		}
	}
	return false
}

// datapathReconciled reports whether a relaunched datapath child has
// reprogrammed the bridge: the flows and groups the killed child left, none
// still under a generation the killed child stamped. Until the successor
// sweeps them, a stale generation also shows as a duplicate rule.
func (g *supervisedGatewayd) datapathReconciled() bool {
	state, err := readBridge()
	if err != nil || !slices.Equal(state.rules, g.programmed.rules) {
		return false
	}
	if len(state.generations) != len(g.programmed.generations) {
		return false
	}
	for cookie := range state.generations {
		if g.programmed.generations[cookie] {
			return false
		}
	}
	return true
}

// bridge is readBridge for a caller that cannot go on without the dump.
func (g *supervisedGatewayd) bridge(t *testing.T) bridgeState {
	t.Helper()
	state, err := readBridge()
	if err != nil {
		t.Fatalf("read %s: %v", supervisedBridge, err)
	}
	return state
}

// bridgeState is the suite bridge's flows and groups, sorted, each flow's
// counters dropped and its gateway cookie cut to the owner id, so two dumps
// of the same programming compare equal whichever generation stamped it.
// generations is the set of full gateway cookies the flows carried that hold
// a drawn generation; an owner's fixed cookie (low 32 bits zero) is not one.
type bridgeState struct {
	rules       []string
	generations map[uint64]bool
}

// flowCounters are the dump-flows fields that change with time and traffic,
// not with what the datapath programmed.
var flowCounters = []string{"duration=", "n_packets=", "n_bytes=", "idle_age=", "hard_age="}

// readBridge dumps the suite bridge's flows and groups.
func readBridge() (bridgeState, error) {
	flows, err := ovsCommand("ovs-ofctl", "-O", "OpenFlow13", "dump-flows", supervisedBridge)
	if err != nil {
		return bridgeState{}, err
	}
	groups, err := ovsCommand("ovs-ofctl", "-O", "OpenFlow13", "dump-groups", supervisedBridge)
	if err != nil {
		return bridgeState{}, err
	}
	return parseBridge(flows, groups)
}

// parseBridge builds a bridgeState from dump-flows and dump-groups output.
func parseBridge(flows, groups string) (bridgeState, error) {
	state := bridgeState{generations: make(map[uint64]bool)}
	for _, line := range strings.Split(flows, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "cookie=") {
			continue // the reply header
		}
		rule, err := state.addFlow(line)
		if err != nil {
			return bridgeState{}, err
		}
		state.rules = append(state.rules, rule)
	}
	for _, line := range strings.Split(groups, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "group_id=") {
			state.rules = append(state.rules, line)
		}
	}
	slices.Sort(state.rules)
	return state, nil
}

// addFlow records the flow's gateway cookie and returns the flow without its
// counters and with the cookie cut to its owner.
func (s bridgeState) addFlow(line string) (string, error) {
	fields := strings.Split(line, ", ")
	kept := make([]string, 0, len(fields))
	for _, field := range fields {
		if slices.ContainsFunc(flowCounters, func(counter string) bool { return strings.HasPrefix(field, counter) }) {
			continue
		}
		if value, ok := strings.CutPrefix(field, "cookie="); ok {
			cookie, err := strconv.ParseUint(value, 0, 64)
			if err != nil {
				return "", &bridgeDumpError{Line: line, Cause: err}
			}
			if owner := cookie & ovs.OwnerCookieMask; owner != 0 {
				// ovs.NewGenerationCookie never draws generation 0, so a
				// cookie with empty low bits is an owner's fixed cookie
				// (the base pipeline, the ND punts): the same on every
				// start, and no generation of the killed child's.
				if cookie&^ovs.OwnerCookieMask != 0 {
					s.generations[cookie] = true
				}
				field = fmt.Sprintf("owner=0x%x", owner)
			}
		}
		kept = append(kept, field)
	}
	return strings.Join(kept, ", "), nil
}

// bridgeDumpError is a dump-flows line whose cookie does not parse.
type bridgeDumpError struct {
	Line  string
	Cause error
}

func (e *bridgeDumpError) Error() string {
	return fmt.Sprintf("dump-flows line %q: %v", e.Line, e.Cause)
}

func (e *bridgeDumpError) Unwrap() error { return e.Cause }

// ovsCommandError is an OVS command the suite ran that failed.
type ovsCommandError struct {
	Args   []string
	Output string
	Cause  error
}

func (e *ovsCommandError) Error() string {
	return fmt.Sprintf("%s: %v: %s", strings.Join(e.Args, " "), e.Cause, e.Output)
}

func (e *ovsCommandError) Unwrap() error { return e.Cause }

// ovsCommand runs an OVS command and returns its output.
func ovsCommand(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return "", &ovsCommandError{Args: args, Output: string(out), Cause: err}
	}
	return string(out), nil
}

// revalidate waits for OVS to bring its datapath flows in line with the
// OpenFlow tables, so nothing the comparison reads is still in flight.
func revalidate(t *testing.T) {
	t.Helper()
	if _, err := ovsCommand("ovs-appctl", "revalidator/wait"); err != nil {
		t.Fatalf("revalidate: %v", err)
	}
}

// createSupervisedBridge gives the datapath child an OpenFlow 1.3 bridge of
// its own, deleted when the test ends, and waits for its management socket.
func createSupervisedBridge(t *testing.T) {
	t.Helper()
	if _, err := ovsCommand("ovs-vsctl", "--if-exists", "del-br", supervisedBridge); err != nil {
		t.Fatalf("clear %s: %v", supervisedBridge, err)
	}
	if _, err := ovsCommand("ovs-vsctl", "add-br", supervisedBridge,
		"--", "set", "bridge", supervisedBridge, "protocols=OpenFlow13"); err != nil {
		t.Fatalf("create %s: %v", supervisedBridge, err)
	}
	t.Cleanup(func() {
		if _, err := ovsCommand("ovs-vsctl", "--if-exists", "del-br", supervisedBridge); err != nil {
			t.Errorf("delete %s: %v", supervisedBridge, err)
		}
	})
	socket := filepath.Join("/var/run/openvswitch", supervisedBridge+".mgmt")
	WaitFor(t, 10*time.Second, 50*time.Millisecond, "the "+supervisedBridge+" management socket", func() bool {
		_, err := os.Stat(socket)
		return err == nil
	})
}

func TestParseBridgeComparesProgrammingNotGenerations(t *testing.T) {
	const header = "OFPST_FLOW reply (OF1.3) (xid=0x2):\n"
	first, err := parseBridge(header+
		" cookie=0xf1be000300000001, duration=1.5s, table=0, n_packets=4, n_bytes=240, priority=100,tcp,nw_dst=10.100.0.20,tp_dst=80 actions=group:1\n"+
		" cookie=0x0, duration=1.5s, table=0, n_packets=0, n_bytes=0, priority=0 actions=NORMAL\n",
		"OFPST_GROUP_DESC reply (OF1.3) (xid=0x2):\n group_id=1,type=select,bucket=actions=output:7\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	second, err := parseBridge(header+
		" cookie=0xf1be000300000002, duration=9.1s, table=0, n_packets=0, n_bytes=0, priority=100,tcp,nw_dst=10.100.0.20,tp_dst=80 actions=group:1\n"+
		" cookie=0x0, duration=9.1s, table=0, n_packets=7, n_bytes=420, priority=0 actions=NORMAL\n",
		" group_id=1,type=select,bucket=actions=output:7\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !slices.Equal(first.rules, second.rules) {
		t.Errorf("rules differ only in counters and generation, yet\n%v\n!=\n%v", first.rules, second.rules)
	}
	if want := map[uint64]bool{0xf1be000300000001: true}; !maps.Equal(first.generations, want) {
		t.Errorf("generations = %v, want %v: the uncookied flow carries none", first.generations, want)
	}
	if len(first.rules) != 3 {
		t.Errorf("rules = %v, want two flows and one group", first.rules)
	}
}

// A launch over the bridge a killed datapath child left must not take that
// child's flows for its successor's programming. The check launch once made,
// any generation and a group, passed on the leftovers alone.
func TestProgrammedSinceRefusesAPredecessorsLeftovers(t *testing.T) {
	const (
		header = "OFPST_FLOW reply (OF1.3) (xid=0x2):\n"
		group  = " group_id=1,type=select,bucket=actions=output:7\n"
		flow   = ", duration=1.5s, table=0, n_packets=4, n_bytes=240, priority=100,tcp,nw_dst=10.100.0.20,tp_dst=80 actions=group:1\n"
	)
	parse := func(t *testing.T, flows, groups string) bridgeState {
		t.Helper()
		state, err := parseBridge(header+flows, groups)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return state
	}
	predecessor := parse(t, " cookie=0xf1be000300000001"+flow, group)

	t.Run("leftovers alone", func(t *testing.T) {
		left := parse(t, " cookie=0xf1be000300000001"+flow, group)
		oldCheck := len(left.generations) > 0 && slices.ContainsFunc(left.rules, func(rule string) bool {
			return strings.HasPrefix(rule, "group_id=")
		})
		if !oldCheck {
			t.Fatalf("the old check refused the leftovers; this test no longer shows its defect")
		}
		if left.programmedSince(predecessor) {
			t.Errorf("the predecessor's leftovers count as the successor's programming")
		}
	})
	t.Run("the successor's generation", func(t *testing.T) {
		next := parse(t, " cookie=0xf1be000300000001"+flow+" cookie=0xf1be000300000002"+flow, group)
		if !next.programmedSince(predecessor) {
			t.Errorf("a generation the predecessor did not hold is the successor's programming")
		}
	})
	t.Run("no group", func(t *testing.T) {
		next := parse(t, " cookie=0xf1be000300000002"+flow, "")
		if next.programmedSince(predecessor) {
			t.Errorf("flows without the VIP's group count as programmed")
		}
	})
	t.Run("first launch", func(t *testing.T) {
		if !predecessor.programmedSince(bridgeState{}) {
			t.Errorf("a first launch, with no predecessor, is refused its own generation")
		}
	})
}

// TestParseBridgeLeavesFixedCookiesOutOfTheGenerations pins what a
// generation is: an owner's cookie with a generation drawn in its low 32
// bits. The base pipeline (gateway.CookiePipeline) and the overlay's ND
// punts (modes.OverlayNDCookie) stamp one fixed cookie on every start, so
// a relaunched datapath re-installs the very cookie its predecessor left.
// Counted as a generation, that cookie would read as the predecessor's
// forever and datapathReconciled could never turn true.
func TestParseBridgeLeavesFixedCookiesOutOfTheGenerations(t *testing.T) {
	const header = "OFPST_FLOW reply (OF1.3) (xid=0x2):\n"
	state, err := parseBridge(header+
		" cookie=0xf1be000000000000, duration=1.5s, table=0, n_packets=4, n_bytes=240, priority=0 actions=resubmit(,10)\n"+
		" cookie=0xf1be000600000000, duration=1.5s, table=0, n_packets=0, n_bytes=0, priority=200,icmp6,icmp_type=135 actions=CONTROLLER:65535\n"+
		" cookie=0xf1be000300000007, duration=1.5s, table=0, n_packets=0, n_bytes=0, priority=100,tcp,nw_dst=10.100.0.20,tp_dst=80 actions=group:1\n",
		"")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if want := map[uint64]bool{0xf1be000300000007: true}; !maps.Equal(state.generations, want) {
		t.Errorf("generations = %v, want %v: a fixed cookie carries no generation", state.generations, want)
	}
	for _, rule := range state.rules {
		if strings.Contains(rule, "cookie=") {
			t.Errorf("rule %q keeps a raw gateway cookie, want it cut to the owner", rule)
		}
	}
}

func TestParseBridgeRefusesAnUnparsableCookie(t *testing.T) {
	_, err := parseBridge(" cookie=0xzz, table=0, priority=0 actions=NORMAL\n", "")
	var dumpErr *bridgeDumpError
	if !errors.As(err, &dumpErr) {
		t.Fatalf("err = %v, want *bridgeDumpError", err)
	}
}

func TestLeafBusyNamesTheTasksLeftInTheLeaf(t *testing.T) {
	leaf := t.TempDir()
	if err := os.WriteFile(filepath.Join(leaf, "cgroup.procs"), []byte("4242\n4243\n"), 0o600); err != nil {
		t.Fatalf("write cgroup.procs: %v", err)
	}
	err := leafBusy(leaf, context.DeadlineExceeded)
	var leafErr *cgroupLeafError
	if !errors.As(err, &leafErr) {
		t.Fatalf("err = %v, want *cgroupLeafError", err)
	}
	if leafErr.Leaf != leaf || leafErr.Procs != "4242 4243" {
		t.Errorf("leaf %q procs %q, want %q and \"4242 4243\"", leafErr.Leaf, leafErr.Procs, leaf)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want it to wrap the wait's deadline", err)
	}
}

func TestLeafBusySaysWhenCgroupProcsCannotBeRead(t *testing.T) {
	leaf := filepath.Join(t.TempDir(), "gone")
	var leafErr *cgroupLeafError
	if !errors.As(leafBusy(leaf, context.DeadlineExceeded), &leafErr) {
		t.Fatal("want *cgroupLeafError for a leaf with no cgroup.procs")
	}
	if !strings.HasPrefix(leafErr.Procs, "unreadable: ") {
		t.Errorf("procs = %q, want it to say cgroup.procs was unreadable", leafErr.Procs)
	}
}

// requireRunning fails the test at once if gatewayd itself has exited: the
// supervisor must outlive every child it restarts.
func (g *supervisedGatewayd) requireRunning(t *testing.T) {
	t.Helper()
	select {
	case <-g.exited:
		t.Fatalf("gatewayd exited: %v\n%s", g.exitErr, g.log(t))
	default:
	}
}

// stop sends SIGTERM, waits for a clean exit, and removes the cgroup parent
// the run created; the supervisor removes each leaf as it stops the child.
func (g *supervisedGatewayd) stop(t *testing.T) {
	if g.cmd == nil {
		return // the launch failed before a supervisor started
	}
	select {
	case <-g.exited:
	default:
		// Each class's leaf accounting at the end of a normal run is the
		// measured basis for its MemoryMax (#955); gatewayd removes the
		// leaves as it stops, so it is read first. A read failure is
		// reported, not fatal: the stop below must still happen.
		for name, pid := range g.children(t) {
			usage, err := g.cgroups().Memory(name)
			if err != nil {
				t.Errorf("%s leaf memory: %v", name, err)
				continue
			}
			logMemory(t, name, pid, "at teardown", usage)
			def, err := process.DefinitionByName(name)
			if err != nil {
				t.Errorf("definition %s: %v", name, err)
				continue
			}
			// A leaf that charged nothing measured nothing. One the kernel
			// OOM-killed in, beyond what the test did on purpose, means
			// the class value is below what the child needs; the relaunch
			// keeps the leaf, so a purposeful kill is still counted here.
			switch {
			case !usage.HasPeak:
				t.Errorf(peakRequired, name)
			case usage.Peak <= 0:
				t.Errorf("%s memory.peak at teardown = %d, want the bytes the child charged", name, usage.Peak)
			}
			if want := g.oomKills[name]; usage.OOMKill != want {
				t.Errorf("%s memory.events oom_kill at teardown = %d, want %d: the class MemoryMax %d killed it", name, usage.OOMKill, want, def.MemoryMax)
			}
			t.Logf("%s memory.peak %d is %.1f%% of the class MemoryMax %d", name, usage.Peak, 100*float64(usage.Peak)/float64(def.MemoryMax), def.MemoryMax)
		}
		if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Errorf("signal gatewayd: %v", err)
		}
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		select {
		case <-g.exited:
			if g.exitErr != nil {
				t.Errorf("teardown: gatewayd (pid %d) did not shut down cleanly on SIGTERM: %v%s",
					g.cmd.Process.Pid, g.exitErr, killedBySignal(g.exitErr))
			}
		case <-deadline.C:
			t.Errorf("teardown: gatewayd (pid %d) did not stop within 30s of SIGTERM", g.cmd.Process.Pid)
			if err := g.cmd.Process.Kill(); err != nil {
				t.Errorf("kill gatewayd: %v", err)
			}
			<-g.exited
		}
	}
	if t.Failed() {
		t.Logf("gatewayd log:\n%s", g.log(t))
	}
	g.removeCgroups(t)
}

// killedBySignal explains an exit by a signal's default action: gatewayd
// handles SIGTERM, so dying of it means the handler was not installed when
// the signal arrived.
func killedBySignal(err error) string {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return ""
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return ""
	}
	return fmt.Sprintf(" (killed by the default action of %v: no handler for it was installed yet)", status.Signal())
}

// removeCgroups removes the test's cgroup parent. A reaped child leaves
// its leaf only after its last context switch, so every leaf gatewayd did
// not remove is first waited on until the kernel reports it empty
// (cgroup.events "populated 0"); the parent cannot be removed before. A
// leaf still populated at the deadline fails the test with a
// cgroupLeafError naming the PIDs in its cgroup.procs.
func (g *supervisedGatewayd) removeCgroups(t *testing.T) {
	parent := filepath.Join(cgroupRoot, g.cgroupParent)
	entries, err := os.ReadDir(parent)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Errorf("list cgroup parent: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue // an interface file, not a leaf
		}
		if err := g.cgroups().Remove(ctx, entry.Name()); err != nil {
			t.Errorf("teardown: %v", leafBusy(filepath.Join(parent, entry.Name()), err))
		}
	}
	if err := os.Remove(parent); err != nil && !os.IsNotExist(err) {
		t.Errorf("remove cgroup parent: %v", err)
	}
}

// cgroupLeafError is a leaf the teardown could not remove, with the tasks
// still in it: after gatewayd has exited, any PID left there is a child
// that outlived its supervisor.
type cgroupLeafError struct {
	Leaf  string
	Procs string
	Cause error
}

func (e *cgroupLeafError) Error() string {
	return fmt.Sprintf("cgroup leaf %s not removed (cgroup.procs: %s): %v", e.Leaf, e.Procs, e.Cause)
}

func (e *cgroupLeafError) Unwrap() error { return e.Cause }

// leafBusy names the leaf a removal failed on and the tasks it still holds.
func leafBusy(leaf string, cause error) error {
	procs, err := os.ReadFile(filepath.Join(leaf, "cgroup.procs")) // #nosec G304 -- a leaf of the suite's own cgroup parent
	switch {
	case err != nil:
		return &cgroupLeafError{Leaf: leaf, Procs: "unreadable: " + err.Error(), Cause: cause}
	case len(bytes.TrimSpace(procs)) == 0:
		return &cgroupLeafError{Leaf: leaf, Procs: "empty", Cause: cause}
	}
	return &cgroupLeafError{Leaf: leaf, Procs: strings.Join(strings.Fields(string(procs)), " "), Cause: cause}
}

// cgroups is the view of the cgroup tree gatewayd places its children in.
func (g *supervisedGatewayd) cgroups() *process.CgroupManager {
	return &process.CgroupManager{Root: cgroupRoot, Parent: g.cgroupParent}
}

func (g *supervisedGatewayd) log(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(g.logPath)
	if err != nil {
		return "(log unreadable: " + err.Error() + ")" + vswitchdLogTail()
	}
	return string(data) + vswitchdLogTail()
}

// vswitchdLogPath is where the devcontainer runner has ovs-vswitchd log.
const vswitchdLogPath = "/var/log/openvswitch/ovs-vswitchd.log"

// vswitchdLogTailLines bounds how much of the vswitchd log a failure shows.
const vswitchdLogTailLines = 40

// vswitchdLogTail returns the end of the ovs-vswitchd log. A datapath child
// that reports ErrConfigNotApplied waited its full bound for vswitchd to
// advance cur_cfg; only vswitchd's own log says why it did not (run 58285).
func vswitchdLogTail() string {
	data, err := os.ReadFile(vswitchdLogPath)
	if err != nil {
		return "\n(ovs-vswitchd log unreadable: " + err.Error() + ")"
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > vswitchdLogTailLines {
		lines = lines[len(lines)-vswitchdLogTailLines:]
	}
	return "\n--- " + vswitchdLogPath + " (tail) ---\n" + strings.Join(lines, "\n")
}

// trafficLoad is a set of clients requesting through the proxy without
// pause, counting what succeeded and what failed.
type trafficLoad struct {
	ok     atomic.Int64
	failed atomic.Int64
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (g *supervisedGatewayd) startLoad(t *testing.T) *trafficLoad {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	load := &trafficLoad{cancel: cancel}
	for range loadWorkers {
		load.wg.Add(1)
		go func() {
			defer load.wg.Done()
			for ctx.Err() == nil {
				if g.proxyRequest(ctx) {
					load.ok.Add(1)
					continue
				}
				if ctx.Err() != nil {
					return
				}
				load.failed.Add(1)
				// A refused connection returns at once; pace the retries
				// so a down proxy is not a busy loop.
				select {
				case <-ctx.Done():
				case <-time.After(50 * time.Millisecond):
				}
			}
		}()
	}
	t.Cleanup(func() {
		load.cancel()
		load.wg.Wait()
	})
	return load
}

// waitForTraffic waits until the load has completed more requests than it
// had when called, proving traffic flows now.
func (l *trafficLoad) waitForTraffic(t *testing.T) {
	t.Helper()
	floor := l.ok.Load() + loadWorkers
	WaitFor(t, relaunchBound, 50*time.Millisecond, "proxied traffic to flow", func() bool {
		return l.ok.Load() >= floor
	})
}

// requireDelegatedControllers fails when the cgroup root does not offer the
// memory and cpu controllers to its children; without them gatewayd cannot
// write a leaf's limits and no supervised child starts.
func requireDelegatedControllers(t *testing.T) {
	t.Helper()
	enabled := strings.Fields(readTrimmed(t, filepath.Join(cgroupRoot, "cgroup.subtree_control")))
	for _, want := range []string{"memory", "cpu"} {
		found := false
		for _, controller := range enabled {
			found = found || controller == want
		}
		if !found {
			t.Fatalf("%s/cgroup.subtree_control = %v lacks %s: the harness must delegate it (prepare_gatewayd_supervision)", cgroupRoot, enabled, want)
		}
	}
}

// serviceAccount returns the uid and gid the children drop to.
func serviceAccount(t *testing.T) (int, int) {
	t.Helper()
	account, err := user.Lookup("nobody")
	if err != nil {
		t.Fatalf("look up nobody: %v", err)
	}
	group, err := user.LookupGroup("nogroup")
	if err != nil {
		t.Fatalf("look up nogroup: %v", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		t.Fatalf("nobody uid %q: %v", account.Uid, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		t.Fatalf("nogroup gid %q: %v", group.Gid, err)
	}
	return uid, gid
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) string {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("read %s: %v", from, err)
	}
	if err := os.WriteFile(to, data, mode); err != nil {
		t.Fatalf("write %s: %v", to, err)
	}
	return to
}

// freeLoopbackAddress returns a loopback address with a port nothing holds.
func freeLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release %s: %v", address, err)
	}
	return address
}

func readTrimmed(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(data))
}

func writeCgroupFile(t *testing.T, path, value string) {
	t.Helper()
	// os.OpenFile registers a kernfs file with the poller, which leaves the
	// descriptor O_NONBLOCK, and since Linux 6.16 a non-blocking memory.max
	// write sets the limit and returns without reclaim or the OOM kill. A raw
	// descriptor stays blocking, so the write returns only once the kernel
	// has enforced the limit.
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		if err := syscall.Close(fd); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()
	n, err := syscall.Write(fd, []byte(value))
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if n != len(value) {
		t.Fatalf("write %s: wrote %d of %d bytes", path, n, len(value))
	}
}

// peakRequired fails a peak assertion on a kernel without memory.peak: the
// test measures each class's MemoryMax from it, so it cannot pass without it.
const peakRequired = "%s memory.peak is absent: this test needs cgroup v2 memory.peak, Linux 5.19 or later"

// leafMemory reads a child's leaf accounting.
func leafMemory(t *testing.T, cgroups *process.CgroupManager, name string) process.MemoryUsage {
	t.Helper()
	usage, err := cgroups.Memory(name)
	if err != nil {
		t.Fatalf("%s leaf memory: %v", name, err)
	}
	return usage
}

// logMemory records a leaf's accounting in the job log: the measured
// numbers behind every class's MemoryMax and behind an OOM kill.
func logMemory(t *testing.T, name string, pid int, when string, usage process.MemoryUsage) {
	t.Helper()
	peak := "absent (kernel before 5.19)"
	if usage.HasPeak {
		peak = strconv.FormatInt(usage.Peak, 10)
	}
	t.Logf("%s (pid %d) memory %s: memory.current %d, memory.peak %s, memory.events max %d oom %d oom_kill %d",
		name, pid, when, usage.Current, peak, usage.Max, usage.OOM, usage.OOMKill)
}
