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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
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
// relaunched child must bind the same address its predecessor held.
const supervisedConfig = `gateway:
  enabled: true
  id: gw-supervised
  bgp:
    asn: 64512
    router-id: 192.0.2.1
    listen-port: %s
    listen-addresses: [%s]
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
`

// probes says how the suite tells each supervised child is serving again.
// A child the assembly starts that has no probe here fails the test, so a
// class added later cannot go unproven.
var probes = map[string]func(gw *supervisedGatewayd) bool{
	"proxy":   (*supervisedGatewayd).proxyServes,
	"routing": (*supervisedGatewayd).bgpListens,
}

// supervisedGatewayd is one running `gatewayd serve`.
type supervisedGatewayd struct {
	cmd          *exec.Cmd
	exited       chan struct{}
	exitErr      error
	logPath      string
	baseURL      string
	bgpAddress   string
	cgroupParent string
	client       *http.Client
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
	if strings.Join(names, ",") != "proxy,routing" {
		t.Fatalf("supervised children = %v, want the proxy and routing processes", started)
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			probe, ok := probes[name]
			if !ok {
				t.Fatalf("no probe for supervised process %q", name)
			}
			before := gw.children(t)
			failedBefore := load.failed.Load()

			killedAt := time.Now()
			if err := syscall.Kill(before[name], syscall.SIGKILL); err != nil {
				t.Fatalf("kill %s (pid %d): %v", name, before[name], err)
			}
			after := gw.awaitRelaunch(t, name, before, probe)
			t.Logf("%s: pid %d killed, pid %d serving %v later", name, before[name], after[name], time.Since(killedAt).Round(time.Millisecond))

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
	oomBefore := memoryEvent(t, leaf, "oom_kill")
	failedBefore := load.failed.Load()

	// Take swap away so reclaim cannot satisfy the limit, then set one far
	// below what any Go process needs: the kernel's OOM killer acts inside
	// the leaf, exactly as it would for a child that grew past MemoryMax.
	swapMax := filepath.Join(leaf, "memory.swap.max")
	if _, err := os.Stat(swapMax); err == nil {
		writeCgroupFile(t, swapMax, "0")
	}
	writeCgroupFile(t, filepath.Join(leaf, "memory.max"), strconv.Itoa(1<<20))

	after := gw.awaitRelaunch(t, victim, before, probes[victim])
	if oom := memoryEvent(t, leaf, "oom_kill"); oom <= oomBefore {
		t.Errorf("%s memory.events oom_kill = %d, want more than %d", victim, oom, oomBefore)
	}
	if limit := readTrimmed(t, filepath.Join(leaf, "memory.max")); limit != strconv.FormatInt(def.MemoryMax, 10) {
		t.Errorf("relaunched %s memory.max = %s, want the class value %d restored", victim, limit, def.MemoryMax)
	}
	t.Logf("%s: pid %d OOM-killed, pid %d relaunched", victim, before[victim], after[victim])

	load.waitForTraffic(t)
	if failed := load.failed.Load(); failed != failedBefore {
		t.Errorf("%d proxied requests failed while %s was OOM-killed", failed-failedBefore, victim)
	}
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
	config := fmt.Sprintf(supervisedConfig, bgpPort, bgpHost, certFile, keyFile, proxyAddress,
		echo.URL, filepath.Join(dir, "run"), cgroupParent, supervisedReadyTimeout)
	configPath := filepath.Join(dir, "gatewayd.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	logPath := filepath.Join(dir, "gatewayd.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	cmd := exec.Command(binary, "serve", "--config", configPath, "--data-dir", dataDir, "--log-format", "text")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gatewayd: %v", err)
	}
	gw := &supervisedGatewayd{
		cmd:          cmd,
		exited:       make(chan struct{}),
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
	go func() {
		gw.exitErr = cmd.Wait()
		close(gw.exited)
	}()
	t.Cleanup(func() {
		if err := logFile.Close(); err != nil {
			t.Errorf("close gatewayd log: %v", err)
		}
	})
	t.Cleanup(func() { gw.stop(t) })

	WaitFor(t, 60*time.Second, 200*time.Millisecond, "the proxy and routing children to serve", func() bool {
		gw.requireRunning(t)
		children := gw.children(t)
		return children["proxy"] != 0 && children["routing"] != 0 && gw.proxyServes() && gw.bgpListens()
	})
	return gw
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
	select {
	case <-g.exited:
	default:
		if err := g.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Errorf("signal gatewayd: %v", err)
		}
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		select {
		case <-g.exited:
			if g.exitErr != nil {
				t.Errorf("gatewayd shutdown: %v", g.exitErr)
			}
		case <-deadline.C:
			t.Errorf("gatewayd did not stop within 30s of SIGTERM")
			if err := g.cmd.Process.Kill(); err != nil {
				t.Errorf("kill gatewayd: %v", err)
			}
			<-g.exited
		}
	}
	if t.Failed() {
		t.Logf("gatewayd log:\n%s", g.log(t))
	}
	if err := os.Remove(filepath.Join(cgroupRoot, g.cgroupParent)); err != nil && !os.IsNotExist(err) {
		t.Errorf("remove cgroup parent (a leaf left behind?): %v", err)
	}
}

func (g *supervisedGatewayd) log(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(g.logPath)
	if err != nil {
		return "(log unreadable: " + err.Error() + ")"
	}
	return string(data)
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
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// memoryEvent returns one counter from a leaf's memory.events.
func memoryEvent(t *testing.T, leaf, event string) int64 {
	t.Helper()
	for _, line := range strings.Split(readTrimmed(t, filepath.Join(leaf, "memory.events")), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == event {
			count, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("memory.events %s = %q: %v", event, fields[1], err)
			}
			return count
		}
	}
	t.Fatalf("%s/memory.events has no %s counter", leaf, event)
	return 0
}
