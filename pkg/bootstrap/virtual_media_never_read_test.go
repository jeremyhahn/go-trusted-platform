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

package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// vmediaSink is a bootstrap-container double for the virtual-media boot
// loop: /health, per-MAC config, a scripted /media/status, the install
// log, and the forensic upload path the console capture writes to.
type vmediaSink struct {
	srv       *httptest.Server
	mu        sync.Mutex
	media     ipxe.MediaStatus
	mediaCode int // 0 = serve media; otherwise answer this status
	// reading makes every /media/status answer advance smbd's activity
	// on the ISO, the way a live watcher does while the host reads it.
	// With it false the record is served frozen: history, no new reads —
	// though smbd's last_seen is still refreshed, as a watcher does for a
	// descriptor that stays open idle.
	reading      bool
	watcherSince time.Time
	serveLog     bool
	uploads      map[string][]byte
	mediaHits    int
}

func newVmediaSink(t *testing.T) *vmediaSink {
	t.Helper()
	s := &vmediaSink{uploads: make(map[string][]byte), media: ipxe.MediaStatus{DataDir: "/data"}, watcherSince: time.Now()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("PUT /config/mac/{mac}/{key}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /media/status", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.mediaHits++
		if s.mediaCode != 0 {
			w.WriteHeader(s.mediaCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		now := time.Now()
		for i := range s.media.Files {
			f := &s.media.Files[i]
			f.OpenSamples++
			f.LastSeen = now
			for j := range f.Openers {
				f.Openers[j].OpenSamples++
				f.Openers[j].LastSeen = now
				if s.reading && f.Openers[j].Name == "smbd" && (f.Openers[j].Client == "" || f.Openers[j].Client == "198.51.100.102") {
					f.Openers[j].PosChanges++
					f.Openers[j].LastActivity = now
				}
			}
		}
		status := s.media
		status.Since = s.watcherSince
		status.SampledAt = time.Now()
		status.Files = append([]ipxe.MediaOpen(nil), s.media.Files...)
		if err := json.NewEncoder(w).Encode(status); err != nil {
			t.Errorf("encode media status: %v", err)
		}
	})
	mux.HandleFunc("GET /installs/{key...}", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/install.log") && s.serveLog {
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			if _, err := w.Write([]byte("=== POSTMORTEM MANIFEST ===\nexit_code: 0\n")); err != nil {
				t.Errorf("write install.log: %v", err)
			}
			return
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("PUT /installs/{key...}", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upload: %v", err)
		}
		s.mu.Lock()
		s.uploads[r.URL.Path] = body
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("vmedia sink: unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// setMedia records files as the watcher would report them for a host
// that is reading right now: held by smbd, seen just now, and — because
// reading is switched on — smbd activity advancing on every poll.
func (s *vmediaSink) setMedia(files ...ipxe.MediaOpen) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for i := range files {
		if len(files[i].Openers) == 0 {
			files[i].Openers = []ipxe.MediaOpener{{Name: "smbd", Client: "198.51.100.102", Opens: 1, OpenSamples: 1, OpenEvents: 1, MaxPos: files[i].MaxPos, LastActivity: now}}
		}
		files[i].LastSeen = now
	}
	s.media = ipxe.MediaStatus{DataDir: "/data", Files: files}
	s.reading = true
}

// freezeMedia serves the current record without advancing it: the ISO
// was read at some point, but nothing reads it any more.
func (s *vmediaSink) freezeMedia(files ...ipxe.MediaOpen) {
	s.setMedia(files...)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reading = false
}

func (s *vmediaSink) upload(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.uploads[path]
	return b, ok
}

// mediaStatusTransport carries every /media/status exchange to completion
// regardless of the context the probe issued it under. The probe's first
// sample runs inside the media-read window, and with the 20 ms windows
// these tests use the loopback round trip itself can outlive the window
// on a loaded runner. The window then cuts the request short, no sample
// decodes, and the probe reports — correctly, per #197 — that media-read
// evidence was unavailable rather than that the ISO was never opened; the
// never-observed assertions fail on a scheduling accident (#262, third
// instance). Detaching the exchange from the request's context makes the
// precondition true by construction: the sink's answer reaches the probe,
// and only then can the window's expiry be the result. The sink answers
// at once and never hangs, so nothing is left waiting on a dead context —
// a run cancelled mid-exchange is seen by the probe as soon as the answer
// is in.
type mediaStatusTransport struct {
	base http.RoundTripper
}

func (t mediaStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(req.WithContext(context.WithoutCancel(req.Context())))
}

// vmediaOrchestrator builds an orchestrator whose BMC is a mock, whose
// deployer config points at the sink through the real config path, whose
// pollers never wait on wall-clock tickers, and whose media-read probe is
// guaranteed its first sample before the window can close.
func vmediaOrchestrator(t *testing.T, sink *vmediaSink, client *bmc.MockClient, window time.Duration) (*Orchestrator, *DiscoveredNode) {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(sink.srv.URL, "http://"))
	if err != nil {
		t.Fatalf("sink URL: %v", err)
	}
	httpPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("sink port: %v", err)
	}
	cfg := &BootstrapConfig{
		Deployer:    DeployerConfig{NetbootMediaDir: fleetMedia, Host: host, BootstrapHTTPPort: httpPort},
		Environment: testEnvironment(),
		Platform:    PlatformGlobalConfig{Domain: "test.local"},
		ISOPath:     "/isos/platform.iso",
		Nodes: []NodeConfig{{
			Hostname: "node-02", Role: RoleControlPlane, BootMethod: BootMethodVirtualMedia,
			BMCAddress: "198.51.100.102", BMCUser: "admin", BMCPassword: "pass", BMCProtocol: "ipmi",
			MACs: []string{"aa:bb:cc:dd:ee:02"},
		}},
	}
	o, err := NewOrchestrator(OrchestratorParams{
		Config:                cfg,
		BMCFactory:            &bmc.MockClientFactory{Client: client},
		Logger:                orchTestLogger(),
		HealthChecker:         &mockHealthChecker{},
		ConfigServerReadiness: readyConfigServer{},
		SkipVirtualMediaMount: true,
	})
	if err != nil {
		t.Fatalf("NewOrchestrator: %v", err)
	}
	// Ticks are queued generously: verifyPowerOn consumes one per poll
	// and the mock reports "on" on its first poll after PowerOn.
	o.pollTicker = newFakeHealthTicker(64).New
	o.mediaReadWindow = window
	o.mediaReadHTTPClient = &http.Client{Transport: mediaStatusTransport{base: sink.srv.Client().Transport}}
	// The advisory media watch falls through to the install-log wait, so
	// a test that serves no install log needs that window bounded too.
	//
	// The two windows are set together only because most tests want both
	// to expire. They mean different things, and a test whose install log
	// IS served must widen bootProbeWindow afterwards: expiry is the
	// behaviour under test for the media watch, but for the log poller it
	// is a scheduling accident that costs a retry (#214).
	o.bootProbeWindow = window
	node := &DiscoveredNode{NodeConfig: cfg.Nodes[0], BMCManaged: true, DiscoveredMACs: cfg.Nodes[0].MACs}
	return o, node
}

// fakeConsole is a serial console a test feeds: Read hands out the
// scripted chunks in order, then blocks — the way an idle SOL session
// does — until Close.
type fakeConsole struct {
	data   chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeConsole(chunks ...string) *fakeConsole {
	f := &fakeConsole{data: make(chan []byte, len(chunks)), closed: make(chan struct{})}
	for _, c := range chunks {
		f.data <- []byte(c)
	}
	return f
}

func (f *fakeConsole) Read(p []byte) (int, error) {
	// Scripted output is delivered before a close is honoured, so a
	// recorder stopped right after start still sees every chunk.
	select {
	case b := <-f.data:
		return copy(p, b), nil
	default:
	}
	select {
	case b := <-f.data:
		return copy(p, b), nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeConsole) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

// consoleFeed is a consoleOpener that hands every attempt a fresh
// fakeConsole with the same script, counting opens and closes.
type consoleFeed struct {
	chunks []string
	err    error
	opens  atomic.Int64
	mu     sync.Mutex
	opened []*fakeConsole
}

func (c *consoleFeed) open(_ context.Context, _ *bmc.Config) (io.ReadCloser, error) {
	c.opens.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	f := newFakeConsole(c.chunks...)
	c.mu.Lock()
	c.opened = append(c.opened, f)
	c.mu.Unlock()
	return f, nil
}

// allClosed reports whether every console handed out was closed.
func (c *consoleFeed) allClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range c.opened {
		select {
		case <-f.closed:
		default:
			return false
		}
	}
	return true
}

// diskBootScript is what a host that ignored the virtual CD and booted
// its on-disk system writes to the console.
var diskBootScript = []string{
	"\x1b[2J\x1b[H",
	"GRUB loading.\r\n",
	"[    0.000000] Linux version 6.12.0 (root@builder)\r\n",
	"[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda2 console=ttyS0,115200n8\r\n",
	"[    1.204431] sd 0:0:0:0: [sda] Attached SCSI disk\r\n",
	"\r\nnode-02 login: ",
}

func TestBootNodeVirtualMedia_NeverObservedIsAdvisory(t *testing.T) {
	// The media watcher reports no ISO reads — which on this fleet is
	// what a HEALTHY install looks like too (#126: the BMC's reads leave
	// no held smbd descriptors). The attempt must fall through to the
	// install-log wait instead of aborting, and when the log never
	// appears the final error is the install-log failure carrying the
	// console transcript and the never-observed note.
	sink := newVmediaSink(t)
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)
	feed := &consoleFeed{chunks: diskBootScript}
	o.consoleOpener = feed.open

	err := o.bootNodeVirtualMedia(t.Context(), node)
	if err == nil {
		t.Fatal("expected the boot to fail when no install log ever appears")
	}

	var exhausted ErrBootRetryExhausted
	if !errors.As(err, &exhausted) || exhausted.MaxRetries != defaultBootRetryMax {
		t.Fatalf("the install-log wait feeds the retry loop and exhausts it, got %v", err)
	}
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrInstallLogNotFound in the chain, got %v", err)
	}
	if !notFound.MediaNeverObserved {
		t.Error("the final error must carry the never-observed note")
	}
	if notFound.Console == nil || notFound.Console.URL == "" || notFound.Console.Bytes == 0 {
		t.Fatalf("console transcript should be attached: %+v", notFound.Console)
	}
	msg := err.Error()
	for _, want := range []string{
		"install log never appeared",
		"the media watcher also never saw the ISO opened",
		"console transcript: ",
		"/installs/node-02/console-attempt" + strconv.Itoa(defaultBootRetryMax) + ".log",
		"last 5 lines:\nGRUB loading.\n",
		"node-02 login:",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must contain %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "\x1b[") || strings.Contains(msg, "\r") {
		t.Errorf("the quoted tail must be free of escape sequences and carriage returns: %q", msg)
	}
	if strings.Contains(msg, "booted from disk") || strings.Contains(msg, "firmware never read") {
		t.Errorf("never-observed is advisory and must not be diagnosed as a firmware failure: %s", msg)
	}

	// One console per attempt, opened before the power cycle and closed
	// by the time the attempt is reported; one upload per attempt with
	// the raw transcript. The uploads succeed even though the attempt's
	// media and install-log windows had both expired by upload time —
	// the upload context is detached from the attempt's (#126).
	if got := feed.opens.Load(); got != int64(defaultBootRetryMax) {
		t.Errorf("expected %d console sessions (one per attempt), got %d", defaultBootRetryMax, got)
	}
	if !feed.allClosed() {
		t.Error("every console session must be closed when its attempt ends")
	}
	raw := strings.Join(diskBootScript, "")
	for attempt := 1; attempt <= defaultBootRetryMax; attempt++ {
		path := "/installs/node-02/console-attempt" + strconv.Itoa(attempt) + ".log"
		if body, ok := sink.upload(path); !ok || string(body) != raw {
			t.Errorf("expected the raw transcript uploaded at %s", path)
		}
	}
	// The NVRAM clear safety net still ran on the retries.
	if got := client.ClearUEFIBootEntriesCalls(); got != int64(defaultBootRetryMax-1) {
		t.Errorf("expected %d NVRAM clears on retries, got %d", defaultBootRetryMax-1, got)
	}
}

func TestBootNodeVirtualMedia_NeverObservedSilentConsole(t *testing.T) {
	// Nothing on SOL, nothing read, no install log: on this fleet BIOS
	// POST is not redirected, so the error says the host never reached
	// an OS (or redirection is off in BIOS), plus the advisory
	// never-observed note, and nothing is uploaded.
	sink := newVmediaSink(t)
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)
	feed := &consoleFeed{}
	o.consoleOpener = feed.open

	err := o.bootNodeVirtualMedia(t.Context(), node)
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrInstallLogNotFound, got %v", err)
	}
	if !notFound.MediaNeverObserved {
		t.Error("the never-observed note must ride the final error")
	}
	if notFound.Console == nil || notFound.Console.Bytes != 0 || notFound.Console.URL != "" || notFound.Console.Error != "" {
		t.Errorf("a silent console is a captured, empty transcript: %+v", notFound.Console)
	}
	msg := err.Error()
	for _, want := range []string{"console silent for the whole window", "BIOS POST is not redirected", "halted before the OS", "console redirection is disabled in BIOS", "the media watcher also never saw the ISO opened"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error must say %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "booted from disk") {
		t.Errorf("silence must never be read as a disk boot: %s", msg)
	}
	if len(sink.uploads) != 0 {
		t.Errorf("nothing to upload for a silent console, got %v", sink.uploads)
	}
	if !feed.allClosed() {
		t.Error("console sessions must be closed")
	}
}

func TestBootNodeVirtualMedia_NeverObservedWithoutConsole(t *testing.T) {
	// The default opener activates SOL on a fresh client; the mock's
	// Console reports the operation unsupported. The attempts continue
	// without a transcript and the error says why there is none.
	sink := newVmediaSink(t)
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)

	err := o.bootNodeVirtualMedia(t.Context(), node)
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrInstallLogNotFound, got %v", err)
	}
	if notFound.Console == nil || notFound.Console.Error == "" || notFound.Console.Bytes != 0 {
		t.Errorf("console should record why there is no transcript: %+v", notFound.Console)
	}
	if !strings.Contains(err.Error(), "console transcript not captured: ") || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error should say the transcript could not be captured and why: %v", err)
	}
	if got := client.ConsoleCalls(); got != int64(defaultBootRetryMax) {
		t.Errorf("SOL is attempted once per boot attempt, got %d", got)
	}
	if len(sink.uploads) != 0 {
		t.Error("nothing to upload without a transcript")
	}
}

func TestBootNodeVirtualMedia_MediaReadThenInstalled(t *testing.T) {
	sink := newVmediaSink(t)
	sink.setMedia(ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1, MaxPos: 1 << 20})
	sink.mu.Lock()
	sink.serveLog = true
	sink.mu.Unlock()
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, time.Hour)
	feed := &consoleFeed{chunks: []string{"[    0.000000] Linux version 6.12.0\r\n", "autoinstall: done\r\n"}}
	o.consoleOpener = feed.open

	if err := o.bootNodeVirtualMedia(t.Context(), node); err != nil {
		t.Fatalf("a read ISO and a clean install log must succeed, got %v", err)
	}
	if feed.opens.Load() != 1 || !feed.allClosed() {
		t.Errorf("one console session for the one attempt, closed on success: opens=%d closed=%v", feed.opens.Load(), feed.allClosed())
	}
	if body, ok := sink.upload("/installs/node-02/console-attempt1.log"); !ok || !strings.Contains(string(body), "autoinstall: done") {
		t.Errorf("the boot transcript is uploaded beside the install log on success too, got %v", sink.uploads)
	}
}

func TestBootNodeVirtualMedia_UnsupportedSinkFallsThroughToLogPoller(t *testing.T) {
	sink := newVmediaSink(t)
	sink.mu.Lock()
	sink.mediaCode = http.StatusNotFound
	sink.serveLog = true
	sink.mu.Unlock()
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, time.Hour)

	if err := o.bootNodeVirtualMedia(t.Context(), node); err != nil {
		t.Fatalf("an old container without /media/status must not fail the boot, got %v", err)
	}
	sink.mu.Lock()
	hits := sink.mediaHits
	sink.mu.Unlock()
	if hits != 2 {
		t.Errorf("unsupported endpoint is probed once for the baseline and once by the gate, got %d", hits)
	}
}

func TestBootNodeVirtualMedia_MonitoringOutageIsNotNeverRead(t *testing.T) {
	// /media/status answers 503 for the whole window: the container's
	// watcher is down, which says nothing about the host. The boot must
	// fall through to the install log, which reports success.
	sink := newVmediaSink(t)
	sink.mu.Lock()
	sink.mediaCode = http.StatusServiceUnavailable
	sink.serveLog = true
	sink.mu.Unlock()
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)
	// The media window is short on purpose: the outage lasts the whole of
	// it, and it expiring is the scenario. The install-log wait is not
	// under test here — the log is served and the first poll finds it — so
	// its window must not be able to expire. At 20ms a loaded host beat the
	// poller, attempt 1 was abandoned, and the retry opened a second
	// console session: the assertion below failed with opens=2 on a branch
	// that does not touch this package (#214).
	o.bootProbeWindow = time.Hour
	feed := &consoleFeed{}
	o.consoleOpener = feed.open

	if err := o.bootNodeVirtualMedia(t.Context(), node); err != nil {
		t.Fatalf("a monitoring outage must not be diagnosed as never-read, got %v", err)
	}
	if feed.opens.Load() != 1 || !feed.allClosed() {
		t.Errorf("one console session, closed: opens=%d closed=%v", feed.opens.Load(), feed.allClosed())
	}
}

func TestMediaReadWindow_CoversMeasuredFirstRead(t *testing.T) {
	// Measured on node-02 (2026-08-29): the first per-MAC installer.yaml
	// GET lands ≈ 6 min 15 s after power-on, and the first ISO read a
	// little before it. The watch is advisory now (#126), but its window
	// still covers the measured first read so any evidence that does
	// appear (a mount-time open) is caught rather than cut off.
	const measuredFirstConfigFetch = 6*time.Minute + 15*time.Second
	if defaultMediaReadWindow != 7*time.Minute {
		t.Fatalf("the window is a package constant set from the measurement, got %s", defaultMediaReadWindow)
	}
	if defaultMediaReadWindow < measuredFirstConfigFetch+defaultMediaReadPollInterval {
		t.Fatalf("defaultMediaReadWindow %s does not cover the measured first read %s plus a poll %s",
			defaultMediaReadWindow, measuredFirstConfigFetch, defaultMediaReadPollInterval)
	}
	if defaultMediaReadWindow >= bootProbeTimeout {
		t.Fatalf("the media watch (%s) must be shorter than the install-log wait (%s) it front-runs",
			defaultMediaReadWindow, bootProbeTimeout)
	}
}

func TestBootNodeVirtualMedia_InstallLogMissingCarriesConsole(t *testing.T) {
	// The ISO is read, but the installer never uploads a log: the final
	// error is still ErrInstallLogNotFound, now carrying the transcript
	// of the last attempt.
	sink := newVmediaSink(t)
	sink.setMedia(ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1})
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, time.Hour)
	o.bootProbeWindow = 20 * time.Millisecond
	feed := &consoleFeed{chunks: []string{"[    0.000000] Linux version 6.12.0\r\n", "autoinstall: partitioning /dev/sda\r\n", "Kernel panic - not syncing: VFS: Unable to mount root fs\r\n"}}
	o.consoleOpener = feed.open

	err := o.bootNodeVirtualMedia(t.Context(), node)
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("expected ErrInstallLogNotFound, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the poller's timeout should be the cause: %v", err)
	}
	if notFound.Console == nil || notFound.Console.URL == "" {
		t.Fatalf("console should be attached to the install-log failure: %+v", notFound.Console)
	}
	if !strings.Contains(notFound.Console.URL, "/console-attempt"+strconv.Itoa(defaultBootRetryMax)+".log") {
		t.Errorf("the final error carries the last attempt's transcript: %q", notFound.Console.URL)
	}
	if !strings.Contains(err.Error(), "Kernel panic - not syncing") {
		t.Errorf("error text should end with the console tail: %v", err)
	}
	if feed.opens.Load() != int64(defaultBootRetryMax) || !feed.allClosed() {
		t.Errorf("one console per attempt, all closed: opens=%d closed=%v", feed.opens.Load(), feed.allClosed())
	}
	for attempt := 1; attempt <= defaultBootRetryMax; attempt++ {
		if _, ok := sink.upload("/installs/node-02/console-attempt" + strconv.Itoa(attempt) + ".log"); !ok {
			t.Errorf("attempt %d transcript not uploaded", attempt)
		}
	}
}

func TestBootNodeVirtualMedia_PreCycleReadDoesNotCount(t *testing.T) {
	// The previous boot had the ISO open before this attempt and smbd
	// still holds the descriptor idle; the watcher's cumulative record
	// shows 500 samples of past activity and refreshes smbd's last_seen
	// on every poll — including while the baselines are being taken —
	// but no open event or position change happens after the power
	// cycle. That must still be never-read: the attempt's evidence has
	// to move past the baseline, and an idle descriptor is not evidence.
	sink := newVmediaSink(t)
	sink.freezeMedia(ipxe.MediaOpen{Path: "/data/platform.iso", OpenSamples: 500, MaxPos: 1 << 30,
		Openers: []ipxe.MediaOpener{{Name: "smbd", Opens: 1, OpenSamples: 500, OpenEvents: 1, PosChanges: 499, MaxPos: 1 << 30, LastActivity: time.Now()}}})
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)

	err := o.bootNodeVirtualMedia(t.Context(), node)
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) || !notFound.MediaNeverObserved {
		t.Fatalf("a read from before the power cycle must not count as this attempt's evidence, got %v", err)
	}
}

func TestBootNodeVirtualMedia_OtherProcessAfterBaselineDoesNotCount(t *testing.T) {
	// smbd read the ISO on an earlier attempt, so its name is on the
	// record; after this attempt's baseline only a checksum job touches
	// the file. smbd's own counters do not move, so this is never-read.
	sink := newVmediaSink(t)
	sink.freezeMedia(ipxe.MediaOpen{Path: "/data/platform.iso", OpenSamples: 20,
		Openers: []ipxe.MediaOpener{
			{Name: "smbd", OpenSamples: 20, OpenEvents: 1, PosChanges: 19, LastActivity: time.Now().Add(-time.Hour)},
		}})
	// Let the checksum start reading after the baseline: the sink serves
	// it as live activity from the second poll on.
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)
	orig := sink.srv.Config.Handler
	var polls int
	sink.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == mediaStatusPath {
			sink.mu.Lock()
			polls++
			if polls == 2 {
				f := &sink.media.Files[0]
				f.Openers = append(f.Openers, ipxe.MediaOpener{Name: "sha256sum", Opens: 1, OpenSamples: 1, OpenEvents: 1, LastActivity: time.Now()})
			}
			if polls >= 2 {
				for j := range sink.media.Files[0].Openers {
					if sink.media.Files[0].Openers[j].Name == "sha256sum" {
						sink.media.Files[0].Openers[j].PosChanges++
						sink.media.Files[0].Openers[j].LastActivity = time.Now()
					}
				}
			}
			sink.mu.Unlock()
		}
		orig.ServeHTTP(w, r)
	})

	err := o.bootNodeVirtualMedia(t.Context(), node)
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) || !notFound.MediaNeverObserved {
		t.Fatalf("another process reading after the baseline must not pass as smbd, got %v", err)
	}
}

func TestBootNodeVirtualMedia_BaselineTakenAfterVerifiedPowerOff(t *testing.T) {
	// The host is ON when the attempt starts. The media baseline must be
	// read only once the BMC has confirmed the chassis off — so anything
	// the running OS did with the ISO lands before the baseline — and
	// before the power-on. The console, by contrast, is open before the
	// power-off so the transcript covers the boot from its first byte.
	sink := newVmediaSink(t)
	sink.setMedia(ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1})
	sink.mu.Lock()
	sink.serveLog = true
	sink.mu.Unlock()
	client := bmc.NewMockClient()
	client.Power = bmc.PowerStateOn
	o, node := vmediaOrchestrator(t, sink, client, time.Hour)
	feed := &consoleFeed{}
	var consoleOpenedWithPowerOffCalls int64
	o.consoleOpener = func(ctx context.Context, cfg *bmc.Config) (io.ReadCloser, error) {
		consoleOpenedWithPowerOffCalls = client.PowerOffCalls()
		return feed.open(ctx, cfg)
	}

	orig := sink.srv.Config.Handler
	var baselineState bmc.PowerState
	var baselineOffCalls, baselineOnCalls int64
	var mediaPolls int
	sink.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == mediaStatusPath {
			sink.mu.Lock()
			mediaPolls++
			first := mediaPolls == 1
			sink.mu.Unlock()
			if first {
				baselineState = client.Power
				baselineOffCalls = client.PowerOffCalls()
				baselineOnCalls = client.PowerOnCalls()
			}
		}
		orig.ServeHTTP(w, r)
	})

	if err := o.bootNodeVirtualMedia(t.Context(), node); err != nil {
		t.Fatalf("boot: %v", err)
	}
	if baselineState != bmc.PowerStateOff || baselineOffCalls != 1 || baselineOnCalls != 0 {
		t.Errorf("baseline must be read with the chassis off, after PowerOff and before PowerOn: state=%s offCalls=%d onCalls=%d",
			baselineState, baselineOffCalls, baselineOnCalls)
	}
	if consoleOpenedWithPowerOffCalls != 0 {
		t.Errorf("the console must be open before the power cycle starts, saw %d power-offs already", consoleOpenedWithPowerOffCalls)
	}
}

func TestBootNodeVirtualMedia_AnotherNodesReadsDoNotCount(t *testing.T) {
	// Two nodes share the ISO. The other node's BMC (.103) is reading it
	// busily; this node's BMC (.102) never opens it. Its gate must not
	// be satisfied by the neighbour's traffic.
	sink := newVmediaSink(t)
	sink.setMedia(ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1,
		Openers: []ipxe.MediaOpener{{Name: "smbd", Client: "198.51.100.103", Opens: 1, OpenSamples: 1, OpenEvents: 1, LastActivity: time.Now()}}})
	orig := sink.srv.Config.Handler
	sink.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == mediaStatusPath {
			sink.mu.Lock()
			for j := range sink.media.Files[0].Openers {
				sink.media.Files[0].Openers[j].PosChanges++
				sink.media.Files[0].Openers[j].LastActivity = time.Now()
			}
			sink.mu.Unlock()
		}
		orig.ServeHTTP(w, r)
	})
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, 20*time.Millisecond)

	err := o.bootNodeVirtualMedia(t.Context(), node)
	var notFound ErrInstallLogNotFound
	if !errors.As(err, &notFound) || !notFound.MediaNeverObserved {
		t.Fatalf("a neighbour's reads must not count as this node's evidence, got %v", err)
	}
}

func TestBootNodeVirtualMedia_CancelledRunDoesNotRetry(t *testing.T) {
	// A run cancelled while waiting on the media-read watch must surface
	// the cancellation, not a never-read diagnosis, must not go around
	// the retry loop power-cycling a host nobody asked to boot, and must
	// release the console it opened.
	sink := newVmediaSink(t)
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, time.Hour)
	feed := &consoleFeed{chunks: diskBootScript}
	o.consoleOpener = feed.open

	ctx, cancel := context.WithCancel(t.Context())
	orig := sink.srv.Config.Handler
	sink.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == mediaStatusPath {
			cancel()
		}
		orig.ServeHTTP(w, r)
	})

	err := o.bootNodeVirtualMedia(ctx, node)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the run's cancellation, got %v", err)
	}
	var notFound ErrInstallLogNotFound
	if errors.As(err, &notFound) {
		t.Error("cancellation must not be diagnosed as an install-log failure")
	}
	if feed.opens.Load() != 1 || client.PowerOnCalls() != 1 {
		t.Errorf("one console and no second boot after cancellation: consoles=%d powerOns=%d",
			feed.opens.Load(), client.PowerOnCalls())
	}
	if !feed.allClosed() {
		t.Error("the console must be released when the run is cancelled")
	}
}

func TestBootNodeVirtualMedia_CancelledDuringLogPollDoesNotRetry(t *testing.T) {
	// The media was read and the run is cancelled while the install log
	// is being polled: the cancellation is the error, no retry power
	// cycles the host, and the console is released.
	sink := newVmediaSink(t)
	sink.setMedia(ipxe.MediaOpen{Path: "/data/platform.iso", Opens: 1})
	client := bmc.NewMockClient()
	o, node := vmediaOrchestrator(t, sink, client, time.Hour)
	feed := &consoleFeed{chunks: []string{"[    0.000000] Linux version 6.12.0\r\n"}}
	o.consoleOpener = feed.open

	ctx, cancel := context.WithCancel(t.Context())
	orig := sink.srv.Config.Handler
	sink.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/install.log") {
			cancel()
		}
		orig.ServeHTTP(w, r)
	})

	err := o.bootNodeVirtualMedia(ctx, node)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the run's cancellation, got %v", err)
	}
	var notFound ErrInstallLogNotFound
	if errors.As(err, &notFound) {
		t.Error("cancellation must not be reported as a missing install log")
	}
	if client.PowerOnCalls() != 1 || feed.opens.Load() != 1 {
		t.Errorf("no second boot after cancellation: powerOns=%d consoles=%d", client.PowerOnCalls(), feed.opens.Load())
	}
	if !feed.allClosed() {
		t.Error("the console must be released when the run is cancelled")
	}
}

func TestOpenSOLConsole_Errors(t *testing.T) {
	client := bmc.NewMockClient()
	o := &Orchestrator{logger: orchTestLogger(), bmcFactory: &bmc.MockClientFactory{Client: client}}
	cfg := &bmc.Config{Address: "198.51.100.102"}

	// The mock has no SOL: the error is the client's, and the client is
	// released.
	if _, err := o.openSOLConsole(t.Context(), cfg); err == nil {
		t.Error("an unsupported console must be an error")
	}
	if client.ConsoleCalls() != 1 || client.CloseCalls() != 1 {
		t.Errorf("Console attempted once and the client closed on failure: console=%d close=%d", client.ConsoleCalls(), client.CloseCalls())
	}

	o.bmcFactory = &bmc.MockClientFactory{Err: bmc.ErrNilConfig{}}
	if _, err := o.openSOLConsole(t.Context(), cfg); err == nil {
		t.Error("a client that cannot be built must be an error")
	}
}

func TestConsoleRecorder_BoundKeepsTheEnd(t *testing.T) {
	o := &Orchestrator{logger: orchTestLogger()}
	line := strings.Repeat("x", 1023) + "\n"
	script := make([]string, 0, consoleTranscriptMaxBytes/len(line)+8)
	for i := 0; i < cap(script); i++ {
		script = append(script, line)
	}
	script = append(script, "the end\n")
	feed := &consoleFeed{chunks: script}
	o.consoleOpener = feed.open

	rec := o.startConsoleTranscript(t.Context(), &bmc.Config{}, "node-02")
	// Drain: the recorder has consumed the whole script once Read blocks
	// on the closed channel, which stop() forces.
	rec.stop()
	got := rec.transcript()
	if len(got) > consoleTranscriptMaxBytes {
		t.Errorf("transcript exceeds the bound: %d bytes", len(got))
	}
	if len(got) < consoleTranscriptMaxBytes/2 {
		t.Errorf("the bound must keep at least half the transcript, got %d bytes", len(got))
	}
	if !strings.HasSuffix(string(got), "the end\n") {
		t.Error("the end of the transcript must survive the bound")
	}
	// Idempotent stop; transcript unchanged.
	rec.stop()
	if len(rec.transcript()) != len(got) {
		t.Error("stop must be idempotent")
	}
}

func TestFinishConsoleTranscript_UploadFailureIsReported(t *testing.T) {
	o := &Orchestrator{logger: orchTestLogger()}
	feed := &consoleFeed{chunks: []string{"boot\n"}}
	o.consoleOpener = feed.open
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInsufficientStorage)
	}))
	t.Cleanup(srv.Close)

	rec := o.startConsoleTranscript(t.Context(), &bmc.Config{}, "node-02")
	out := o.finishConsoleTranscript(rec, srv.URL, "node-02", 1)
	if out.Bytes != 5 || out.URL != "" || !strings.Contains(out.Error, "status 507") {
		t.Errorf("upload failure must be recorded with the transcript kept: %+v", out)
	}
	if got := out.Summary(); !strings.Contains(got, "console transcript captured (5 bytes) [upload failed: ") || !strings.HasSuffix(got, "last 1 lines:\nboot") {
		t.Errorf("Summary() = %q", got)
	}
}

func TestFinishConsoleTranscript_UploadOutlivesTheAttemptContext(t *testing.T) {
	// Run 7 (#126): every transcript upload died "context deadline
	// exceeded" because it inherited the attempt's expired context. The
	// upload now runs on a context of its own: end the attempt's before
	// finishing and the transcript must still land on the sink.
	o := &Orchestrator{logger: orchTestLogger()}
	feed := &consoleFeed{chunks: []string{"boot\n"}}
	o.consoleOpener = feed.open
	var uploaded atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			uploaded.Store(true)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	attemptCtx, cancel := context.WithCancel(t.Context())
	rec := o.startConsoleTranscript(attemptCtx, &bmc.Config{}, "node-02")
	cancel()
	out := o.finishConsoleTranscript(rec, srv.URL, "node-02", 1)
	if out.URL == "" || out.Error != "" || !uploaded.Load() {
		t.Errorf("the upload must survive the attempt context's end: %+v", out)
	}
}

func TestConsoleTail(t *testing.T) {
	in := []byte("\x1b[2J\x1b[Hfirst\r\n\r\n  second  \r\n\x1b[1;31mred\x1b[0m\r\nlast\x07\r\n")
	got := consoleTail(in, 40)
	want := []string{"first", "  second", "red", "last"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("consoleTail() = %q, want %q", got, want)
	}
	if got := consoleTail(in, 2); strings.Join(got, "|") != "red|last" {
		t.Errorf("limited tail = %q", got)
	}
	if got := consoleTail(nil, 40); len(got) != 0 {
		t.Errorf("empty transcript has no tail, got %q", got)
	}
	if got := consoleTail([]byte("\r\n\r\n"), 40); len(got) != 0 {
		t.Errorf("blank transcript has no tail, got %q", got)
	}
}

func TestConsoleTranscript_Summary(t *testing.T) {
	cases := []struct {
		name string
		c    *ConsoleTranscript
		want string
	}{
		{"nil", nil, "console transcript not captured"},
		{"not opened", &ConsoleTranscript{Error: "bmc: operation not supported: console"}, "console transcript not captured: bmc: operation not supported: console"},
		{"silent", &ConsoleTranscript{}, "console silent for the whole window — BIOS POST is not redirected to SOL on this hardware, so the firmware halted before the OS, or console redirection is disabled in BIOS"},
		{"uploaded", &ConsoleTranscript{URL: "http://x/console-attempt1.log", Bytes: 12, Tail: []string{"a", "b"}}, "console transcript: http://x/console-attempt1.log; last 2 lines:\na\nb"},
		{"upload failed", &ConsoleTranscript{Bytes: 12, Tail: []string{"a"}, Error: "status 507"}, "console transcript captured (12 bytes) [upload failed: status 507]; last 1 lines:\na"},
	}
	for _, tc := range cases {
		if got := tc.c.Summary(); got != tc.want {
			t.Errorf("%s: Summary() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestErrInstallLogNotFound_Error(t *testing.T) {
	notFound := ErrInstallLogNotFound{Hostname: "node-02", URL: "http://x/install.log", Cause: context.DeadlineExceeded, Console: &ConsoleTranscript{}}
	if !strings.HasSuffix(notFound.Error(), "; console: console silent for the whole window — BIOS POST is not redirected to SOL on this hardware, so the firmware halted before the OS, or console redirection is disabled in BIOS") {
		t.Errorf("install-log suffix: %q", notFound.Error())
	}
	notFound.MediaNeverObserved = true
	if !strings.HasSuffix(notFound.Error(), "; the media watcher also never saw the ISO opened (advisory: this fleet's BMC reads leave no held smbd descriptors)") {
		t.Errorf("never-observed suffix: %q", notFound.Error())
	}
	notFound.Console = &ConsoleTranscript{URL: "http://x/console-attempt1.log", Bytes: 3, Tail: []string{"GRUB loading."}}
	if !strings.Contains(notFound.Error(), "console transcript: http://x/console-attempt1.log") {
		t.Errorf("console URL must survive alongside the note: %q", notFound.Error())
	}
}

func TestUploadForensic_Errors(t *testing.T) {
	// The short retry delay keeps the transport-failure case from paying
	// the production pause three times over; the retry behaviour itself is
	// covered in console_transcript_upload_test.go.
	o := &Orchestrator{logger: orchTestLogger(), forensicRetryDelay: time.Millisecond}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInsufficientStorage)
	}))
	t.Cleanup(srv.Close)
	if _, err := o.uploadForensic(t.Context(), srv.URL, "node-02", "console-attempt1.log", []byte("x"), "text/plain"); err == nil {
		t.Error("non-2xx must be an error")
	}
	if _, err := o.uploadForensic(t.Context(), "http://127.0.0.1:1", "node-02", "c.log", nil, "text/plain"); err == nil {
		t.Error("transport failure must be an error")
	}
	if _, err := o.uploadForensic(t.Context(), "://bad", "node-02", "c.log", nil, "text/plain"); err == nil {
		t.Error("bad URL must be an error")
	}
}
