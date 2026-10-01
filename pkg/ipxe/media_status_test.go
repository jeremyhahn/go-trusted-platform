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

package ipxe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProc builds a procfs look-alike: procRoot/<pid>/fd/<n> symlinks and
// procRoot/<pid>/fdinfo/<n> files, exactly the two things the scan reads.
type fakeProc struct {
	t    *testing.T
	root string
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	return &fakeProc{t: t, root: t.TempDir()}
}

func (p *fakeProc) open(pid, fd int, target string, pos int64) {
	p.t.Helper()
	p.openAs("smbd", pid, fd, target, pos)
}

// openAs is open with an explicit process name for /proc/<pid>/comm; an
// empty name leaves comm absent, as a container with a hidden /proc would.
func (p *fakeProc) openAs(comm string, pid, fd int, target string, pos int64) {
	p.t.Helper()
	p.openFor(comm, "", pid, fd, target, pos)
}

// openFor is openAs with an smbd-style process title naming the client
// the process serves; an empty client writes a plain title.
func (p *fakeProc) openFor(comm, client string, pid, fd int, target string, pos int64) {
	p.t.Helper()
	pidDir := filepath.Join(p.root, itoa(pid))
	require.NoError(p.t, os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755))
	require.NoError(p.t, os.MkdirAll(filepath.Join(pidDir, "fdinfo"), 0o755))
	if comm != "" {
		require.NoError(p.t, os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm+"\n"), 0o644))
	}
	title := comm + "\x00--foreground\x00"
	if client != "" {
		title = "smbd: client [" + client + "]\x00"
	}
	require.NoError(p.t, os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(title), 0o644))
	require.NoError(p.t, os.Symlink(target, filepath.Join(pidDir, "fd", itoa(fd))))
	info := "pos:\t" + itoa64(pos) + "\nflags:\t0100000\nmnt_id:\t29\n"
	require.NoError(p.t, os.WriteFile(filepath.Join(pidDir, "fdinfo", itoa(fd)), []byte(info), 0o644))
}

// openTitled is openFor with full control of comm and cmdline, for the
// worker-title styles openFor does not produce: Alpine/musl smbd carries
// its title in comm — truncated by the kernel to 15 bytes — while
// cmdline keeps the plain argv.
func (p *fakeProc) openTitled(comm, cmdline string, pid, fd int, target string, pos int64) {
	p.t.Helper()
	pidDir := filepath.Join(p.root, itoa(pid))
	require.NoError(p.t, os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755))
	require.NoError(p.t, os.MkdirAll(filepath.Join(pidDir, "fdinfo"), 0o755))
	require.NoError(p.t, os.WriteFile(filepath.Join(pidDir, "comm"), []byte(comm+"\n"), 0o644))
	require.NoError(p.t, os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte(cmdline), 0o644))
	require.NoError(p.t, os.Symlink(target, filepath.Join(pidDir, "fd", itoa(fd))))
	info := "pos:\t" + itoa64(pos) + "\nflags:\t0100000\nmnt_id:\t29\n"
	require.NoError(p.t, os.WriteFile(filepath.Join(pidDir, "fdinfo", itoa(fd)), []byte(info), 0o644))
}

func itoa(i int) string     { return itoa64(int64(i)) }
func itoa64(i int64) string { return json.Number(formatInt(i)).String() }

func formatInt(i int64) string {
	b, err := json.Marshal(i)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestScanMediaOpens_GroupsDescriptorsByProcessName(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	require.NoError(t, os.WriteFile(iso, []byte("iso"), 0o644))

	// Two smbd workers hold the ISO; one is further into it. A checksum
	// job also has it open and must be grouped under its own name.
	proc.open(101, 7, iso, 4096)
	proc.open(102, 9, iso, 1<<20)
	proc.openAs("sha256sum", 104, 3, iso, 77)
	// A descriptor on something outside DataDir must not appear.
	proc.open(102, 3, "/var/log/samba/log.smbd", 12)
	// A non-pid directory and a dangling link are skipped / kept.
	require.NoError(t, os.MkdirAll(filepath.Join(proc.root, "sys", "fd"), 0o755))
	proc.open(103, 4, filepath.Join(data, "gone.iso"), 0)

	scan, err := scanMediaOpens(proc.root, data, 999)
	require.NoError(t, err)
	assert.Equal(t, data, scan.dataDir)
	require.Len(t, scan.files, 2, "the dangling link is still an open descriptor under DataDir")
	file := scan.files[iso]
	require.NotNil(t, file)
	assert.Equal(t, 3, file.opens)
	assert.Equal(t, int64(1<<20), file.maxPos)
	smbd := file.byName[openerKey{name: "smbd"}]
	sum := file.byName[openerKey{name: "sha256sum"}]
	require.NotNil(t, smbd)
	require.NotNil(t, sum)
	assert.Equal(t, 2, smbd.opens)
	assert.Equal(t, int64(1<<20), smbd.maxPos)
	assert.Equal(t, int64(4096+1<<20), smbd.posSum)
	assert.Equal(t, 1, sum.opens)
	assert.Equal(t, int64(77), sum.posSum)
	gone := scan.files[filepath.Join(data, "gone.iso")]
	require.NotNil(t, gone)
	assert.Equal(t, 1, gone.opens)
}

func TestScanMediaOpens_ExcludesSelfAndCountsDeleted(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")

	proc.open(555, 5, iso, 100) // pxeboot itself serving /data/ over HTTP
	proc.openAs("", 556, 5, iso+" (deleted)", 200)

	scan, err := scanMediaOpens(proc.root, data, 555)
	require.NoError(t, err)
	require.Len(t, scan.files, 1)
	file := scan.files[iso+" (deleted)"]
	require.NotNil(t, file)
	assert.Equal(t, 1, file.opens)
	assert.Equal(t, int64(200), file.maxPos)
	_, unnamed := file.byName[openerKey{}]
	assert.True(t, unnamed, "no comm file: recorded under the empty name")
}

func TestScanMediaOpens_EmptyWhenNothingOpen(t *testing.T) {
	proc := newFakeProc(t)
	proc.open(1, 0, "/dev/null", 0)
	scan, err := scanMediaOpens(proc.root, t.TempDir(), 999)
	require.NoError(t, err)
	assert.Empty(t, scan.files)
}

func TestScanMediaOpens_MissingProcRootIsTyped(t *testing.T) {
	_, err := scanMediaOpens(filepath.Join(t.TempDir(), "no-proc"), t.TempDir(), 1)
	var scanErr ErrMediaScanFailed
	require.True(t, errors.As(err, &scanErr), "got %T: %v", err, err)
	assert.True(t, os.IsNotExist(scanErr.Cause))
}

func TestReadFDPos(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	require.NoError(t, os.WriteFile(good, []byte("pos:\t77\nflags:\t02\n"), 0o644))
	assert.Equal(t, int64(77), readFDPos(good))

	noPos := filepath.Join(dir, "nopos")
	require.NoError(t, os.WriteFile(noPos, []byte("flags:\t02\n"), 0o644))
	assert.Equal(t, int64(0), readFDPos(noPos))

	bad := filepath.Join(dir, "bad")
	require.NoError(t, os.WriteFile(bad, []byte("pos:\tnope\n"), 0o644))
	assert.Equal(t, int64(0), readFDPos(bad))

	assert.Equal(t, int64(0), readFDPos(filepath.Join(dir, "missing")))
}

func TestScanMediaOpens_SeparatesSMBClients(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	// Two BMCs read the same ISO through two smbd workers; a third smbd
	// process carries no client title.
	proc.openFor("smbd", "10.4.2.103", 301, 5, iso, 1000)
	proc.openFor("smbd", "10.4.2.104", 302, 5, iso, 2000)
	proc.open(303, 5, iso, 10)

	scan, err := scanMediaOpens(proc.root, data, 999)
	require.NoError(t, err)
	file := scan.files[iso]
	require.NotNil(t, file)
	require.Len(t, file.byName, 3)
	assert.Equal(t, int64(1000), file.byName[openerKey{name: "smbd", client: "10.4.2.103"}].posSum)
	assert.Equal(t, int64(2000), file.byName[openerKey{name: "smbd", client: "10.4.2.104"}].posSum)
	assert.Equal(t, int64(10), file.byName[openerKey{name: "smbd"}].posSum)
}

func TestReadClientFromTitle(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
		return p
	}
	cases := []struct {
		file, content string
		client        string
		truncated     bool
	}{
		{"a", "smbd: client [10.4.2.103]\x00", "10.4.2.103", false},
		{"b", "smbd: client [fe80::1]\x00", "fe80::1", false},
		{"e", "  SMBD: Client [10.0.0.5:52311]\x00", "10.0.0.5:52311", false},
		{"f", "smbd[10.4.2.103]\x00", "10.4.2.103", false},
		{"g", "smbd[198.51.100", "198.51.100", true},
		{"c", "/usr/sbin/smbd\x00--foreground\x00", "", false},
		{"d", "sha256sum\x00x.iso\x00", "", false},
	}
	for _, tc := range cases {
		client, truncated := readClientFromTitle(write(tc.file, tc.content))
		assert.Equal(t, tc.client, client, tc.content)
		assert.Equal(t, tc.truncated, truncated, tc.content)
	}
	client, truncated := readClientFromTitle(filepath.Join(dir, "absent"))
	assert.Equal(t, "", client)
	assert.False(t, truncated)
}

func TestParseSMBDWorkerTitle(t *testing.T) {
	cases := []struct {
		title     string
		client    string
		truncated bool
	}{
		// The Debian per-connection title.
		{"smbd: client [10.4.2.103]", "10.4.2.103", false},
		// The Alpine per-connection title, and its 15-byte comm
		// truncation exactly as measured live during #126.
		{"smbd[10.4.2.103]", "10.4.2.103", false},
		{"smbd[198.51.100", "198.51.100", true},
		// A worker whose short address fits comm keeps its bracket.
		{"smbd[10.0.0.5]", "10.0.0.5", false},
		// Titles that name no client.
		{"smbd[", "", false},
		{"smbd", "", false},
		{"/usr/sbin/smbd --foreground", "", false},
		{"sha256sum x.iso", "", false},
	}
	for _, tc := range cases {
		client, truncated := parseSMBDWorkerTitle(tc.title)
		assert.Equal(t, tc.client, client, tc.title)
		assert.Equal(t, tc.truncated, truncated, tc.title)
	}
}

func TestScanMediaOpens_AlpineWorkerTitles(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "trusted-platform-cp.iso")
	// Measured live on the jumpbox during #126: the worker's comm is the
	// truncated title with no closing bracket, and cmdline is plain argv.
	proc.openTitled("smbd[198.51.100", "/usr/sbin/smbd\x00--foreground\x00", 401, 27, iso, 4096)
	// A worker whose full title fits comm carries the whole address.
	proc.openTitled("smbd[10.0.0.5]", "/usr/sbin/smbd\x00--foreground\x00", 402, 5, iso, 100)

	scan, err := scanMediaOpens(proc.root, data, 999)
	require.NoError(t, err)
	file := scan.files[iso]
	require.NotNil(t, file)
	require.Len(t, file.byName, 2)
	trunc := file.byName[openerKey{name: "smbd[198.51.100", client: "198.51.100", truncated: true}]
	require.NotNil(t, trunc, "the truncated comm must be attributed to its IP prefix")
	assert.Equal(t, int64(4096), trunc.posSum)
	full := file.byName[openerKey{name: "smbd[10.0.0.5]", client: "10.0.0.5", truncated: false}]
	require.NotNil(t, full, "an untruncated comm title carries the whole address")
	assert.Equal(t, int64(100), full.posSum)
}

func TestOpenersNamed_MatchesWorkerTitledComms(t *testing.T) {
	m := &MediaOpen{Openers: []MediaOpener{
		{Name: "smbd"},
		{Name: "smbd[198.51.100", Client: "198.51.100", ClientTruncated: true},
		{Name: "smbd[10.4.2.103]", Client: "10.4.2.103"},
		{Name: "smbd-notify"},
		{Name: "sha256sum"},
	}}
	got := m.OpenersNamed("smbd")
	require.Len(t, got, 3, "exact smbd plus both smbd[ worker titles; never exact-only")
	assert.Equal(t, "smbd", got[0].Name)
	assert.Equal(t, "smbd[198.51.100", got[1].Name)
	assert.Equal(t, "smbd[10.4.2.103]", got[2].Name)
}

func TestReadComm(t *testing.T) {
	dir := t.TempDir()
	comm := filepath.Join(dir, "comm")
	require.NoError(t, os.WriteFile(comm, []byte("smbd\n"), 0o644))
	assert.Equal(t, "smbd", readComm(comm))
	assert.Equal(t, "", readComm(filepath.Join(dir, "absent")))
}

func TestIsUnder(t *testing.T) {
	assert.True(t, isUnder("/data/x.iso", "/data"))
	assert.True(t, isUnder("/data/sub/x.iso (deleted)", "/data"))
	assert.False(t, isUnder("/data-other/x.iso", "/data"))
	assert.False(t, isUnder("/etc/passwd", "/data"))
	assert.False(t, isUnder("/data/../etc/passwd", "/data"))
}

func TestHTTPServer_handleMediaStatus(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	proc.open(42, 8, iso, 512)

	cfg := DefaultServerConfig()
	cfg.DataDir = data
	server := newTestHTTPServer(t, cfg)
	server.procRootOverride = proc.root
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server.startMediaWatcher(ctx)

	rr := httptest.NewRecorder()
	server.handleMediaStatus(rr, httptest.NewRequest(http.MethodGet, "/media/status", nil))
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var status MediaStatus
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &status))
	require.Len(t, status.Files, 1, "the initial sample runs before Start returns")
	assert.Equal(t, iso, status.Files[0].Path)
	assert.Equal(t, 1, status.Files[0].Opens)
	assert.Equal(t, int64(512), status.Files[0].MaxPos)
	assert.Equal(t, 1, status.Files[0].OpenSamples)
	require.Len(t, status.Files[0].Openers, 1)
	smbd := status.Files[0].Opener("smbd")
	require.NotNil(t, smbd)
	assert.Equal(t, 1, smbd.OpenEvents, "first sight is an open event")
	assert.Equal(t, 0, smbd.PosChanges)
	assert.Equal(t, 1, smbd.Activity())
	assert.Nil(t, status.Files[0].Opener("tar"))
	assert.False(t, status.Since.IsZero())
	assert.Equal(t, defaultMediaSampleInterval, status.Interval)
}

func TestHTTPServer_handleMediaStatus_Errors(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.DataDir = t.TempDir()
		server := newTestHTTPServer(t, cfg)
		rr := httptest.NewRecorder()
		server.handleMediaStatus(rr, httptest.NewRequest(http.MethodPut, "/media/status", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		assert.Equal(t, "GET", rr.Header().Get("Allow"))
	})
	t.Run("no data dir", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.DataDir = ""
		server := newTestHTTPServer(t, cfg)
		server.startMediaWatcher(context.Background())
		rr := httptest.NewRecorder()
		server.handleMediaStatus(rr, httptest.NewRequest(http.MethodGet, "/media/status", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		assert.Nil(t, server.mediaWatcher.Load(), "no watcher without a data dir")
	})
	t.Run("watcher not started", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.DataDir = t.TempDir()
		server := newTestHTTPServer(t, cfg)
		rr := httptest.NewRecorder()
		server.handleMediaStatus(rr, httptest.NewRequest(http.MethodGet, "/media/status", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})
	t.Run("proc unreadable is 503, not an empty record", func(t *testing.T) {
		cfg := DefaultServerConfig()
		cfg.DataDir = t.TempDir()
		server := newTestHTTPServer(t, cfg)
		server.procRootOverride = filepath.Join(t.TempDir(), "absent")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server.startMediaWatcher(ctx)
		rr := httptest.NewRecorder()
		server.handleMediaStatus(rr, httptest.NewRequest(http.MethodGet, "/media/status", nil))
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
		assert.Contains(t, rr.Body.String(), "no successful sample yet")
	})
}

func TestMediaWatcher_HealthyAndStale(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	clock := &fakeClock{t: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
	w := newMediaWatcher(proc.root, data, 999, time.Second, clock.now)

	var unhealthy ErrMediaWatcherUnhealthy
	err := w.healthy()
	require.True(t, errors.As(err, &unhealthy), "no sample yet: %v", err)
	assert.Equal(t, "no successful sample yet", unhealthy.Reason)

	require.NoError(t, w.sample())
	assert.NoError(t, w.healthy(), "a fresh sample is healthy")

	// The clock advances one second per call; staleFactor intervals later
	// with no successful sample, the record is refused.
	require.NoError(t, os.RemoveAll(proc.root))
	for i := 0; i < staleFactor; i++ {
		require.Error(t, w.sample())
	}
	// A failed scan never reads the clock; move it past the staleness
	// bound explicitly.
	clock.t = clock.t.Add(staleFactor * time.Second)
	err = w.healthy()
	require.True(t, errors.As(err, &unhealthy), "stale: %v", err)
	assert.Contains(t, unhealthy.Reason, "last successful sample")
	assert.Error(t, unhealthy.Cause, "the last scan error rides along")
}
