package qemu

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netlink"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// qmpGreeting is the banner a QEMU QMP server sends on every new connection.
const qmpGreeting = `{"QMP":{"version":{"qemu":{"major":8,"minor":2,"micro":1},"package":""},"capabilities":["oob"]}}`

// qmpRequest is one command the fake QMP server received.
type qmpRequest struct {
	Execute   string                 `json:"execute"`
	Arguments map[string]interface{} `json:"arguments"`
}

// fakeQMP is an in-process QMP server on a temporary unix socket. It answers
// each command with the reply registered for it, or {"return":{}}.
type fakeQMP struct {
	path     string
	listener net.Listener
	// handshake is set only before serve starts (see withHandshake).
	handshake string

	mu       sync.Mutex
	replies  map[string]string
	requests []qmpRequest
	// onCommand, when set, runs before the server replies to a command.
	onCommand func(execute string)
}

// newFakeQMP starts a fake QMP server. The socket directory is kept short
// because unix socket paths are limited to 108 bytes.
func newFakeQMP(t *testing.T, replies map[string]string, opts ...fakeQMPOption) *fakeQMP {
	t.Helper()
	dir, err := os.MkdirTemp("", "qmp964")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })

	path := filepath.Join(dir, "qmp.sock")
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	if replies == nil {
		replies = map[string]string{}
	}
	f := &fakeQMP{path: path, listener: listener, handshake: `{"return":{}}`, replies: replies}
	// Options are applied before the server goroutine starts, so the
	// fields they set are never written while it reads them.
	for _, opt := range opts {
		opt(f)
	}
	go f.serve()
	return f
}

// fakeQMPOption configures a fakeQMP before it starts serving.
type fakeQMPOption func(f *fakeQMP)

// withHandshake sets the reply the server sends to qmp_capabilities.
func withHandshake(reply string) fakeQMPOption {
	return func(f *fakeQMP) { f.handshake = reply }
}

// setOnCommand installs a hook that runs before the server replies to a
// command. It takes f.mu because the server may already be serving.
func (f *fakeQMP) setOnCommand(hook func(execute string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onCommand = hook
}

func (f *fakeQMP) serve() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeQMP) handle(conn net.Conn) {
	defer conn.Close()
	if _, err := io.WriteString(conn, qmpGreeting+"\n"); err != nil {
		return
	}
	dec := json.NewDecoder(conn)
	for {
		var req qmpRequest
		if err := dec.Decode(&req); err != nil {
			return
		}
		reply := f.handshake
		if req.Execute != "qmp_capabilities" {
			f.mu.Lock()
			f.requests = append(f.requests, req)
			r, ok := f.replies[req.Execute]
			onCommand := f.onCommand
			f.mu.Unlock()
			if onCommand != nil {
				onCommand(req.Execute)
			}
			reply = `{"return":{}}`
			if ok {
				reply = r
			}
		}
		if _, err := io.WriteString(conn, reply+"\n"); err != nil {
			return
		}
	}
}

// last returns the most recent non-handshake command the server received.
func (f *fakeQMP) last(t *testing.T) qmpRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.requests)
	return f.requests[len(f.requests)-1]
}

// connectFakeMonitor starts a fake QMP server and returns a connected Monitor.
func connectFakeMonitor(t *testing.T, replies map[string]string) (*Monitor, *fakeQMP) {
	t.Helper()
	srv := newFakeQMP(t, replies)
	m := NewMonitor(srv.path, 2*time.Second, logging.DefaultLogger())
	require.NoError(t, m.Connect(context.Background()))
	t.Cleanup(func() { require.NoError(t, m.Close()) })
	return m, srv
}

const qmpGenericError = `{"error":{"class":"GenericError","desc":"boom"}}`

func TestMonitor964_ConnectReportsVersionAndCapabilities(t *testing.T) {
	m, _ := connectFakeMonitor(t, nil)

	assert.True(t, m.IsConnected())
	v, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, "8.2.1", v.String())
	caps, err := m.Capabilities()
	require.NoError(t, err)
	assert.Equal(t, []string{"oob"}, caps)

	var already ErrMonitorAlreadyConnected
	assert.True(t, errors.As(m.Connect(context.Background()), &already))
}

func TestMonitor964_ConnectFailures(t *testing.T) {
	t.Run("handshake rejected", func(t *testing.T) {
		srv := newFakeQMP(t, nil, withHandshake(qmpGenericError))
		m := NewMonitor(srv.path, 2*time.Second, nil)

		var target ErrMonitorHandshakeFailed
		assert.True(t, errors.As(m.Connect(context.Background()), &target))
		assert.False(t, m.IsConnected())
	})

	t.Run("path is not a socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "plain-file")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
		m := NewMonitor(path, time.Second, nil)

		var target ErrMonitorConnectionFailed
		assert.True(t, errors.As(m.Connect(context.Background()), &target))
	})
}

func TestMonitor964_StatusAndQueries(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"query-status":     `{"return":{"running":false,"singlestep":false,"status":"paused"}}`,
		"query-commands":   `{"return":[{"name":"stop"},{"name":"cont"}]}`,
		"query-block":      `{"return":[{"device":"drive0","locked":false,"removable":false}]}`,
		"query-blockstats": `{"return":[{"device":"drive0"}]}`,
	})
	ctx := context.Background()

	status, err := m.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, VMStatusPaused, status)

	cmds, err := m.QueryCommands(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"stop", "cont"}, cmds)

	devs, err := m.BlockDevices(ctx)
	require.NoError(t, err)
	require.Len(t, devs, 1)
	assert.Equal(t, "drive0", devs[0].Device)

	stats, err := m.BlockStats(ctx)
	require.NoError(t, err)
	assert.Len(t, stats, 1)
}

func TestMonitor964_InvalidResponses(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"query-status":     `{"return":"not-an-object"}`,
		"query-commands":   `{"return":{}}`,
		"query-block":      `{"return":{}}`,
		"query-blockstats": `{"return":{}}`,
	})
	ctx := context.Background()

	calls := map[string]func() error{
		"query-status":     func() error { _, err := m.Status(ctx); return err },
		"query-commands":   func() error { _, err := m.QueryCommands(ctx); return err },
		"query-block":      func() error { _, err := m.BlockDevices(ctx); return err },
		"query-blockstats": func() error { _, err := m.BlockStats(ctx); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var target ErrMonitorInvalidResponse
			require.True(t, errors.As(call(), &target))
			assert.Equal(t, name, target.Command)
		})
	}
}

func TestMonitor964_CommandsSendExpectedExecute(t *testing.T) {
	m, srv := connectFakeMonitor(t, nil)
	ctx := context.Background()

	tests := []struct {
		execute string
		call    func() error
		args    map[string]interface{}
	}{
		{"stop", func() error { return m.Pause(ctx) }, nil},
		{"cont", func() error { return m.Resume(ctx) }, nil},
		{"system_powerdown", func() error { return m.SystemPowerdown(ctx) }, nil},
		{"system_reset", func() error { return m.SystemReset(ctx) }, nil},
		{"blockdev-del", func() error { return m.BlockdevDel(ctx, "node0") }, map[string]interface{}{"node-name": "node0"}},
		{"device_del", func() error { return m.DeviceDel(ctx, "disk0") }, map[string]interface{}{"id": "disk0"}},
		{"device_add", func() error { return m.AddVirtioBlkDevice(ctx, "disk0", "node0") },
			map[string]interface{}{"driver": "virtio-blk-pci", "drive": "node0", "id": "disk0"}},
		{"block_resize", func() error { return m.BlockResize(ctx, "node0", "", 2048) },
			map[string]interface{}{"node-name": "node0", "size": float64(2048)}},
		{"block_resize", func() error { return m.BlockResize(ctx, "", "drive0", 4096) },
			map[string]interface{}{"device": "drive0", "size": float64(4096)}},
	}
	for _, tt := range tests {
		t.Run(tt.execute, func(t *testing.T) {
			require.NoError(t, tt.call())
			req := srv.last(t)
			assert.Equal(t, tt.execute, req.Execute)
			if tt.args != nil {
				assert.Equal(t, tt.args, req.Arguments)
			}
		})
	}

	t.Run("blockdev-add", func(t *testing.T) {
		require.NoError(t, m.BlockdevAddQcow2(ctx, "node0", "/images/a.qcow2"))
		req := srv.last(t)
		assert.Equal(t, "blockdev-add", req.Execute)
		assert.Equal(t, "qcow2", req.Arguments["driver"])
		assert.Equal(t, map[string]interface{}{"driver": "file", "filename": "/images/a.qcow2"}, req.Arguments["file"])
	})
}

func TestMonitor964_CommandErrorIsTyped(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"stop":         qmpGenericError,
		"query-status": qmpGenericError,
	})

	var target ErrMonitorCommandFailed
	require.True(t, errors.As(m.Pause(context.Background()), &target))
	assert.Equal(t, "stop", target.Command)

	status, err := m.Status(context.Background())
	assert.Equal(t, VMStatusUnknown, status)
	assert.True(t, errors.As(err, &target))
}

func TestMonitor964_SubscribeEventsDeliversEvents(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"x-emit": `{"event":"STOP","data":{},"timestamp":{"seconds":1,"microseconds":0}}` + "\n" + `{"return":{}}`,
	})

	var target ErrMonitorCommandFailed
	assert.True(t, errors.As(m.SubscribeEvents(context.Background(), nil), &target))

	got := make(chan qmp.Event, 1)
	require.NoError(t, m.SubscribeEvents(context.Background(), func(e qmp.Event) { got <- e }))

	_, err := m.Run(context.Background(), "x-emit", nil)
	require.NoError(t, err)

	select {
	case e := <-got:
		assert.Equal(t, "STOP", e.Event)
	case <-time.After(5 * time.Second):
		t.Fatal("event was not delivered to the handler")
	}

	m.UnsubscribeEvents()
	assert.Nil(t, m.eventCancel)
	assert.Nil(t, m.eventHandler)
}

func TestMonitor964_CloseStopsEventsAndDisconnects(t *testing.T) {
	srv := newFakeQMP(t, nil)
	m := NewMonitor(srv.path, 2*time.Second, nil)
	require.NoError(t, m.Connect(context.Background()))
	require.NoError(t, m.SubscribeEvents(context.Background(), func(qmp.Event) {}))

	require.NoError(t, m.Close())
	assert.False(t, m.IsConnected())
	assert.Nil(t, m.eventCancel)
	assert.Nil(t, m.monitor)

	var notConnected ErrMonitorNotConnected
	_, err := m.Run(context.Background(), "stop", nil)
	assert.True(t, errors.As(err, &notConnected))
}

func TestSnapshotManager964_CommandsAgainstMonitor(t *testing.T) {
	m, srv := connectFakeMonitor(t, map[string]string{
		"human-monitor-command": `{"return":""}`,
	})
	sm, err := NewSnapshotManager(m, nil)
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name    string
		call    func() error
		cmdLine string
	}{
		{"create", func() error { return sm.Create(ctx, "snap1") }, "savevm snap1"},
		{"restore", func() error { return sm.Restore(ctx, "snap1") }, "loadvm snap1"},
		{"delete", func() error { return sm.Delete(ctx, "snap1") }, "delvm snap1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, tt.call())
			req := srv.last(t)
			assert.Equal(t, "human-monitor-command", req.Execute)
			assert.Equal(t, tt.cmdLine, req.Arguments["command-line"])
		})
	}
}

func TestSnapshotManager964_HumanMonitorErrors(t *testing.T) {
	tests := []struct {
		name  string
		reply string
		check func(t *testing.T, sm *SnapshotManager)
	}{
		{"create reports failure", `{"return":"Error: savevm failed"}`, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotCreateFailed
			assert.True(t, errors.As(sm.Create(context.Background(), "s1"), &target))
		}},
		{"restore of missing snapshot", `{"return":"Snapshot 's1' not found"}`, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotNotFound
			require.True(t, errors.As(sm.Restore(context.Background(), "s1"), &target))
			assert.Equal(t, "s1", target.Name)
		}},
		{"restore reports failure", `{"return":"Error: cannot load"}`, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotRestoreFailed
			assert.True(t, errors.As(sm.Restore(context.Background(), "s1"), &target))
		}},
		{"delete of missing snapshot", `{"return":"Snapshot 's1' not found"}`, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotNotFound
			assert.True(t, errors.As(sm.Delete(context.Background(), "s1"), &target))
		}},
		{"delete reports failure", `{"return":"Error: delvm failed"}`, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotDeleteFailed
			assert.True(t, errors.As(sm.Delete(context.Background(), "s1"), &target))
		}},
		{"non-string reply", `{"return":{}}`, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotCreateFailed
			require.True(t, errors.As(sm.Create(context.Background(), "s1"), &target))
			var invalid ErrMonitorInvalidResponse
			assert.True(t, errors.As(target.Cause, &invalid))
		}},
		{"list of non-string reply", `{"return":{}}`, func(t *testing.T, sm *SnapshotManager) {
			_, err := sm.List(context.Background())
			var target ErrSnapshotListFailed
			assert.True(t, errors.As(err, &target))
		}},
		{"qmp error on create", qmpGenericError, func(t *testing.T, sm *SnapshotManager) {
			var target ErrSnapshotCreateFailed
			assert.True(t, errors.As(sm.Create(context.Background(), "s1"), &target))
		}},
		{"qmp error on list", qmpGenericError, func(t *testing.T, sm *SnapshotManager) {
			_, err := sm.Get(context.Background(), "s1")
			var target ErrSnapshotListFailed
			assert.True(t, errors.As(err, &target))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := connectFakeMonitor(t, map[string]string{"human-monitor-command": tt.reply})
			sm, err := NewSnapshotManager(m, nil)
			require.NoError(t, err)
			tt.check(t, sm)
		})
	}
}

func TestSnapshotManager964_ListExistsGet(t *testing.T) {
	listing := "List of snapshots present on all disks:\n" +
		"ID        TAG               VM SIZE                DATE       VM CLOCK\n" +
		"1         snap1                256M 2024-01-15 10:30:00   00:05:30.123\n" +
		"2         snap2                512M 2024-01-16 11:00:00   00:10:00.000\n" +
		"garbage\n"
	reply, err := json.Marshal(map[string]string{"return": listing})
	require.NoError(t, err)

	m, _ := connectFakeMonitor(t, map[string]string{"human-monitor-command": string(reply)})
	sm, err := NewSnapshotManager(m, nil)
	require.NoError(t, err)
	ctx := context.Background()

	snaps, err := sm.List(ctx)
	require.NoError(t, err)
	require.Len(t, snaps, 2)
	assert.Equal(t, "1", snaps[0].ID)
	assert.Equal(t, "snap1", snaps[0].Name)
	assert.Equal(t, time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC), snaps[0].Date)
	assert.Equal(t, "snap2", snaps[1].Name)

	exists, err := sm.Exists(ctx, "snap2")
	require.NoError(t, err)
	assert.True(t, exists)
	exists, err = sm.Exists(ctx, "absent")
	require.NoError(t, err)
	assert.False(t, exists)

	snap, err := sm.Get(ctx, "snap1")
	require.NoError(t, err)
	assert.Equal(t, "1", snap.ID)

	var notFound ErrSnapshotNotFound
	_, err = sm.Get(ctx, "absent")
	assert.True(t, errors.As(err, &notFound))
}

func TestSnapshotManager964_ListEmpty(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"human-monitor-command": `{"return":"There is no snapshot available."}`,
	})
	sm, err := NewSnapshotManager(m, nil)
	require.NoError(t, err)

	snaps, err := sm.List(context.Background())
	require.NoError(t, err)
	assert.Empty(t, snaps)
}

func TestMigrationManager964_CommandsAgainstMonitor(t *testing.T) {
	m, srv := connectFakeMonitor(t, nil)
	mm := NewMigrationManager(m, nil)
	ctx := context.Background()

	tests := []struct {
		execute string
		call    func() error
		args    map[string]interface{}
	}{
		{"migrate", func() error { return mm.Migrate(ctx, "tcp:10.0.0.2:4444") }, map[string]interface{}{"uri": "tcp:10.0.0.2:4444"}},
		{"migrate-incoming", func() error { return mm.MigrateIncoming(ctx, "tcp:0.0.0.0:4444") }, map[string]interface{}{"uri": "tcp:0.0.0.0:4444"}},
		{"migrate_cancel", func() error { return mm.Cancel(ctx) }, nil},
		{"migrate-continue", func() error { return mm.ContinueMigration(ctx) }, nil},
		{"migrate-start-postcopy", func() error { return mm.StartPostcopy(ctx) }, nil},
		{"migrate-set-capabilities", func() error { return mm.SetCapabilities(ctx, []string{"xbzrle"}) },
			map[string]interface{}{"capabilities": []interface{}{map[string]interface{}{"capability": "xbzrle", "state": true}}}},
		{"migrate-set-parameters", func() error {
			return mm.SetParameters(ctx, &MigrationParams{MaxBandwidth: 1000, CompressLevel: 3, TLSCreds: "tls0"})
		}, map[string]interface{}{"max-bandwidth": float64(1000), "compress-level": float64(3), "tls-creds": "tls0"}},
	}
	for _, tt := range tests {
		t.Run(tt.execute, func(t *testing.T) {
			require.NoError(t, tt.call())
			req := srv.last(t)
			assert.Equal(t, tt.execute, req.Execute)
			if tt.args != nil {
				assert.Equal(t, tt.args, req.Arguments)
			}
		})
	}
}

func TestMigrationManager964_SetParametersAllFields(t *testing.T) {
	m, srv := connectFakeMonitor(t, nil)
	mm := NewMigrationManager(m, nil)

	params := &MigrationParams{
		MaxBandwidth: 1, DowntimeLimit: 2, CompressLevel: 3, CompressThreads: 4,
		DecompressThreads: 5, CPUThrottleInitial: 6, CPUThrottleIncrement: 7,
		CPUThrottleTailslow: true, TLSCreds: "c", TLSHostname: "h", TLSAuthz: "a",
		MaxPostcopyBandwidth: 8, MultifdChannels: 9, MultifdCompression: "zstd",
		MultifdZlibLevel: 1, MultifdZstdLevel: 2, XBZRLECacheSize: 10,
		BlockIncremental: true, AnnounceInitial: 11, AnnounceMax: 12,
		AnnounceRounds: 13, AnnounceStep: 14,
	}
	require.NoError(t, mm.SetParameters(context.Background(), params))
	assert.Len(t, srv.last(t).Arguments, 22)

	var invalid ErrMigrationParameterInvalid
	err := mm.SetParameters(context.Background(), &MigrationParams{CompressLevel: 10})
	require.True(t, errors.As(err, &invalid))
	assert.Equal(t, "compress-level", invalid.Parameter)
}

func TestMigrationManager964_QueriesParseResponses(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"query-migrate": `{"return":{"status":"active","total-time":100,"expected-downtime":5,` +
			`"ram":{"transferred":10,"remaining":20,"total":30,"mbps":1.5},"disk":{"transferred":1,"remaining":2,"total":3}}}`,
		"query-migrate-parameters":   `{"return":{"max-bandwidth":4096,"tls-creds":"tls0","multifd-channels":2}}`,
		"query-migrate-capabilities": `{"return":[{"capability":"xbzrle","state":true},{"capability":"events","state":false}]}`,
	})
	mm := NewMigrationManager(m, nil)
	ctx := context.Background()

	status, err := mm.Status(ctx)
	require.NoError(t, err)
	assert.Equal(t, MigrationStatusActive, status.Status)
	assert.Equal(t, int64(100), status.TotalTime)
	require.NotNil(t, status.RAM)
	assert.Equal(t, int64(20), status.RAM.Remaining)
	assert.Equal(t, 1.5, status.RAM.Mbps)
	require.NotNil(t, status.Disk)
	assert.Equal(t, int64(3), status.Disk.Total)

	params, err := mm.GetParameters(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4096), params.MaxBandwidth)
	assert.Equal(t, "tls0", params.TLSCreds)
	assert.Equal(t, 2, params.MultifdChannels)

	caps, err := mm.GetCapabilities(ctx)
	require.NoError(t, err)
	assert.Equal(t, []MigrationCapability{{Capability: "xbzrle", State: true}, {Capability: "events", State: false}}, caps)
}

func TestMigrationManager964_ErrorsAreTyped(t *testing.T) {
	commands := []string{
		"migrate", "migrate-incoming", "migrate_cancel", "migrate-continue", "migrate-start-postcopy",
		"migrate-set-capabilities", "migrate-set-parameters",
		"query-migrate", "query-migrate-parameters", "query-migrate-capabilities",
	}
	replies := make(map[string]string, len(commands))
	for _, c := range commands {
		replies[c] = qmpGenericError
	}
	m, _ := connectFakeMonitor(t, replies)
	mm := NewMigrationManager(m, nil)
	ctx := context.Background()

	var failed ErrMigrationFailed
	assert.True(t, errors.As(mm.Migrate(ctx, "unix:/run/m.sock"), &failed))

	var setup ErrMigrationSetupFailed
	assert.True(t, errors.As(mm.MigrateIncoming(ctx, "unix:/run/m.sock"), &setup))
	assert.True(t, errors.As(mm.SetCapabilities(ctx, []string{"events"}), &setup))
	assert.True(t, errors.As(mm.SetParameters(ctx, &MigrationParams{MaxBandwidth: 1}), &setup))

	commandErrs := map[string]func() error{
		"migrate_cancel":             func() error { return mm.Cancel(ctx) },
		"migrate-continue":           func() error { return mm.ContinueMigration(ctx) },
		"migrate-start-postcopy":     func() error { return mm.StartPostcopy(ctx) },
		"query-migrate":              func() error { _, err := mm.Status(ctx); return err },
		"query-migrate-parameters":   func() error { _, err := mm.GetParameters(ctx); return err },
		"query-migrate-capabilities": func() error { _, err := mm.GetCapabilities(ctx); return err },
	}
	for name, call := range commandErrs {
		t.Run(name, func(t *testing.T) {
			var target ErrMonitorCommandFailed
			require.True(t, errors.As(call(), &target))
			assert.Equal(t, name, target.Command)
		})
	}
}

func TestMigrationManager964_InvalidResponses(t *testing.T) {
	m, _ := connectFakeMonitor(t, map[string]string{
		"query-migrate":              `{"return":[]}`,
		"query-migrate-parameters":   `{"return":[]}`,
		"query-migrate-capabilities": `{"return":{}}`,
	})
	mm := NewMigrationManager(m, nil)
	ctx := context.Background()

	calls := map[string]func() error{
		"query-migrate":              func() error { _, err := mm.Status(ctx); return err },
		"query-migrate-parameters":   func() error { _, err := mm.GetParameters(ctx); return err },
		"query-migrate-capabilities": func() error { _, err := mm.GetCapabilities(ctx); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			var target ErrMonitorInvalidResponse
			require.True(t, errors.As(call(), &target))
			assert.Equal(t, name, target.Command)
		})
	}
}

// runningVM returns a VM marked running whose QMP socket is the fake server.
func runningVM(t *testing.T, srv *fakeQMP) *VM {
	t.Helper()
	vm := &VM{config: &Config{QMPSocketPath: srv.path}, logger: logging.DefaultLogger()}
	vm.running.Store(true)
	return vm
}

func TestVM964_MonitorLifecycle(t *testing.T) {
	srv := newFakeQMP(t, map[string]string{
		"query-status": `{"return":{"running":true,"singlestep":false,"status":"running"}}`,
	})
	vm := runningVM(t, srv)
	ctx := context.Background()

	assert.Nil(t, vm.Monitor())
	require.NoError(t, vm.ConnectMonitor(ctx))
	require.NotNil(t, vm.Monitor())
	assert.True(t, vm.Monitor().IsConnected())

	var already ErrMonitorAlreadyConnected
	assert.True(t, errors.As(vm.ConnectMonitor(ctx), &already))

	status, err := vm.VMStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, VMStatusRunning, status)

	operations := []struct {
		execute string
		call    func() error
	}{
		{"stop", func() error { return vm.Pause(ctx) }},
		{"cont", func() error { return vm.Resume(ctx) }},
		{"system_reset", func() error { return vm.Reset(ctx) }},
	}
	for _, op := range operations {
		require.NoError(t, op.call())
		assert.Equal(t, op.execute, srv.last(t).Execute)
	}

	require.NoError(t, vm.DisconnectMonitor())
	assert.Nil(t, vm.Monitor())
	require.NoError(t, vm.DisconnectMonitor())
}

func TestVM964_MonitorOperationGuards(t *testing.T) {
	ctx := context.Background()
	srv := newFakeQMP(t, nil)

	stopped := &VM{config: &Config{QMPSocketPath: srv.path}, logger: logging.DefaultLogger()}
	notConnected := runningVM(t, srv)

	operations := map[string]func(vm *VM) error{
		"pause":   func(vm *VM) error { return vm.Pause(ctx) },
		"resume":  func(vm *VM) error { return vm.Resume(ctx) },
		"reset":   func(vm *VM) error { return vm.Reset(ctx) },
		"status":  func(vm *VM) error { _, err := vm.VMStatus(ctx); return err },
		"connect": func(vm *VM) error { return vm.ConnectMonitor(ctx) },
	}
	for name, op := range operations {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, op(stopped), ErrVMNotRunning)
			if name != "connect" {
				var target ErrMonitorNotConnected
				assert.True(t, errors.As(op(notConnected), &target))
			}
		})
	}
}

func TestVM964_ConnectMonitorSocketMissing(t *testing.T) {
	vm := &VM{
		config: &Config{QMPSocketPath: filepath.Join(t.TempDir(), "absent.sock")},
		logger: logging.DefaultLogger(),
	}
	vm.running.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var target ErrMonitorSocketNotFound
	assert.True(t, errors.As(vm.ConnectMonitor(ctx), &target))
	assert.Nil(t, vm.Monitor())
}

// startChild starts a long-lived child process standing in for QEMU and
// returns it with a reap function that waits for it exactly once.
func startChild(t *testing.T) (*exec.Cmd, func()) {
	t.Helper()
	sleepPath, err := exec.LookPath("sleep")
	require.NoError(t, err)
	cmd := exec.Command(sleepPath, "60")
	require.NoError(t, cmd.Start())

	var once sync.Once
	reap := func() { once.Do(func() { _ = cmd.Wait() }) }
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		reap()
	})
	return cmd, reap
}

// childVM returns a running VM whose process is a real child process.
func childVM(t *testing.T, qmpPath string) (*VM, *exec.Cmd, func()) {
	t.Helper()
	cmd, reap := startChild(t)
	vm := &VM{config: &Config{QMPSocketPath: qmpPath}, logger: logging.DefaultLogger(), cmd: cmd}
	vm.running.Store(true)
	return vm, cmd, reap
}

// exited reports whether the child terminated (signalled or exited).
func exited(t *testing.T, cmd *exec.Cmd, reap func()) bool {
	t.Helper()
	reap()
	return cmd.ProcessState != nil && !cmd.ProcessState.Success()
}

func TestVM964_StopWithTimeoutGracefulViaQMP(t *testing.T) {
	srv := newFakeQMP(t, nil)
	vm, cmd, reap := childVM(t, srv.path)
	// The fake QEMU exits when it receives the ACPI power button event.
	srv.setOnCommand(func(execute string) {
		if execute == "system_powerdown" {
			_ = cmd.Process.Kill()
			reap()
		}
	})
	require.NoError(t, vm.ConnectMonitor(context.Background()))
	assert.Equal(t, cmd.Process.Pid, vm.GetPID())

	require.NoError(t, vm.StopWithTimeout(5*time.Second))
	assert.False(t, vm.IsRunning())
	assert.Nil(t, vm.Monitor())
	assert.Equal(t, "system_powerdown", srv.last(t).Execute)
}

func TestVM964_StopWithTimeoutFallsBackToSIGTERM(t *testing.T) {
	tests := []struct {
		name    string
		replies map[string]string
	}{
		{"guest ignores powerdown", nil},
		{"powerdown rejected", map[string]string{"system_powerdown": qmpGenericError}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newFakeQMP(t, tt.replies)
			vm, cmd, reap := childVM(t, srv.path)
			require.NoError(t, vm.ConnectMonitor(context.Background()))

			require.NoError(t, vm.StopWithTimeout(200*time.Millisecond))
			assert.False(t, vm.IsRunning())
			assert.Nil(t, vm.Monitor())
			require.True(t, exited(t, cmd, reap))
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			require.True(t, ok)
			assert.Equal(t, syscall.SIGTERM, status.Signal())
		})
	}
}

func TestVM964_StopWithoutMonitorSendsSIGTERM(t *testing.T) {
	vm, cmd, reap := childVM(t, "")

	require.NoError(t, vm.StopWithTimeout(time.Second))
	assert.False(t, vm.IsRunning())
	assert.True(t, exited(t, cmd, reap))
}

func TestVM964_StopAndForceStopWithoutProcess(t *testing.T) {
	stops := map[string]func(vm *VM) error{
		"stop":       func(vm *VM) error { return vm.StopWithTimeout(time.Second) },
		"force stop": func(vm *VM) error { return vm.ForceStop() },
	}
	for name, stop := range stops {
		t.Run(name, func(t *testing.T) {
			vm := &VM{config: &Config{}, logger: logging.DefaultLogger()}
			assert.ErrorIs(t, stop(vm), ErrVMNotRunning)

			// Marked running but no process: the flag is corrected.
			vm.running.Store(true)
			assert.ErrorIs(t, stop(vm), ErrVMNotRunning)
			assert.False(t, vm.IsRunning())
		})
	}
}

func TestVM964_ForceStopKillsProcessAndClosesMonitor(t *testing.T) {
	srv := newFakeQMP(t, nil)
	vm, cmd, reap := childVM(t, srv.path)
	require.NoError(t, vm.ConnectMonitor(context.Background()))

	require.NoError(t, vm.ForceStop())
	assert.False(t, vm.IsRunning())
	assert.Nil(t, vm.Monitor())
	require.True(t, exited(t, cmd, reap))
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	assert.Equal(t, syscall.SIGKILL, status.Signal())
}

func TestVM964_NetworkArgs(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   []string
	}{
		{"none", &Config{NetworkMode: "none"}, nil},
		{"tap", &Config{NetworkMode: "user", TapDevice: "tap0"}, []string{
			"-netdev", "tap,id=net0,ifname=tap0,script=no,downscript=no,vnet_hdr=on",
			"-device", "virtio-net-pci,netdev=net0,csum=off,guest_csum=off",
		}},
		{"tap with mac", &Config{TapDevice: "tap1", MACAddress: "52:54:00:00:00:01"}, []string{
			"-netdev", "tap,id=net0,ifname=tap1,script=no,downscript=no,vnet_hdr=on",
			"-device", "virtio-net-pci,netdev=net0,mac=52:54:00:00:00:01,csum=off,guest_csum=off",
		}},
		{"user with port forwards", &Config{NetworkMode: "user", PortForwards: []PortForward{
			{HostPort: 2222, GuestPort: 22},
			{HostPort: 5353, GuestPort: 53, Protocol: "udp"},
		}}, []string{
			"-netdev", "user,id=net0,hostfwd=tcp::2222-:22,hostfwd=udp::5353-:53",
			"-device", "virtio-net-pci,netdev=net0",
		}},
		{"missing bridge falls back to user", &Config{NetworkMode: "bridge", BridgeName: "nobr964x"}, []string{
			"-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0",
		}},
		{"custom mode", &Config{NetworkMode: "socket"}, []string{
			"-netdev", "socket,id=net0", "-device", "virtio-net-pci,netdev=net0",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm := &VM{config: tt.config, logger: logging.DefaultLogger()}
			assert.Equal(t, tt.want, vm.networkArgs())
		})
	}
}

// fakeQEMUConfig returns a boot-ready config whose QEMU binary is script.
func fakeQEMUConfig(t *testing.T, script string) *Config {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{"OVMF_CODE.fd": "mock", "OVMF_VARS.fd": "mock", "test.qcow2": "mock"}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	binary := filepath.Join(dir, "qemu-system-x86_64")
	require.NoError(t, os.WriteFile(binary, []byte(script), 0o755))
	return &Config{
		DiskPath:    filepath.Join(dir, "test.qcow2"),
		Memory:      1024,
		CPUs:        1,
		DiskSize:    "1G",
		WorkDir:     dir,
		OVMFCode:    filepath.Join(dir, "OVMF_CODE.fd"),
		OVMFVars:    filepath.Join(dir, "OVMF_VARS.fd"),
		QEMUBinary:  binary,
		NetworkMode: "none",
	}
}

func TestVM964_StartCapturesOutputWithSerialLogFile(t *testing.T) {
	config := fakeQEMUConfig(t, "#!/bin/sh\necho qemu-says-hello\nexit 0\n")
	config.SerialLogFile = filepath.Join(config.WorkDir, "serial.log")
	vm, err := NewVM(config, nil)
	require.NoError(t, err)

	require.NoError(t, vm.Start(context.Background(), string(BootModeBoot)))
	assert.ErrorIs(t, vm.Start(context.Background(), string(BootModeBoot)), ErrVMAlreadyRunning)
	require.NoError(t, vm.Wait())
	assert.Contains(t, vm.stdoutBuf.String(), "qemu-says-hello")
}

func TestVM964_StartFailures(t *testing.T) {
	t.Run("invalid mode", func(t *testing.T) {
		vm, err := NewVM(fakeQEMUConfig(t, "#!/bin/sh\n"), nil)
		require.NoError(t, err)
		assert.ErrorIs(t, vm.Start(context.Background(), "teleport"), ErrInvalidMode)
	})

	t.Run("binary cannot be executed", func(t *testing.T) {
		config := fakeQEMUConfig(t, "#!/bin/sh\n")
		require.NoError(t, os.Chmod(config.QEMUBinary, 0o644))
		vm, err := NewVM(config, nil)
		require.NoError(t, err)

		assert.ErrorIs(t, vm.Start(context.Background(), string(BootModeBoot)), ErrQEMUFailed)
		assert.False(t, vm.IsRunning())
		assert.Empty(t, vm.runtimeDir)
	})
}

func TestVM964_StartIncomingDefersTheStream(t *testing.T) {
	tests := []struct {
		name      string
		tlsDir    string
		wantCreds string
	}{
		{"plain", "", ""},
		{"tls", "/etc/pki/migration", migrationTLSCredsObjectID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := filepath.Join(t.TempDir(), "args")
			config := fakeQEMUConfig(t, "#!/bin/sh\necho \"$@\" > "+argsFile+"\n")
			vm, err := NewVM(config, nil)
			require.NoError(t, err)

			credsID, err := vm.StartIncoming(context.Background(), tt.tlsDir)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCreds, credsID)
			assert.True(t, vm.IsRunning())

			_, err = vm.StartIncoming(context.Background(), tt.tlsDir)
			assert.ErrorIs(t, err, ErrVMAlreadyRunning)

			require.NoError(t, vm.Wait())
			args, err := os.ReadFile(argsFile)
			require.NoError(t, err)
			assert.Contains(t, string(args), "-incoming defer")
			if tt.tlsDir != "" {
				assert.Contains(t, string(args), "tls-creds-x509,id="+migrationTLSCredsObjectID+",endpoint=server,dir="+tt.tlsDir)
			} else {
				assert.NotContains(t, string(args), "tls-creds-x509")
			}
		})
	}
}

func TestVM964_StartIncomingErrors(t *testing.T) {
	t.Run("disk missing", func(t *testing.T) {
		config := fakeQEMUConfig(t, "#!/bin/sh\n")
		require.NoError(t, os.Remove(config.DiskPath))
		vm, err := NewVM(config, nil)
		require.NoError(t, err)

		_, err = vm.StartIncoming(context.Background(), "")
		assert.ErrorIs(t, err, ErrDiskNotFound)
	})

	t.Run("binary cannot be executed", func(t *testing.T) {
		config := fakeQEMUConfig(t, "#!/bin/sh\n")
		require.NoError(t, os.Chmod(config.QEMUBinary, 0o644))
		vm, err := NewVM(config, nil)
		require.NoError(t, err)

		_, err = vm.StartIncoming(context.Background(), "")
		assert.ErrorIs(t, err, ErrQEMUFailed)
		assert.False(t, vm.IsRunning())
	})
}

// ovsNetwork964 builds an OVSNetwork against a socket path that exists but
// is never dialed: NewOVSNetwork only checks the path before building the
// client, so no OVSDB server is needed.
func ovsNetwork964(t *testing.T) *OVSNetwork {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "db.sock")
	require.NoError(t, os.WriteFile(socketPath, nil, 0600))

	n, err := NewOVSNetwork(&Config{OVS: &OVSConfig{Enable: true, SocketPath: socketPath, BridgeName: "br964"}}, nil)
	require.NoError(t, err)
	require.NotNil(t, n)
	return n
}

func TestOVSNetwork964_NewBuildsClientAndCloses(t *testing.T) {
	n := ovsNetwork964(t)
	assert.NotNil(t, n.ovsClient)
	assert.NotNil(t, n.nlManager)
	assert.NotNil(t, n.logger)
	assert.Empty(t, n.GetTAPName())
	assert.NoError(t, n.Close())
}

func TestOVSNetwork964_CleanupReportsFailuresAndForgetsTAP(t *testing.T) {
	// The netlink seam stands in for the kernel, so no host interface is
	// looked up or deleted whatever name the TAP carries.
	ops := &netlinkOps964{}
	netlink.SetNetlinkOps(ops)
	t.Cleanup(netlink.ResetNetlinkOps)

	n := ovsNetwork964(t)
	n.tapName = "tap964"

	// The OVS client is not connected, so the port removal fails too; the
	// TAP deletion runs last and is the error Cleanup reports.
	err := n.Cleanup(context.Background())
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, "failed to delete TAP device", wrapped.Msg)
	var nlErr *netlink.NetlinkError
	require.ErrorAs(t, err, &nlErr)
	assert.Equal(t, netlink.ErrorTypeDeleteFailed, nlErr.Type)
	var delErr *linkDelError964
	require.ErrorAs(t, err, &delErr, "Cleanup must report the seam's deletion error")
	assert.Equal(t, "tap964", delErr.name)
	assert.Equal(t, []string{"tap964"}, ops.deleted, "Cleanup deletes the TAP through the seam")

	assert.Empty(t, n.GetTAPName(), "Cleanup must forget the TAP even when removal fails")
	assert.NoError(t, n.Cleanup(context.Background()), "a second Cleanup has nothing to remove")
	assert.Len(t, ops.deleted, 1, "a second Cleanup must not delete again")
}

// linkDelError964 is the controlled deletion failure netlinkOps964 returns.
type linkDelError964 struct{ name string }

func (e *linkDelError964) Error() string { return "link delete refused: " + e.name }

// unexpectedNetlinkCall964 reports a seam operation the test did not expect.
type unexpectedNetlinkCall964 struct{ op string }

func (e *unexpectedNetlinkCall964) Error() string { return "unexpected netlink call: " + e.op }

// netlinkOps964 is a NetlinkOps fake: every link exists as a TAP, every
// deletion is refused, and no call reaches the host kernel.
type netlinkOps964 struct {
	deleted []string
}

func (o *netlinkOps964) LinkByName(name string) (vnl.Link, error) {
	return &vnl.Tuntap{LinkAttrs: vnl.LinkAttrs{Name: name}, Mode: vnl.TUNTAP_MODE_TAP}, nil
}

func (o *netlinkOps964) LinkDel(link vnl.Link) error {
	name := link.Attrs().Name
	o.deleted = append(o.deleted, name)
	return &linkDelError964{name: name}
}

func (o *netlinkOps964) LinkAdd(vnl.Link) error {
	return &unexpectedNetlinkCall964{op: "LinkAdd"}
}

func (o *netlinkOps964) LinkSetUp(vnl.Link) error {
	return &unexpectedNetlinkCall964{op: "LinkSetUp"}
}

func (o *netlinkOps964) LinkSetDown(vnl.Link) error {
	return &unexpectedNetlinkCall964{op: "LinkSetDown"}
}

func (o *netlinkOps964) LinkSetMTU(vnl.Link, int) error {
	return &unexpectedNetlinkCall964{op: "LinkSetMTU"}
}

func (o *netlinkOps964) LinkList() ([]vnl.Link, error) {
	return nil, &unexpectedNetlinkCall964{op: "LinkList"}
}

func TestOVSNetwork964_OwnershipIsCurrentUser(t *testing.T) {
	n := ovsNetwork964(t)
	uid, gid := n.getOwnership()
	assert.Equal(t, uint32(os.Getuid()), uid)
	assert.Equal(t, uint32(os.Getgid()), gid)
}

func TestVM964_NetworkArgsOVSWithoutTAPFallsBack(t *testing.T) {
	vm := &VM{logger: logging.DefaultLogger(), config: &Config{
		NetworkMode: "user",
		OVS:         &OVSConfig{Enable: true},
	}}
	assert.Equal(t, []string{"-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0"}, vm.networkArgs())
}

func TestSecureBootEnroller964_ReenrollsAfterKeyRotation(t *testing.T) {
	_, config, cleanup := setupTestEnv(t)
	defer cleanup()

	enroller, err := NewSecureBootEnroller(config, logging.DefaultLogger())
	require.NoError(t, err)
	require.NoError(t, enroller.EnrollKeys(context.Background()))
	require.True(t, enroller.IsEnrolled())

	nvramPath := filepath.Join(config.NVRAMDir, "OVMF_VARS.fd")
	flagPath := filepath.Join(config.NVRAMDir, "OVMF_VARS_ENROLLED.flag")
	oldKeys := secureBootKeys964(t, config.KeysDir)
	assert.Equal(t, oldKeys, enrolledKeys964(t, nvramPath), "the first enrollment holds the original keys")

	// Controlled timestamps, all in the past: the first enrollment is dated
	// enrolledAt and the rotated keys rotatedAt, an hour later.
	enrolledAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	rotatedAt := enrolledAt.Add(time.Hour)
	require.NoError(t, os.Chtimes(flagPath, enrolledAt, enrolledAt))
	for _, key := range secureBootKeyFiles964 {
		path := filepath.Join(config.KeysDir, key.file)
		require.NoError(t, os.WriteFile(path, generateTestCertificate(t, "Rotated "+key.variable), 0644))
		require.NoError(t, os.Chtimes(path, rotatedAt, rotatedAt))
	}
	newKeys := secureBootKeys964(t, config.KeysDir)
	require.False(t, enroller.IsEnrolled(), "rotated keys are newer than the enrollment flag")

	require.NoError(t, enroller.EnrollKeys(context.Background()))
	enrolled := enrolledKeys964(t, nvramPath)
	assert.Equal(t, newKeys, enrolled, "re-enrollment writes the rotated keys into NVRAM")
	for variable, cert := range oldKeys {
		assert.NotEqual(t, cert, enrolled[variable], "%s still holds the pre-rotation key", variable)
	}

	flag, err := os.Stat(flagPath)
	require.NoError(t, err)
	assert.True(t, flag.ModTime().After(rotatedAt), "re-enrollment writes a flag newer than the rotated keys")
	assert.True(t, enroller.IsEnrolled(), "the rotated keys are enrolled")
}

// secureBootKeyFiles964 maps each Secure Boot key file to the NVRAM variable
// it is enrolled into.
var secureBootKeyFiles964 = []struct {
	file     string
	variable string
	guid     uefi.GUID
}{
	{"PK.crt", "PK", uefi.EFIGlobalVariable},
	{"KEK.crt", "KEK", uefi.EFIGlobalVariable},
	{"DB.crt", "db", uefi.EFIImageSecurityDatabase},
}

// secureBootKeys964 returns the DER certificate of each key file, keyed by
// the NVRAM variable it is enrolled into.
func secureBootKeys964(t *testing.T, keysDir string) map[string][]byte {
	t.Helper()
	keys := make(map[string][]byte, len(secureBootKeyFiles964))
	for _, key := range secureBootKeyFiles964 {
		data, err := os.ReadFile(filepath.Join(keysDir, key.file))
		require.NoError(t, err)
		block, _ := pem.Decode(data)
		require.NotNil(t, block, "%s is not PEM", key.file)
		keys[key.variable] = block.Bytes
	}
	return keys
}

// enrolledKeys964 reads the certificate each Secure Boot variable holds in
// the NVRAM file, keyed by variable name.
func enrolledKeys964(t *testing.T, nvramPath string) map[string][]byte {
	t.Helper()
	nvram, err := uefi.OpenNVRAM(nvramPath)
	require.NoError(t, err)
	keys := make(map[string][]byte, len(secureBootKeyFiles964))
	for _, key := range secureBootKeyFiles964 {
		variable, err := nvram.GetVariable(key.variable, key.guid)
		require.NoError(t, err, key.variable)
		lists, err := uefi.ParseSignatureLists(variable.Data)
		require.NoError(t, err, key.variable)
		require.Len(t, lists, 1, key.variable)
		require.Len(t, lists[0].Signatures, 1, key.variable)
		keys[key.variable] = lists[0].Signatures[0].Data
	}
	return keys
}

func TestSecureBootEnroller964_NVRAMFailures(t *testing.T) {
	t.Run("template missing", func(t *testing.T) {
		_, config, cleanup := setupTestEnvWithMockCerts(t)
		defer cleanup()
		enroller, err := NewSecureBootEnroller(config, logging.DefaultLogger())
		require.NoError(t, err)
		require.NoError(t, os.Remove(config.OVMFVarsPath))

		var wrapped *WrappedError
		require.ErrorAs(t, enroller.InitializeNVRAM("OVMF_VARS.fd"), &wrapped)
		assert.Equal(t, "failed to copy OVMF VARS template", wrapped.Msg)

		require.ErrorAs(t, enroller.EnrollKeys(context.Background()), &wrapped)
		assert.Equal(t, "failed to initialize NVRAM", wrapped.Msg)
	})

	t.Run("NVRAM directory is a file", func(t *testing.T) {
		_, config, cleanup := setupTestEnvWithMockCerts(t)
		defer cleanup()
		enroller, err := NewSecureBootEnroller(config, logging.DefaultLogger())
		require.NoError(t, err)
		require.NoError(t, os.RemoveAll(config.NVRAMDir))
		require.NoError(t, os.WriteFile(config.NVRAMDir, nil, 0600))

		var wrapped *WrappedError
		require.ErrorAs(t, enroller.InitializeNVRAM("OVMF_VARS.fd"), &wrapped)
		assert.Equal(t, "failed to create NVRAM directory", wrapped.Msg)

		require.ErrorAs(t, enroller.EnrollKeys(context.Background()), &wrapped)
		assert.Equal(t, "failed to create NVRAM directory", wrapped.Msg)
	})
}
