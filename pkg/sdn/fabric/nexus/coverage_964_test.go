package nexus

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fabric"
)

// cov964CommandError mirrors the session contract: Run returns a typed
// error for a command that exits non-zero, alongside its output.
type cov964CommandError struct {
	Command string
}

func (e *cov964CommandError) Error() string { return "command failed: " + e.Command }

// cov964ErrClose is the typed error the fake session returns on Close.
type cov964ErrClose struct{}

func (cov964ErrClose) Error() string { return "close failed" }

// cov964Session is an in-memory session.Session. It records every
// command it runs, answers from a fixed table and fails the commands
// listed in failing with a typed error, as the real session does on a
// non-zero exit.
type cov964Session struct {
	outputs  map[string]string
	failing  map[string]bool
	ran      []string
	closeErr error
	closed   int
	// cancel, when set, is called after the first Run so the next
	// command observes a cancelled context.
	cancel context.CancelFunc
}

func (s *cov964Session) Run(ctx context.Context, cmd string) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	s.ran = append(s.ran, cmd)
	if s.cancel != nil {
		s.cancel()
	}
	if s.failing[cmd] {
		return []byte(s.outputs[cmd]), []byte("stderr: " + cmd), &cov964CommandError{Command: cmd}
	}
	return []byte(s.outputs[cmd]), nil, nil
}

func (s *cov964Session) Shell(context.Context) error { return nil }

func (s *cov964Session) Upload(context.Context, io.Reader, string, fs.FileMode) error {
	return nil
}

func (s *cov964Session) Close() error {
	s.closed++
	return s.closeErr
}

func cov964Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// cov964WriteKey writes a freshly generated OpenSSH ed25519 private key
// into dir and returns its path.
func cov964WriteKey(t *testing.T, dir string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "cov964")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// cov964ClosedPort returns a loopback port nothing listens on.
func cov964ClosedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return port
}

func TestCov964SessionExecutorExecute(t *testing.T) {
	sess := &cov964Session{
		outputs: map[string]string{
			"show vlan id 100":  "100  data  active",
			"show vlan id 4000": "% Invalid",
		},
		failing: map[string]bool{"show vlan id 4000": true},
	}
	exec := &sessionExecutor{sess: sess}

	stdout, stderr, err := exec.Execute(context.Background(), "show vlan id 100")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout != "100  data  active" || stderr != "" {
		t.Errorf("Execute output = (%q, %q)", stdout, stderr)
	}

	stdout, stderr, err = exec.Execute(context.Background(), "show vlan id 4000")
	var cmdErr *cov964CommandError
	if !errors.As(err, &cmdErr) || cmdErr.Command != "show vlan id 4000" {
		t.Fatalf("Execute error = %v, want the session's command error", err)
	}
	if stdout != "% Invalid" || stderr != "stderr: show vlan id 4000" {
		t.Errorf("failed Execute output = (%q, %q)", stdout, stderr)
	}

	want := []string{"show vlan id 100", "show vlan id 4000"}
	if !slices.Equal(sess.ran, want) {
		t.Errorf("commands sent = %q, want %q", sess.ran, want)
	}
}

func TestCov964SessionExecutorExecuteBatch(t *testing.T) {
	commands := []string{"configure terminal", "vlan 200", "name storage", "end"}
	sess := &cov964Session{
		outputs: map[string]string{"vlan 200": "ok"},
		failing: map[string]bool{"name storage": true},
	}
	exec := &sessionExecutor{sess: sess}

	results, err := exec.ExecuteBatch(context.Background(), commands)
	if err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if !slices.Equal(sess.ran, commands) {
		t.Fatalf("commands sent = %q, want %q", sess.ran, commands)
	}
	if len(results) != len(commands) {
		t.Fatalf("got %d results, want %d", len(results), len(commands))
	}
	for i, res := range results {
		if res.Command != commands[i] {
			t.Errorf("result %d command = %q, want %q", i, res.Command, commands[i])
		}
	}
	if results[1].Stdout != "ok" || results[1].Err != nil {
		t.Errorf("vlan result = %+v", results[1])
	}
	// A per-command failure is reported in its Result, not as the
	// batch error, and the batch carries on.
	var cmdErr *cov964CommandError
	if !errors.As(results[2].Err, &cmdErr) || results[2].Stderr != "stderr: name storage" {
		t.Errorf("failing result = %+v", results[2])
	}
	if results[3].Err != nil {
		t.Errorf("command after the failure = %+v", results[3])
	}
}

func TestCov964SessionExecutorExecuteBatchCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &cov964Session{cancel: cancel}
	exec := &sessionExecutor{sess: sess}

	results, err := exec.ExecuteBatch(ctx, []string{"configure terminal", "vlan 300", "end"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ExecuteBatch error = %v, want context.Canceled", err)
	}
	if len(results) != 1 || results[0].Command != "configure terminal" {
		t.Errorf("results = %+v, want only the command run before cancellation", results)
	}
	if !slices.Equal(sess.ran, []string{"configure terminal"}) {
		t.Errorf("commands sent = %q", sess.ran)
	}
}

func TestCov964CloseSession(t *testing.T) {
	tests := []struct {
		name     string
		closeErr error
	}{
		{name: "clean close"},
		{name: "close error surfaces", closeErr: cov964ErrClose{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess := &cov964Session{closeErr: tc.closeErr}
			d := &nexusDriver{logger: cov964Logger(), sshSess: sess}
			d.connected.Store(true)

			if err := d.Close(); !errors.Is(err, tc.closeErr) || (tc.closeErr == nil && err != nil) {
				t.Fatalf("Close = %v, want %v", err, tc.closeErr)
			}
			if sess.closed != 1 {
				t.Errorf("session closed %d times, want 1", sess.closed)
			}
			if d.sshSess != nil || d.connected.Load() {
				t.Error("Close left the session attached or the driver connected")
			}
			// A second Close does not touch the released session.
			if err := d.Close(); err != nil || sess.closed != 1 {
				t.Errorf("second Close = %v, session closed %d times", err, sess.closed)
			}
		})
	}
}

func TestCov964ConnectKeyErrors(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem key"), 0o600); err != nil {
		t.Fatalf("write garbage key: %v", err)
	}
	missing := filepath.Join(dir, "missing.pem")

	tests := []struct {
		name    string
		keyPath string
	}{
		{name: "key file missing", keyPath: missing},
		{name: "key file not PEM", keyPath: garbage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			drv, err := NewDriver(fabric.SwitchConfig{
				ID:             "leaf-1",
				MgmtIP:         "127.0.0.1",
				SSHKeyPath:     tc.keyPath,
				KnownHostsPath: filepath.Join(dir, "known_hosts"),
			}, cov964Logger())
			if err != nil {
				t.Fatalf("NewDriver: %v", err)
			}
			err = drv.Connect(context.Background())
			var keyErr ErrSSHKeyLoad
			if !errors.As(err, &keyErr) || keyErr.Path != tc.keyPath || keyErr.Cause == nil {
				t.Fatalf("Connect = %v, want ErrSSHKeyLoad for %s", err, tc.keyPath)
			}
			if pingErr := drv.Ping(context.Background()); !errors.As(pingErr, new(ErrNotConnected)) {
				t.Errorf("Ping after failed Connect = %v, want ErrNotConnected", pingErr)
			}
		})
	}
}

func TestCov964ConnectDialFailure(t *testing.T) {
	dir := t.TempDir()
	drv, err := NewDriver(fabric.SwitchConfig{
		ID:             "leaf-2",
		MgmtIP:         "127.0.0.1",
		SSHPort:        cov964ClosedPort(t),
		SSHUser:        "admin",
		SSHKeyPath:     cov964WriteKey(t, dir),
		KnownHostsPath: filepath.Join(dir, "pins", "known_hosts"),
	}, cov964Logger())
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = drv.Connect(ctx)
	var execErr ErrCommandExec
	if !errors.As(err, &execErr) || execErr.Command != "connect" || execErr.Cause == nil {
		t.Fatalf("Connect = %v, want ErrCommandExec{Command: connect}", err)
	}
	if pingErr := drv.Ping(ctx); !errors.As(pingErr, new(ErrNotConnected)) {
		t.Errorf("Ping after failed dial = %v, want ErrNotConnected", pingErr)
	}
}

func TestCov964NewKnownHostsStore(t *testing.T) {
	dir := t.TempDir()
	store, err := newKnownHostsStore(filepath.Join(dir, "known_hosts"))
	if err != nil || store == nil {
		t.Fatalf("newKnownHostsStore = (%v, %v), want a store", store, err)
	}

	// The parent of the known_hosts path is a regular file, so no
	// store can be rooted there.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if _, err := newKnownHostsStore(filepath.Join(blocker, "known_hosts")); err == nil {
		t.Error("newKnownHostsStore under a regular file succeeded, want an error")
	}
}
