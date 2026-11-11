package switchmgmt

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// fakeSession is an in-memory session.Session that records the command it
// ran and returns canned output.
type fakeSession struct {
	ranCommand string
	stdout     []byte
	stderr     []byte
	runErr     error
	closeErr   error
	closed     bool
}

func (f *fakeSession) Run(_ context.Context, cmd string) ([]byte, []byte, error) {
	f.ranCommand = cmd
	return f.stdout, f.stderr, f.runErr
}

func (f *fakeSession) Shell(context.Context) error { return nil }

func (f *fakeSession) Upload(context.Context, io.Reader, string, fs.FileMode) error { return nil }

func (f *fakeSession) Close() error {
	f.closed = true
	return f.closeErr
}

// closeErrExecutor is an SSHExecutor whose Close fails with closeErr.
type closeErrExecutor struct {
	closeErr error
	closed   bool
}

func (c *closeErrExecutor) Execute(context.Context, string) (string, error) { return "", nil }

func (c *closeErrExecutor) Close() error {
	c.closed = true
	return c.closeErr
}

var errFakeRemote = errors.New("fake remote failure")

func TestSSHExecutor_Execute(t *testing.T) {
	tests := []struct {
		name       string
		session    *fakeSession
		wantOutput string
		wantErr    bool
	}{
		{
			name:       "returns stdout on success",
			session:    &fakeSession{stdout: []byte("Vlan10 up\n")},
			wantOutput: "Vlan10 up\n",
		},
		{
			name:    "wraps a run failure with the command and stderr",
			session: &fakeSession{stderr: []byte("% Invalid command"), runErr: errFakeRemote},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &sshExecutor{sess: tt.session}
			out, err := exec.Execute(context.Background(), "show vlan brief")
			if tt.session.ranCommand != "show vlan brief" {
				t.Fatalf("session ran %q, want %q", tt.session.ranCommand, "show vlan brief")
			}
			if out != tt.wantOutput {
				t.Fatalf("output = %q, want %q", out, tt.wantOutput)
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var cmdErr ErrCommandFailed
			if !errors.As(err, &cmdErr) {
				t.Fatalf("expected ErrCommandFailed, got %T %v", err, err)
			}
			if cmdErr.Command != "show vlan brief" || cmdErr.Output != "% Invalid command" {
				t.Fatalf("ErrCommandFailed = %+v, want command and stderr carried", cmdErr)
			}
			if !errors.Is(cmdErr.Cause, errFakeRemote) {
				t.Fatalf("cause = %v, want %v", cmdErr.Cause, errFakeRemote)
			}
		})
	}
}

func TestSSHExecutor_Close(t *testing.T) {
	t.Run("closes the session and returns its error", func(t *testing.T) {
		sess := &fakeSession{closeErr: errFakeRemote}
		exec := &sshExecutor{sess: sess}
		if err := exec.Close(); !errors.Is(err, errFakeRemote) {
			t.Fatalf("Close() = %v, want %v", err, errFakeRemote)
		}
		if !sess.closed {
			t.Fatal("expected the session to be closed")
		}
	})
	t.Run("nil session is a no-op", func(t *testing.T) {
		exec := &sshExecutor{}
		if err := exec.Close(); err != nil {
			t.Fatalf("Close() on nil session = %v, want nil", err)
		}
	})
}

func TestHostKeyOwner(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{name: "prefers the switch name", config: &Config{Name: "tor-1", Host: "10.0.0.1"}, want: "tor-1"},
		{name: "falls back to the host", config: &Config{Host: "10.0.0.1"}, want: "10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostKeyOwner(tt.config); got != tt.want {
				t.Fatalf("hostKeyOwner() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewKnownHostsStore(t *testing.T) {
	t.Run("opens a store in the known_hosts directory", func(t *testing.T) {
		store, err := newKnownHostsStore(filepath.Join(t.TempDir(), "known_hosts"))
		if err != nil {
			t.Fatalf("newKnownHostsStore() error = %v", err)
		}
		if store == nil {
			t.Fatal("expected a non-nil store")
		}
	})
	t.Run("fails when the parent is a regular file", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatalf("write parent file: %v", err)
		}
		store, err := newKnownHostsStore(filepath.Join(parent, "known_hosts"))
		if err == nil {
			t.Fatal("expected an error for a parent that is not a directory")
		}
		if store != nil {
			t.Fatal("expected a nil store on error")
		}
	})
}

func TestNewSSHExecutor_KnownHostsStoreFailure(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	config := &Config{
		Host:           "10.0.0.1",
		Port:           22,
		User:           "admin",
		SSHKey:         writeTestSSHKey(t),
		KnownHostsPath: filepath.Join(parent, "known_hosts"),
	}
	executor, err := NewSSHExecutor(context.Background(), config)
	if executor != nil {
		t.Fatal("expected nil executor when the known-hosts store cannot open")
	}
	var connErr ErrSSHConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("expected ErrSSHConnectionFailed, got %T %v", err, err)
	}
	if connErr.Host != "10.0.0.1" {
		t.Fatalf("host = %q, want 10.0.0.1", connErr.Host)
	}
}

func TestNewSSHExecutor_DialFailure(t *testing.T) {
	// A cancelled context makes the dial fail before any packet is sent.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	config := &Config{
		Name:           "tor-1",
		Host:           "127.0.0.1",
		Port:           1,
		User:           "admin",
		SSHKey:         writeTestSSHKey(t),
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
	}
	executor, err := NewSSHExecutor(ctx, config)
	if executor != nil {
		t.Fatal("expected nil executor when the dial fails")
	}
	var connErr ErrSSHConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("expected ErrSSHConnectionFailed, got %T %v", err, err)
	}
	if connErr.Cause == nil {
		t.Fatal("expected the dial error as the cause")
	}
}

// unconnectableConfig has no SSH key, so NewSSHExecutor rejects it before
// any connection is attempted.
func unconnectableConfig() *Config {
	return &Config{Host: "10.0.0.1", Port: 22, User: "admin"}
}

func TestEnsureConnected(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	tests := []struct {
		name    string
		connect func(existing SSHExecutor) (SSHExecutor, error)
	}{
		{
			name: "sshManager",
			connect: func(existing SSHExecutor) (SSHExecutor, error) {
				m := &sshManager{config: unconnectableConfig(), logger: logger, executor: existing}
				err := m.ensureConnected(context.Background())
				return m.executor, err
			},
		},
		{
			name: "ciscoNexusConfigurator",
			connect: func(existing SSHExecutor) (SSHExecutor, error) {
				c := &ciscoNexusConfigurator{config: unconnectableConfig(), logger: logger, executor: existing}
				err := c.ensureConnected(context.Background())
				return c.executor, err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/keeps an existing executor", func(t *testing.T) {
			existing := &closeErrExecutor{}
			got, err := tt.connect(existing)
			if err != nil {
				t.Fatalf("ensureConnected() error = %v", err)
			}
			if got != existing {
				t.Fatal("expected the existing executor to be kept")
			}
		})
		t.Run(tt.name+"/propagates the connection error", func(t *testing.T) {
			got, err := tt.connect(nil)
			var connErr ErrSSHConnectionFailed
			if !errors.As(err, &connErr) {
				t.Fatalf("expected ErrSSHConnectionFailed, got %T %v", err, err)
			}
			if got != nil {
				t.Fatal("expected no executor to be stored on failure")
			}
		})
	}
}

func TestService_Close(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	t.Run("returns the close error of a failing manager", func(t *testing.T) {
		failing := &closeErrExecutor{closeErr: errFakeRemote}
		healthy := &closeErrExecutor{}
		svc := &Service{
			managers: map[string]Manager{
				"bad":  &sshManager{executor: failing},
				"good": &sshManager{executor: healthy},
			},
			logger: logger,
		}
		if err := svc.Close(); !errors.Is(err, errFakeRemote) {
			t.Fatalf("Close() = %v, want %v", err, errFakeRemote)
		}
		if !failing.closed || !healthy.closed {
			t.Fatal("expected every manager to be closed despite the failure")
		}
	})
	t.Run("returns nil when every manager closes", func(t *testing.T) {
		svc := &Service{
			managers: map[string]Manager{"good": &sshManager{executor: &closeErrExecutor{}}},
			logger:   logger,
		}
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() = %v, want nil", err)
		}
	})
}

func TestExtractColumn(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		start, end int
		want       string
	}{
		{name: "trims a column inside the line", line: "Eth1/1  connected", start: 0, end: 8, want: "Eth1/1"},
		{name: "clamps an end past the line", line: "Eth1/1  connected", start: 8, end: 99, want: "connected"},
		{name: "start past the line is empty", line: "Eth1/1", start: 10, end: 20, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractColumn(tt.line, tt.start, tt.end); got != tt.want {
				t.Fatalf("extractColumn() = %q, want %q", got, tt.want)
			}
		})
	}
}
