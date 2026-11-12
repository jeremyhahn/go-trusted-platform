package process

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// notifyHelperEnv makes the test binary act as a supervised child that sends
// one notify state and exits (TestNotifyHelperChild).
const notifyHelperEnv = "GTP_NOTIFY_HELPER_STATE"

func TestNotifyHelperChild(t *testing.T) {
	state := os.Getenv(notifyHelperEnv)
	if state == "" {
		t.Skip("helper process only")
	}
	if err := Notify(state); err != nil {
		t.Fatalf("Notify: %v", err)
	}
}

func TestParseNotify_Ready(t *testing.T) {
	m, err := ParseNotify([]byte("READY=1"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.Ready || m.Watchdog || m.Stopping || m.HasStatus || m.HasErrno {
		t.Fatalf("got %+v, want only Ready", m)
	}
}

func TestParseNotify_Status(t *testing.T) {
	m, err := ParseNotify([]byte("STATUS=backend started: 3 peers = up\n"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.HasStatus || m.Status != "backend started: 3 peers = up" {
		t.Fatalf("got status %q (has %v)", m.Status, m.HasStatus)
	}
	if m.Ready {
		t.Fatal("Ready set by a STATUS line")
	}
}

func TestParseNotify_EmptyStatus(t *testing.T) {
	m, err := ParseNotify([]byte("STATUS="))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.HasStatus || m.Status != "" {
		t.Fatalf("got status %q (has %v), want empty and present", m.Status, m.HasStatus)
	}
}

func TestParseNotify_Watchdog(t *testing.T) {
	m, err := ParseNotify([]byte("WATCHDOG=1"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.Watchdog || m.Ready {
		t.Fatalf("got %+v, want only Watchdog", m)
	}
}

func TestParseNotify_Stopping(t *testing.T) {
	m, err := ParseNotify([]byte("STOPPING=1"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.Stopping || m.Ready {
		t.Fatalf("got %+v, want only Stopping", m)
	}
}

func TestParseNotify_Errno(t *testing.T) {
	m, err := ParseNotify([]byte("ERRNO=98"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.HasErrno || m.Errno != 98 {
		t.Fatalf("got errno %d (has %v), want 98", m.Errno, m.HasErrno)
	}
}

func TestParseNotify_MultipleLines(t *testing.T) {
	m, err := ParseNotify([]byte("STATUS=serving\nREADY=1\n\nWATCHDOG=1\n"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.Ready || !m.Watchdog || m.Status != "serving" {
		t.Fatalf("got %+v", m)
	}
}

func TestParseNotify_UnknownKeysKept(t *testing.T) {
	m, err := ParseNotify([]byte("READY=1\nMAINPID=42\nX_CUSTOM=a=b"))
	if err != nil {
		t.Fatalf("ParseNotify: %v", err)
	}
	if !m.Ready {
		t.Fatal("Ready lost next to unknown keys")
	}
	if len(m.Unknown) != 2 || m.Unknown[0] != "MAINPID" || m.Unknown[1] != "X_CUSTOM" {
		t.Fatalf("Unknown = %q, want [MAINPID X_CUSTOM]", m.Unknown)
	}
}

func TestParseNotify_Empty(t *testing.T) {
	for _, in := range []string{"", "\n", "\n\n"} {
		_, err := ParseNotify([]byte(in))
		var want *ErrNotifyEmpty
		if !errors.As(err, &want) {
			t.Fatalf("ParseNotify(%q) error = %v, want *ErrNotifyEmpty", in, err)
		}
	}
}

func TestParseNotify_Malformed(t *testing.T) {
	cases := map[string]string{
		"no equals":         "READY",
		"empty key":         "=1",
		"ready not one":     "READY=0",
		"ready trailing":    "READY=1 ",
		"watchdog not one":  "WATCHDOG=yes",
		"stopping not one":  "STOPPING=2",
		"errno not number":  "ERRNO=EADDRINUSE",
		"errno negative":    "ERRNO=-1",
		"errno empty":       "ERRNO=",
		"key with space":    "READY =1",
		"bad line after ok": "READY=1\ngarbage",
		"nul byte":          "STATUS=a\x00b",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseNotify([]byte(in))
			var want *ErrNotifyMalformed
			if !errors.As(err, &want) {
				t.Fatalf("ParseNotify(%q) error = %v, want *ErrNotifyMalformed", in, err)
			}
		})
	}
}

// shortSocketPath returns a socket path short enough for sun_path whatever
// the test's temporary directory is.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ntf")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "n.sock")
}

func TestNotifySocket_RefusesForeignPid(t *testing.T) {
	path := shortSocketPath(t)
	// Expect a pid that is not this process: the datagram this process sends
	// carries its own pid and must be dropped.
	s, err := ListenNotify(path, os.Getpid()+1)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	defer func() { _ = s.Close() }()

	t.Setenv("NOTIFY_SOCKET", path)
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	_, err = s.Receive(time.Now().Add(300 * time.Millisecond))
	if err == nil {
		t.Fatal("Receive accepted a datagram from a foreign pid")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Receive error = %v, want a deadline", err)
	}
	if got := s.Dropped(); got != 1 {
		t.Fatalf("Dropped() = %d, want 1", got)
	}

	// The same sender is accepted once it is the expected pid.
	s.SetPid(os.Getpid())
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("Notify: %v", err)
	}
	m, err := s.Receive(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if !m.Ready {
		t.Fatalf("got %+v, want Ready", m)
	}
}

func TestNotifySocket_AcceptsChildReady(t *testing.T) {
	path := shortSocketPath(t)
	s, err := ListenNotify(path, 0)
	if err != nil {
		t.Fatalf("ListenNotify: %v", err)
	}
	defer func() { _ = s.Close() }()
	if s.Path() != path {
		t.Fatalf("Path() = %q, want %q", s.Path(), path)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestNotifyHelperChild$")
	cmd.Env = append(os.Environ(),
		notifyHelperEnv+"=STATUS=child up\nREADY=1",
		"NOTIFY_SOCKET="+path,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	// The pid is set after Start, as the supervisor does: the kernel stamps
	// the credentials at send time, so a datagram queued earlier still
	// carries the child's pid.
	s.SetPid(cmd.Process.Pid)

	m, err := s.Receive(time.Now().Add(10 * time.Second))
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("Receive: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}
	if !m.Ready || m.Status != "child up" {
		t.Fatalf("got %+v, want Ready with status %q", m, "child up")
	}
	if got := s.Dropped(); got != 0 {
		t.Fatalf("Dropped() = %d, want 0", got)
	}
}

func TestNotifySocket_ListenOnExistingPathFails(t *testing.T) {
	path := shortSocketPath(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := ListenNotify(path, 1)
	var want *ErrNotifySocket
	if !errors.As(err, &want) {
		t.Fatalf("ListenNotify error = %v, want *ErrNotifySocket", err)
	}
}

func TestNotify_NoSocketIsNoop(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := Notify("READY=1"); err != nil {
		t.Fatalf("Notify with no NOTIFY_SOCKET = %v, want nil", err)
	}
}

func TestNotify_MissingSocketFails(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", shortSocketPath(t))
	err := Notify("READY=1")
	var want *ErrNotifySend
	if !errors.As(err, &want) {
		t.Fatalf("Notify error = %v, want *ErrNotifySend", err)
	}
}
