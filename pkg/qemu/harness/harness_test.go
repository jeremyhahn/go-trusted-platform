package harness

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
)

// fakeTPM records the calls StartTPM makes and answers from its fields.
type fakeTPM struct {
	initialized bool
	socket      string
	stateDir    string
	calls       []string
	initErr     error
	startErr    error
	socketErr   error
	stopErr     error
}

func (f *fakeTPM) IsInitialized() bool {
	f.calls = append(f.calls, "IsInitialized")
	return f.initialized
}
func (f *fakeTPM) Initialize(context.Context) error {
	f.calls = append(f.calls, "Initialize")
	return f.initErr
}
func (f *fakeTPM) Start(context.Context) error { f.calls = append(f.calls, "Start"); return f.startErr }
func (f *fakeTPM) WaitForSocket(time.Duration) error {
	f.calls = append(f.calls, "WaitForSocket")
	return f.socketErr
}
func (f *fakeTPM) SocketPath() string { return f.socket }
func (f *fakeTPM) StateDir() string   { return f.stateDir }
func (f *fakeTPM) PID() int           { return 4242 }
func (f *fakeTPM) Stop() error        { f.calls = append(f.calls, "Stop"); return f.stopErr }

// installFake routes newTPM and stopExisting to a fake for one test.
func installFake(t *testing.T, fake *fakeTPM, constructErr error) (stopped *[]string, gotCfg **swtpm.Config) {
	t.Helper()
	var stoppedDirs []string
	var cfg *swtpm.Config
	origNew, origStop := newTPM, stopExisting
	newTPM = func(c *swtpm.Config, _ *logging.Logger) (TPM, error) {
		cfg = c
		if constructErr != nil {
			return nil, constructErr
		}
		fake.stateDir = c.StateDir
		if fake.socket == "" {
			fake.socket = c.SocketPath
		}
		return fake, nil
	}
	stopExisting = func(dir string) error { stoppedDirs = append(stoppedDirs, dir); return nil }
	t.Cleanup(func() { newTPM, stopExisting = origNew, origStop })
	return &stoppedDirs, &cfg
}

func TestStartTPM_InitializesFreshState(t *testing.T) {
	fake := &fakeTPM{}
	stopped, gotCfg := installFake(t, fake, nil)
	cfg := &qemu.Config{WorkDir: "/work/vm", Debug: true}

	tpm, state, err := StartTPM(context.Background(), nil, cfg)

	require.NoError(t, err)
	assert.Same(t, fake, tpm)
	assert.Equal(t, TPMStateInitialized, state)
	assert.Equal(t, []string{"IsInitialized", "Initialize", "Start", "WaitForSocket"}, fake.calls)
	assert.Equal(t, []string{"/work/vm/tpm"}, *stopped)
	assert.Equal(t, "/work/vm/tpm", (*gotCfg).StateDir)
	assert.True(t, (*gotCfg).QEMUMode, "QEMU's emulator tpmdev needs the --ctrl socket")
	assert.Equal(t, []string{"sha256"}, (*gotCfg).PCRBanks)
	assert.True(t, (*gotCfg).Debug)
	assert.Equal(t, "/work/vm/tpm/swtpm.sock", cfg.TPMSocket)
}

func TestStartTPM_PreservesExistingStateAndAdoptsTheRelocatedSocket(t *testing.T) {
	fake := &fakeTPM{initialized: true, socket: "/tmp/relocated/swtpm.sock"}
	installFake(t, fake, nil)
	cfg := &qemu.Config{WorkDir: "/work/vm"}

	_, state, err := StartTPM(context.Background(), logging.DefaultLogger(), cfg)

	require.NoError(t, err)
	assert.Equal(t, TPMStatePreserved, state)
	assert.NotContains(t, fake.calls, "Initialize")
	assert.Equal(t, "/tmp/relocated/swtpm.sock", cfg.TPMSocket, "the VM must use the socket swtpm actually opened")
}

func TestStartTPM_Failures(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name         string
		fake         *fakeTPM
		constructErr error
		step         string
		stopped      bool
	}{
		{"constructor", &fakeTPM{}, boom, "creating the software TPM", false},
		{"initialize", &fakeTPM{initErr: boom}, nil, "initializing the software TPM", false},
		{"start", &fakeTPM{startErr: boom}, nil, "starting the software TPM", false},
		{"socket", &fakeTPM{socketErr: boom}, nil, "waiting for the TPM socket", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installFake(t, tc.fake, tc.constructErr)

			tpm, _, err := StartTPM(context.Background(), nil, &qemu.Config{WorkDir: t.TempDir()})

			require.Error(t, err)
			assert.Nil(t, tpm)
			var tpmErr *TPMError
			require.True(t, errors.As(err, &tpmErr))
			assert.Equal(t, tc.step, tpmErr.Step)
			assert.ErrorIs(t, err, boom)
			assert.Equal(t, tc.stopped, contains(tc.fake.calls, "Stop"), "a TPM that started but never opened its socket is stopped again")
		})
	}
}

func TestStopTPM(t *testing.T) {
	fake := &fakeTPM{}
	StopTPM(nil, fake)
	assert.Equal(t, []string{"Stop"}, fake.calls)

	failing := &fakeTPM{stopErr: errors.New("already gone")}
	StopTPM(logging.DefaultLogger(), failing) // logged, not returned
	assert.Equal(t, []string{"Stop"}, failing.calls)

	StopTPM(nil, nil) // a nil TPM is a no-op
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// The serial waits only read a file between ticks, so they run in a
// synctest bubble: the poll interval and the deadlines pass on the
// bubble's clock instead of being waited out (#284).

func TestWaitForSerial_ReturnsWhenTheMilestoneAppears(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serial.log")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		done := make(chan error, 1)
		go func() { done <- WaitForSerial(ctx, path, "platformd ready") }()

		// The transcript does not exist yet, then grows in two writes.
		require.NoError(t, os.WriteFile(path, []byte("U-Boot 2026.07\nBooting Linux\n"), 0o644))
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		require.NoError(t, err)
		_, err = f.WriteString("[INIT] platformd ready\n")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		require.NoError(t, <-done)
	})
}

func TestWaitForSerial_TimesOutWithTheTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serial.log")
		require.NoError(t, os.WriteFile(path, []byte("U-Boot 2026.07\nstuck at the prompt\n"), 0o644))
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()

		err := WaitForSerial(ctx, path, "Booting Linux")

		var timeout *SerialTimeoutError
		require.True(t, errors.As(err, &timeout))
		assert.Equal(t, "Booting Linux", timeout.Needle)
		assert.Contains(t, timeout.Tail, "stuck at the prompt")
		assert.Contains(t, err.Error(), `"Booting Linux"`)
	})
}

func TestWaitForSerialAfter_IgnoresAnEarlierBoot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "serial.log")
		first := []byte("boot one: sealed\n")
		require.NoError(t, os.WriteFile(path, first, 0o644))
		offset, err := SerialSize(path)
		require.NoError(t, err)
		assert.Equal(t, int64(len(first)), offset)

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		err = WaitForSerialAfter(ctx, path, "sealed", offset)
		var timeout *SerialTimeoutError
		assert.True(t, errors.As(err, &timeout), "the first boot's milestone must not satisfy the second boot's wait")

		require.NoError(t, os.WriteFile(path, append(first, []byte("boot two: sealed\n")...), 0o644))
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		assert.NoError(t, WaitForSerialAfter(ctx2, path, "sealed", offset))
	})
}

func TestSerialSize_MissingFileIsZero(t *testing.T) {
	size, err := SerialSize(filepath.Join(t.TempDir(), "nope.log"))
	require.NoError(t, err)
	assert.Zero(t, size)
}

func TestSerialContains_UnreadableTranscript(t *testing.T) {
	dir := t.TempDir() // a directory is not a readable transcript
	_, err := SerialContains(dir, "x")
	var serialErr *SerialError
	require.True(t, errors.As(err, &serialErr))
	assert.Equal(t, dir, serialErr.Path)

	_, err = SerialSize(filepath.Join(dir, string([]byte{0})))
	assert.Error(t, err)
}

// fakeGuest is the VM side of a console socket: it scripts prompts and
// echoes commands the way U-Boot does.
func fakeGuest(t *testing.T, socketPath string, script func(conn net.Conn)) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		script(conn)
	}()
}

func TestConsole_DrivesAUBootPrompt(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "console.sock")
	fakeGuest(t, socketPath, func(conn net.Conn) {
		_, _ = conn.Write([]byte("U-Boot 2026.07\nHit any key to stop autoboot:  2 "))
		buf := make([]byte, 64)
		_, _ = conn.Read(buf) // the keypress
		_, _ = conn.Write([]byte("\n=> "))
		n, _ := conn.Read(buf) // the command
		_, _ = conn.Write([]byte(string(buf[:n]) + "\ntpm_tis@0 v2.0: VendorID 0x1014, DeviceID 0x0001\n=> "))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	console, err := DialConsole(ctx, socketPath)
	require.NoError(t, err)
	defer console.Close()

	_, err = console.Expect(ctx, "Hit any key to stop autoboot")
	require.NoError(t, err)
	require.NoError(t, console.Send("\r"))
	_, err = console.Expect(ctx, "=> ")
	require.NoError(t, err)

	console.Discard()
	require.NoError(t, console.SendLine("tpm2 info"))
	out, err := console.Expect(ctx, "=> ")
	require.NoError(t, err)
	assert.Contains(t, out, "VendorID 0x1014")
	assert.NotContains(t, out, "Hit any key", "Discard forgets the earlier output")
	assert.Equal(t, out, console.Transcript())
}

func TestConsole_ExpectTimesOutWithTheTranscript(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "console.sock")
	block := make(chan struct{})
	fakeGuest(t, socketPath, func(conn net.Conn) {
		_, _ = conn.Write([]byte("nothing useful\n"))
		<-block
	})
	defer close(block)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	console, err := DialConsole(ctx, socketPath)
	require.NoError(t, err)
	defer console.Close()

	_, err = console.Expect(ctx, "nothing useful\n")
	require.NoError(t, err)

	// The guest has said all it will, so a deadline that has already
	// passed times the wait out without spending one (#284).
	expired, cancelExpired := context.WithDeadline(ctx, time.Now())
	defer cancelExpired()
	_, err = console.Expect(expired, "=> ")

	var timeout *ConsoleTimeoutError
	require.True(t, errors.As(err, &timeout))
	assert.Equal(t, "=> ", timeout.Needle)
	assert.Contains(t, timeout.Transcript, "nothing useful")
}

func TestConsole_ExpectReportsAClosedGuest(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "console.sock")
	fakeGuest(t, socketPath, func(conn net.Conn) { _, _ = conn.Write([]byte("bye\n")) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	console, err := DialConsole(ctx, socketPath)
	require.NoError(t, err)
	defer console.Close()

	_, err = console.Expect(ctx, "never")

	var consoleErr *ConsoleError
	require.True(t, errors.As(err, &consoleErr))
	assert.Contains(t, consoleErr.Op, "never")
}

func TestDialConsole_WaitsForTheSocketThenGivesUp(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "late.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		// The socket appears after the first dial attempts have failed.
		timer := time.NewTimer(450 * time.Millisecond)
		<-timer.C
		fakeGuest(t, socketPath, func(conn net.Conn) { _, _ = conn.Write([]byte("hello\n")) })
	}()
	console, err := DialConsole(ctx, socketPath)
	require.NoError(t, err)
	_, err = console.Expect(ctx, "hello")
	require.NoError(t, err)
	require.NoError(t, console.Close())
}

func TestDialConsole_GivesUpWhenTheSocketNeverAppears(t *testing.T) {
	// A dial of a missing socket fails at once, so the retries and the
	// deadline run on the synctest bubble's clock (#284).
	synctest.Test(t, func(t *testing.T) {
		short, cancelShort := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancelShort()
		_, err := DialConsole(short, filepath.Join(t.TempDir(), "never.sock"))
		var consoleErr *ConsoleError
		require.True(t, errors.As(err, &consoleErr))
	})
}

func TestConsole_SendOnAClosedSessionFails(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "console.sock")
	fakeGuest(t, socketPath, func(conn net.Conn) {})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	console, err := DialConsole(ctx, socketPath)
	require.NoError(t, err)
	require.NoError(t, console.Close())

	err = console.SendLine("tpm2 info")
	var consoleErr *ConsoleError
	require.True(t, errors.As(err, &consoleErr))
	assert.Contains(t, consoleErr.Op, "tpm2 info")
}

func TestErrorStrings(t *testing.T) {
	cause := errors.New("cause")
	assert.Equal(t, "harness: starting: cause", (&TPMError{Step: "starting", Err: cause}).Error())
	assert.ErrorIs(t, &TPMError{Step: "starting", Err: cause}, cause)
	assert.Equal(t, "harness: reading serial transcript /s.log: cause", (&SerialError{Path: "/s.log", Err: cause}).Error())
	assert.ErrorIs(t, &SerialError{Err: cause}, cause)
	assert.Equal(t, "harness: console: op: cause", (&ConsoleError{Op: "op", Err: cause}).Error())
	assert.ErrorIs(t, &ConsoleError{Err: cause}, cause)
	assert.Contains(t, (&ConsoleTimeoutError{Needle: "=> ", Transcript: "t"}).Error(), `"=> "`)
}

func TestMissingMilestone_NamesTheFirstAbsentOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "serial.log")
	require.NoError(t, os.WriteFile(path, []byte("U-Boot 2026.07\nBooting Linux\nlogin:\n"), 0o644))

	assert.Equal(t, "every milestone present", MissingMilestone(path, []string{"U-Boot 20", "Linux", "login:"}))
	assert.Equal(t, "first missing milestone: Welcome", MissingMilestone(path, []string{"U-Boot 20", "Welcome", "login:"}))
}

func TestMissingMilestone_AbsentTranscriptLacksTheFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.log")
	assert.Equal(t, "first missing milestone: U-Boot 20", MissingMilestone(path, []string{"U-Boot 20", "login:"}))
}
