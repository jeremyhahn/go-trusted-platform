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

package swtpm

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tpmHeaderSize      = 10
	tpmSTNoSessions    = 0x8001
	tpmCCStartup       = 0x00000144
	tpmRCSuccess       = 0x000
	tpmRCInitialize    = 0x100
	tpmRCFailure       = 0x101
	tpmSUClear         = 0x0000
	tpmStartupCmdBytes = tpmHeaderSize + 2
)

// startedFakeSWTPM starts an SWTPM on the stand-in swtpm from fakeSWTPMOnPath.
// Cleanup stops it unless the test already did.
func startedFakeSWTPM(t *testing.T) *SWTPM {
	t.Helper()

	fakeSWTPMOnPath(t)
	s := &SWTPM{
		config: &Config{StateDir: t.TempDir(), SocketPath: filepath.Join(t.TempDir(), "swtpm.sock")},
		logger: logging.DefaultLogger(),
	}
	require.NoError(t, s.Start(context.Background()))
	t.Cleanup(func() {
		if s.PID() != 0 {
			require.NoError(t, s.Stop())
		}
	})
	return s
}

// serveStartupResponses answers each TPM2_Startup sent to a unix socket with
// a response carrying the next of codes, as swtpm does, and returns the
// socket path.
func serveStartupResponses(t *testing.T, codes ...uint32) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "swtpm.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	var answered atomic.Int32
	var connections sync.WaitGroup
	connections.Add(1)
	go func() {
		defer connections.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer func() {
					if err := conn.Close(); err != nil {
						t.Logf("close TPM connection: %v", err)
					}
				}()
				command := make([]byte, tpmStartupCmdBytes)
				for {
					if _, err := io.ReadFull(conn, command); err != nil {
						return
					}
					assert.Equal(t, uint32(tpmStartupCmdBytes), binary.BigEndian.Uint32(command[2:6]))
					assert.Equal(t, uint32(tpmCCStartup), binary.BigEndian.Uint32(command[6:10]))
					assert.Equal(t, uint16(tpmSUClear), binary.BigEndian.Uint16(command[10:12]))

					next := int(answered.Add(1)) - 1
					if next >= len(codes) {
						t.Errorf("unexpected TPM command %d", next+1)
						return
					}
					response := make([]byte, tpmHeaderSize)
					binary.BigEndian.PutUint16(response[0:2], tpmSTNoSessions)
					binary.BigEndian.PutUint32(response[2:6], tpmHeaderSize)
					binary.BigEndian.PutUint32(response[6:10], codes[next])
					if _, err := conn.Write(response); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		require.NoError(t, listener.Close())
		connections.Wait()
		assert.Equal(t, int32(len(codes)), answered.Load(), "every expected TPM2_Startup must be sent")
	})
	return socketPath
}

// A TPM that has already started answers TPM2_Startup with
// TPM_RC_INITIALIZE, which SendStartup treats as success.
func TestSendStartup_StartsAndToleratesAlreadyStarted(t *testing.T) {
	s := &SWTPM{
		config: &Config{SocketPath: serveStartupResponses(t, tpmRCSuccess, tpmRCInitialize)},
		logger: logging.DefaultLogger(),
	}

	require.NoError(t, s.SendStartup())
	require.NoError(t, s.SendStartup())
}

func TestSendStartup_TPMFailure(t *testing.T) {
	s := &SWTPM{
		config: &Config{SocketPath: serveStartupResponses(t, tpmRCFailure)},
		logger: logging.DefaultLogger(),
	}

	assert.ErrorIs(t, s.SendStartup(), ErrStartupFailed)
}

func TestStart_AlreadyRunning(t *testing.T) {
	s := startedFakeSWTPM(t)
	pid := s.PID()
	require.Greater(t, pid, 0)

	assert.ErrorIs(t, s.Start(context.Background()), ErrAlreadyRunning)
	assert.Equal(t, pid, s.PID(), "a refused Start must leave the running daemon in place")
}

// The accessors are safe to call from many goroutines while the daemon runs.
func TestAccessors_ConcurrentWhileRunning(t *testing.T) {
	s := startedFakeSWTPM(t)

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assert.True(t, s.IsRunning())
			assert.NotEmpty(t, s.StateDir())
			assert.NotEmpty(t, s.SocketPath())
			assert.Greater(t, s.PID(), 0)
		}()
	}
	wg.Wait()
}

// Each SWTPM tracks its own daemon: stopping one leaves the others running.
func TestStart_MultipleInstances(t *testing.T) {
	instances := []*SWTPM{startedFakeSWTPM(t), startedFakeSWTPM(t), startedFakeSWTPM(t)}
	pids := map[int]bool{}
	for _, s := range instances {
		require.True(t, s.IsRunning())
		pids[s.PID()] = true
	}
	require.Len(t, pids, len(instances), "every instance must run its own daemon")

	require.NoError(t, instances[0].Stop())

	assert.False(t, instances[0].IsRunning())
	assert.True(t, instances[1].IsRunning())
	assert.True(t, instances[2].IsRunning())
}

// A daemon killed from outside is seen as gone: the socket never becomes
// ready and Stop still succeeds.
func TestStart_KilledProcess(t *testing.T) {
	s := startedFakeSWTPM(t)
	exitCh := s.exitCh

	require.NoError(t, syscall.Kill(s.PID(), syscall.SIGKILL))
	<-exitCh

	assert.False(t, s.IsRunning())
	assert.ErrorIs(t, s.WaitForSocket(time.Minute), ErrSocketNotReady)
	require.NoError(t, s.Stop(), "Stop must tolerate a process that already exited")
	assert.Equal(t, 0, s.PID())
}

// StopExisting stops the swtpm whose command line names the state directory.
func TestStopExisting_StopsDaemonForStateDir(t *testing.T) {
	// The stand-in keeps its command line, which StopExisting matches, and
	// takes its child down with it on SIGTERM.
	fakeSWTPMScriptOnPath(t, "#!/bin/sh\ntrap 'kill $!; exit 143' TERM\nsleep 300 &\nwait\n")
	// Start puts a state directory under /tmp/ on the swtpm command line as
	// is; one anywhere else runs from a relocated copy.
	stateDir, err := os.MkdirTemp("/tmp", "swtpm-stop-existing-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(stateDir)) })

	s := &SWTPM{
		config: &Config{StateDir: stateDir, SocketPath: filepath.Join(stateDir, "swtpm.sock")},
		logger: logging.DefaultLogger(),
	}
	require.NoError(t, s.Start(context.Background()))
	exitCh := s.exitCh
	t.Cleanup(func() { require.NoError(t, s.Stop()) })

	require.NoError(t, StopExisting(stateDir))

	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	select {
	case <-exitCh:
	case <-timeout.C:
		t.Fatal("StopExisting left the swtpm for the state directory running")
	}
	assert.False(t, s.IsRunning())
}
