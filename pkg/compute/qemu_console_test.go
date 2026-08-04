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

package compute

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recvChunk(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case b, ok := <-ch:
		require.True(t, ok, "output channel closed unexpectedly")
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for console output")
		return nil
	}
}

func TestConsoleBroker_FanOutAndWrite(t *testing.T) {
	brokerConn, qemuConn := net.Pipe()
	b := &consoleBroker{
		id:      "vm1",
		conn:    brokerConn,
		logger:  logging.DefaultLogger(),
		subs:    make(map[uint64]chan []byte),
		onClose: func() {},
	}
	go b.readLoop()

	s1, err := b.subscribe()
	require.NoError(t, err)
	s2, err := b.subscribe()
	require.NoError(t, err)

	// Fake QEMU emits console output; both viewers receive it.
	go func() { _, _ = qemuConn.Write([]byte("hello\n")) }()
	assert.Equal(t, "hello\n", string(recvChunk(t, s1.Output())))
	assert.Equal(t, "hello\n", string(recvChunk(t, s2.Output())))

	// A viewer writes input; the fake QEMU reads it off the shared connection.
	readBack := make(chan string, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := qemuConn.Read(buf)
		readBack <- string(buf[:n])
	}()
	require.NoError(t, s1.Write([]byte("cmd")))
	select {
	case got := <-readBack:
		assert.Equal(t, "cmd", got)
	case <-time.After(2 * time.Second):
		t.Fatal("input not received by QEMU side")
	}

	// Detaching one viewer closes only its channel.
	require.NoError(t, s1.Close())
	_, ok := <-s1.Output()
	assert.False(t, ok)

	// Closing the broker closes the remaining viewer and is idempotent.
	require.NoError(t, b.Close())
	require.NoError(t, b.Close())
	_, ok = <-s2.Output()
	assert.False(t, ok)

	// Writing to a closed broker fails.
	assert.Error(t, s2.Write([]byte("x")))
}

// startFakeConsole opens a unix socket that echoes a banner then reads input.
func startFakeConsole(t *testing.T, path string) chan string {
	t.Helper()
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	inputs := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("banner\n"))
		buf := make([]byte, 64)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				inputs <- string(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return inputs
}

func TestAttachConsole_MultiViewer(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "vmc", true, &InstanceConfig{WorkDir: wd})
	inputs := startFakeConsole(t, filepath.Join(wd, "console.sock"))
	t.Cleanup(func() { orch.closeConsole("vmc") })

	s1, err := orch.AttachConsole(context.Background(), "vmc")
	require.NoError(t, err)
	s2, err := orch.AttachConsole(context.Background(), "vmc")
	require.NoError(t, err)

	assert.Equal(t, "banner\n", string(recvChunk(t, s1.Output())))
	assert.Equal(t, "banner\n", string(recvChunk(t, s2.Output())))

	require.NoError(t, orch.SendConsoleInput(context.Background(), "vmc", []byte("reboot")))
	select {
	case got := <-inputs:
		assert.Equal(t, "reboot", got)
	case <-time.After(2 * time.Second):
		t.Fatal("input not received")
	}

	require.NoError(t, s1.Close())
	require.NoError(t, s2.Close())
}

func TestAttachConsole_Errors(t *testing.T) {
	orch := newOpsOrchestrator(t)

	t.Run("empty id", func(t *testing.T) {
		_, err := orch.AttachConsole(context.Background(), "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := orch.AttachConsole(context.Background(), "missing")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("not running", func(t *testing.T) {
		insertVMInstance(t, orch, "stopped", false, &InstanceConfig{WorkDir: t.TempDir()})
		_, err := orch.AttachConsole(context.Background(), "stopped")
		assert.ErrorIs(t, err, ErrConsoleUnavailable)
	})

	t.Run("dial failure", func(t *testing.T) {
		insertVMInstance(t, orch, "nodial", true, &InstanceConfig{WorkDir: t.TempDir()})
		_, err := orch.AttachConsole(context.Background(), "nodial")
		assert.ErrorIs(t, err, ErrConsoleUnavailable)
	})
}

func TestSendConsoleInput(t *testing.T) {
	orch := newOpsOrchestrator(t)

	t.Run("empty id", func(t *testing.T) {
		err := orch.SendConsoleInput(context.Background(), "", []byte("x"))
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("empty data noop", func(t *testing.T) {
		err := orch.SendConsoleInput(context.Background(), "any", nil)
		assert.NoError(t, err)
	})
}
