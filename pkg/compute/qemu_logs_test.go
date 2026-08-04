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
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeSerial(t *testing.T, workDir, content string) string {
	t.Helper()
	path := filepath.Join(workDir, "serial.log")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestReadSerialBacklog(t *testing.T) {
	dir := t.TempDir()
	path := writeSerial(t, dir, "line1\nline2\nline3\n")

	lines, offset, err := readSerialBacklog(path, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"line1", "line2", "line3"}, lines)
	assert.Equal(t, int64(18), offset)

	tail, _, err := readSerialBacklog(path, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"line2", "line3"}, tail)

	_, _, err = readSerialBacklog(filepath.Join(dir, "missing"), 0)
	assert.True(t, os.IsNotExist(err))
}

func TestSplitLines(t *testing.T) {
	assert.Nil(t, splitLines(nil))
	assert.Equal(t, []string{"a", "b"}, splitLines([]byte("a\nb\n")))
	assert.Equal(t, []string{"a", "b"}, splitLines([]byte("a\nb")))
	assert.Equal(t, []string{"a"}, splitLines([]byte("a\r\n")))
}

func TestSerialTailer_Poll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "serial.log")
	require.NoError(t, os.WriteFile(path, []byte("first\n"), 0o644))

	tail := &serialTailer{path: path, offset: 0}
	lines, err := tail.poll()
	require.NoError(t, err)
	assert.Equal(t, []string{"first"}, lines)

	// No new data.
	lines, err = tail.poll()
	require.NoError(t, err)
	assert.Empty(t, lines)

	// Append a complete line and a partial line.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, _ = f.WriteString("second\npart")
	require.NoError(t, f.Close())

	lines, err = tail.poll()
	require.NoError(t, err)
	assert.Equal(t, []string{"second"}, lines)

	// Complete the partial line.
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	require.NoError(t, err)
	_, _ = f.WriteString("ial\n")
	require.NoError(t, f.Close())

	lines, err = tail.poll()
	require.NoError(t, err)
	assert.Equal(t, []string{"partial"}, lines)
}

func TestStreamVMLogs_BacklogNonFollow(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	writeSerial(t, wd, "boot line 1\nboot line 2\n")
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})

	var got []LogEntry
	err := orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{}, func(e LogEntry) error {
		got = append(got, e)
		return nil
	})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "boot line 1", got[0].Message)
	assert.Equal(t, "serial", got[0].Source)
}

func TestStreamVMLogs_Errors(t *testing.T) {
	orch := newOpsOrchestrator(t)

	t.Run("empty id", func(t *testing.T) {
		err := orch.StreamVMLogs(context.Background(), "", VMLogOptions{}, func(LogEntry) error { return nil })
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("nil sink", func(t *testing.T) {
		insertVMInstance(t, orch, "vm-sink", true, &InstanceConfig{WorkDir: t.TempDir()})
		err := orch.StreamVMLogs(context.Background(), "vm-sink", VMLogOptions{}, nil)
		assert.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		err := orch.StreamVMLogs(context.Background(), "nope", VMLogOptions{}, func(LogEntry) error { return nil })
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("missing transcript non-follow", func(t *testing.T) {
		insertVMInstance(t, orch, "vm-nolog", true, &InstanceConfig{WorkDir: t.TempDir()})
		err := orch.StreamVMLogs(context.Background(), "vm-nolog", VMLogOptions{}, func(LogEntry) error { return nil })
		assert.ErrorIs(t, err, ErrVMLogsUnavailable)
	})
}

func TestStreamVMLogs_Follow(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	path := writeSerial(t, wd, "initial\n")
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})

	// Seam QMP events to emit one synthetic lifecycle event.
	origSub := subscribeVMLifecycleEvents
	subscribeVMLifecycleEvents = func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance, emit func(LogEntry)) error {
		emit(LogEntry{Timestamp: time.Now(), Level: "EVENT", Message: "qmp event: SHUTDOWN", Source: "qmp"})
		return nil
	}
	origInterval := followPollInterval
	followPollInterval = 5 * time.Millisecond
	t.Cleanup(func() {
		subscribeVMLifecycleEvents = origSub
		followPollInterval = origInterval
	})

	var (
		mu   sync.Mutex
		got  []LogEntry
		sawE = make(chan struct{}, 1)
		sawS = make(chan struct{}, 1)
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- orch.StreamVMLogs(ctx, "vm1", VMLogOptions{Follow: true}, func(e LogEntry) error {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
			switch {
			case e.Source == "qmp":
				select {
				case sawE <- struct{}{}:
				default:
				}
			case e.Message == "appended":
				select {
				case sawS <- struct{}{}:
				default:
				}
			}
			return nil
		})
	}()

	// Append a new serial line after the follow has started.
	require.Eventually(t, func() bool {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return false
		}
		_, _ = f.WriteString("appended\n")
		_ = f.Close()
		return true
	}, time.Second, 5*time.Millisecond)

	waitCh(t, sawE, "qmp event")
	waitCh(t, sawS, "appended serial line")

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("follow did not return after cancel")
	}

	mu.Lock()
	defer mu.Unlock()
	assert.NotEmpty(t, got)
}

func waitCh(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}
