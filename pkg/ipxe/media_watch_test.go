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
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock hands the watcher deterministic, advancing timestamps.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time {
	c.t = c.t.Add(time.Second)
	return c.t
}

func TestMediaWatcher_AccumulatesPerOpener(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	clock := &fakeClock{t: time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)}
	w := newMediaWatcher(proc.root, data, 999, time.Hour, clock.now)
	setPos := func(pid, fd int, pos int64) {
		require.NoError(t, os.WriteFile(filepath.Join(proc.root, itoa(pid), "fdinfo", itoa(fd)), []byte("pos:\t"+itoa64(pos)+"\n"), 0o644))
	}

	// Sample 1: nothing open.
	require.NoError(t, w.sample())
	assert.Empty(t, w.status().Files)

	// Sample 2: smbd opens the ISO and reads a little.
	proc.open(101, 7, iso, 4096)
	require.NoError(t, w.sample())
	st := w.status()
	require.Len(t, st.Files, 1)
	assert.Equal(t, 1, st.Files[0].Opens)
	assert.Equal(t, 1, st.Files[0].OpenSamples)
	smbd := st.Files[0].Opener("smbd")
	require.NotNil(t, smbd)
	assert.Equal(t, 1, smbd.OpenEvents)
	assert.Equal(t, 0, smbd.PosChanges)
	assert.Equal(t, int64(4096), smbd.MaxPos)
	firstSeen := smbd.FirstSeen
	assert.Equal(t, firstSeen, smbd.LastActivity)

	// Sample 3: smbd's descriptor is unchanged (no activity); a backup
	// opens the file too (its own open event, not smbd's).
	proc.openAs("tar", 200, 4, iso, 10)
	require.NoError(t, w.sample())
	st = w.status()
	smbd = st.Files[0].Opener("smbd")
	assert.Equal(t, 1, smbd.Activity(), "a held-but-idle descriptor is not activity")
	assert.Equal(t, 2, smbd.OpenSamples)
	tar := st.Files[0].Opener("tar")
	require.NotNil(t, tar)
	assert.Equal(t, 1, tar.OpenEvents)
	assert.Equal(t, 2, st.Files[0].Opens)

	// Sample 4: smbd reads further — a position change.
	setPos(101, 7, 65536)
	require.NoError(t, w.sample())
	smbd = w.status().Files[0].Opener("smbd")
	assert.Equal(t, 1, smbd.PosChanges)
	assert.Equal(t, 2, smbd.Activity())
	assert.Equal(t, int64(65536), smbd.MaxPos)
	assert.True(t, smbd.LastActivity.After(firstSeen))

	// Sample 5: everything closed — history survives, Opens drops to 0.
	require.NoError(t, os.RemoveAll(filepath.Join(proc.root, "101")))
	require.NoError(t, os.RemoveAll(filepath.Join(proc.root, "200")))
	require.NoError(t, w.sample())
	st = w.status()
	require.Len(t, st.Files, 1, "a file read earlier stays on record")
	assert.Equal(t, 0, st.Files[0].Opens)
	assert.Equal(t, 3, st.Files[0].OpenSamples)
	smbd = st.Files[0].Opener("smbd")
	assert.Equal(t, 0, smbd.Opens)
	assert.Equal(t, 2, smbd.Activity())
	lastActivity := smbd.LastActivity

	// Sample 6: smbd reopens — a fresh open event, even at the old offset.
	proc.open(102, 3, iso, 65536)
	require.NoError(t, w.sample())
	smbd = w.status().Files[0].Opener("smbd")
	assert.Equal(t, 2, smbd.OpenEvents)
	assert.Equal(t, 3, smbd.Activity())
	assert.True(t, smbd.LastActivity.After(lastActivity))
	assert.Equal(t, time.Hour, w.status().Interval)
}

func TestMediaWatcher_KeepsClientsApart(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	w := newMediaWatcher(proc.root, data, 999, time.Hour, nil)
	proc.openFor("smbd", "198.18.1.103", 301, 5, iso, 1000)
	proc.openFor("smbd", "198.18.1.104", 302, 5, iso, 2000)
	require.NoError(t, w.sample())
	// Only the first client reads further.
	require.NoError(t, os.WriteFile(filepath.Join(proc.root, "301", "fdinfo", "5"), []byte("pos:\t5000\n"), 0o644))
	require.NoError(t, w.sample())

	openers := w.status().Files[0].OpenersNamed("smbd")
	require.Len(t, openers, 2)
	assert.Equal(t, "198.18.1.103", openers[0].Client)
	assert.Equal(t, 2, openers[0].Activity(), "open event plus one position change")
	assert.Equal(t, "198.18.1.104", openers[1].Client)
	assert.Equal(t, 1, openers[1].Activity(), "open event only")
	assert.Nil(t, w.status().Files[0].Opener("smbd"), "no client-less smbd record")
}

func TestMediaWatcher_ScanFailureKeepsPreviousRecord(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	w := newMediaWatcher(proc.root, data, 999, 0, nil)
	proc.open(1, 1, iso, 1)
	require.NoError(t, w.sample())
	require.Len(t, w.status().Files, 1)

	require.NoError(t, os.RemoveAll(proc.root))
	err := w.sample()
	require.Error(t, err)
	assert.Len(t, w.status().Files, 1, "a failed scan does not erase history")
	assert.Equal(t, defaultMediaSampleInterval, w.interval)
	assert.Equal(t, defaultProcRoot, newMediaWatcher("", data, 1, 0, nil).procRoot)
}

func TestMediaWatcher_RunSamplesUntilCancelled(t *testing.T) {
	proc := newFakeProc(t)
	data := t.TempDir()
	iso := filepath.Join(data, "platform.iso")
	proc.open(1, 1, iso, 1)
	w := newMediaWatcher(proc.root, data, 999, time.Millisecond, nil)

	require.NoError(t, w.sample())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.run(ctx)
		close(done)
	}()
	// Wait until the loop has sampled at least once more, then break
	// procfs and wait for the loop to record the failure, then cancel:
	// the loop must exit and the record must still be intact. Both waits
	// are bounded by the test's own deadline, not by a sleep.
	waitUntil(t, done, func() bool { return w.status().Files[0].OpenSamples >= 2 })
	require.NoError(t, os.RemoveAll(proc.root))
	waitUntil(t, done, func() bool { return w.lastErr.Load() != nil })
	cancel()
	<-done
	require.Len(t, w.status().Files, 1)
	assert.GreaterOrEqual(t, w.status().Files[0].OpenSamples, 2)
}

// waitUntil yields until cond holds, failing if the watcher loop exits
// first or the test deadline passes. It polls the watcher's atomic state
// rather than sleeping; the deadline is the test's own, not a guess.
func waitUntil(t *testing.T, done <-chan struct{}, cond func() bool) {
	t.Helper()
	ctx := t.Context()
	for !cond() {
		select {
		case <-done:
			t.Fatal("run exited before cancellation")
		case <-ctx.Done():
			t.Fatal("condition not reached before the test deadline")
		default:
			runtime.Gosched()
		}
	}
}
