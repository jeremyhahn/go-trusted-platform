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

//go:build opa

package opa

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// watcherDeadline bounds how long a test waits for a filesystem event that must
// eventually arrive. It is a liveness backstop, not a timing assumption: these
// tests advance on the callback itself, so a loaded host only makes them slower
// and the deadline is reached only when the watcher has genuinely stopped
// delivering.
const watcherDeadline = 10 * time.Second

// backdatePendingChange ages a queued change past the debounce interval, so the
// next sweep treats it as settled. It does deterministically what waiting out
// the window does by luck: the debouncer compares stamps, so moving the stamp
// is equivalent to moving the clock, and nothing here depends on how busy the
// host is.
func backdatePendingChange(t *testing.T, w *FileWatcher, path string) {
	t.Helper()

	w.debounceMu.Lock()
	defer w.debounceMu.Unlock()

	stamp, ok := w.pendingChanges[path]
	require.True(t, ok, "expected a pending change queued for %s", path)
	w.pendingChanges[path] = stamp.Add(-2 * debounceInterval)
}

// pendingChangeCount reports how many changes are queued for the next sweep.
func pendingChangeCount(w *FileWatcher) int {
	w.debounceMu.Lock()
	defer w.debounceMu.Unlock()
	return len(w.pendingChanges)
}

func TestNewFileWatcher(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)
		require.NotNil(t, watcher)
		assert.Equal(t, tmpDir, watcher.watchDir)
		assert.False(t, watcher.IsRunning())
	})

	t.Run("error with empty path", func(t *testing.T) {
		watcher, err := NewFileWatcher("")
		require.Error(t, err)
		assert.Nil(t, watcher)

		var dirNotFoundErr ErrPolicyDirNotFound
		assert.ErrorAs(t, err, &dirNotFoundErr)
	})

	t.Run("error with non-existent directory", func(t *testing.T) {
		watcher, err := NewFileWatcher("/non/existent/path")
		require.Error(t, err)
		assert.Nil(t, watcher)

		var dirNotFoundErr ErrPolicyDirNotFound
		assert.ErrorAs(t, err, &dirNotFoundErr)
	})

	t.Run("error when path is a file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "file.txt")
		err := os.WriteFile(filePath, []byte("content"), 0644)
		require.NoError(t, err)

		watcher, err := NewFileWatcher(filePath)
		require.Error(t, err)
		assert.Nil(t, watcher)

		var dirNotFoundErr ErrPolicyDirNotFound
		assert.ErrorAs(t, err, &dirNotFoundErr)
	})
}

func TestFileWatcher_Start(t *testing.T) {
	t.Run("successful start", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		assert.True(t, watcher.IsRunning())

		err = watcher.Stop()
		require.NoError(t, err)
	})

	t.Run("error when already started", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)

		err = watcher.Start(ctx)
		require.Error(t, err)

		var alreadyStartedErr ErrWatcherAlreadyStarted
		assert.ErrorAs(t, err, &alreadyStartedErr)

		require.NoError(t, watcher.Stop())
	})
}

func TestFileWatcher_Stop(t *testing.T) {
	t.Run("successful stop", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)

		err = watcher.Stop()
		require.NoError(t, err)
		assert.False(t, watcher.IsRunning())
	})

	t.Run("error when not started", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		err = watcher.Stop()
		require.Error(t, err)

		var notStartedErr ErrWatcherNotStarted
		assert.ErrorAs(t, err, &notStartedErr)
	})
}

func TestFileWatcher_OnPolicyChange(t *testing.T) {
	t.Run("multiple callbacks registered", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {})
		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {})
		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {})

		assert.Len(t, watcher.callbacks, 3)
	})
}

func TestFileWatcher_FileEvents(t *testing.T) {
	t.Run("detects new policy file", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		var mu sync.Mutex
		var receivedName string
		var receivedContent []byte
		var receivedDeleted bool
		callbackDone := make(chan struct{})

		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			mu.Lock()
			receivedName = name
			receivedContent = content
			receivedDeleted = deleted
			mu.Unlock()
			close(callbackDone)
		})

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		defer func() { assert.NoError(t, watcher.Stop()) }()

		// Create a new policy file
		policyPath := filepath.Join(tmpDir, "newpolicy.rego")
		policyContent := []byte(`package test
default allow = false
`)
		err = os.WriteFile(policyPath, policyContent, 0644)
		require.NoError(t, err)

		// Wait for callback or timeout
		select {
		case <-callbackDone:
		case <-time.After(watcherDeadline):
			t.Fatal("timeout waiting for callback")
		}

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, "newpolicy", receivedName)
		assert.Equal(t, policyContent, receivedContent)
		assert.False(t, receivedDeleted)
	})

	t.Run("ignores non-rego files", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		var callbackCalled atomic.Bool
		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			callbackCalled.Store(true)
		})

		// Create a non-rego file
		filePath := filepath.Join(tmpDir, "notapolicy.txt")
		err = os.WriteFile(filePath, []byte("not a policy"), 0644)
		require.NoError(t, err)

		// Waiting cannot prove a negative — a sleep only shows the callback
		// had not fired yet. The event is delivered directly and a sweep is
		// driven to completion, so the assertion is about a filter that
		// provably ran rather than about 300ms of silence.
		watcher.handleEvent(fsnotify.Event{Name: filePath, Op: fsnotify.Write})
		watcher.processPendingChanges()

		assert.False(t, callbackCalled.Load())
		assert.Equal(t, 0, pendingChangeCount(watcher), "a non-rego file must not even be queued")
	})

	t.Run("detects policy file deletion", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create initial policy file
		policyPath := filepath.Join(tmpDir, "deleteme.rego")
		err := os.WriteFile(policyPath, []byte(`package test`), 0644)
		require.NoError(t, err)

		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		var mu sync.Mutex
		var receivedDeleted bool
		callbackDone := make(chan struct{}, 1)

		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			mu.Lock()
			receivedDeleted = deleted
			mu.Unlock()
			select {
			case callbackDone <- struct{}{}:
			default:
			}
		})

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		defer func() { assert.NoError(t, watcher.Stop()) }()

		// Delete the policy file
		err = os.Remove(policyPath)
		require.NoError(t, err)

		// Wait for callback or timeout
		select {
		case <-callbackDone:
		case <-time.After(watcherDeadline):
			t.Fatal("timeout waiting for callback")
		}

		mu.Lock()
		defer mu.Unlock()
		assert.True(t, receivedDeleted)
	})
}

func TestFileWatcher_ContextCancellation(t *testing.T) {
	t.Run("stops on context cancellation", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		err = watcher.Start(ctx)
		require.NoError(t, err)

		// Cancel the context
		cancel()

		// No sleep: Stop closes the done channel and joins both watcher
		// goroutines through its WaitGroup, which is stronger than waiting
		// 200ms and hoping. Cancelling the context alone does not clear the
		// running flag, so Stop is still what cleans up.
		require.NoError(t, watcher.Stop())
	})
}

func TestNewWatchedEngine(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		tmpDir := t.TempDir()
		engine := NewOPAEngine()

		watchedEngine, err := NewWatchedEngine(engine, tmpDir)
		require.NoError(t, err)
		require.NotNil(t, watchedEngine)
		assert.Equal(t, engine, watchedEngine.Engine())
	})

	t.Run("error with invalid directory", func(t *testing.T) {
		engine := NewOPAEngine()

		watchedEngine, err := NewWatchedEngine(engine, "/non/existent/path")
		require.Error(t, err)
		assert.Nil(t, watchedEngine)
	})
}

func TestWatchedEngine_AutoReload(t *testing.T) {
	t.Run("automatically loads new policy", func(t *testing.T) {
		tmpDir := t.TempDir()
		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}
		err := engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		watchedEngine, err := NewWatchedEngine(engine, tmpDir)
		require.NoError(t, err)

		// Observe the same watcher the engine listens to. Callbacks run in
		// registration order and NewWatchedEngine registered its own first,
		// so by the time this one fires the engine has already applied the
		// change — the test advances on the reload itself instead of on a
		// 500ms guess that one happened.
		reloaded := reloadSignal(watchedEngine)

		err = watchedEngine.Start(ctx)
		require.NoError(t, err)
		defer func() { assert.NoError(t, watchedEngine.Stop()) }()

		// Create a new policy file
		policyPath := filepath.Join(tmpDir, "autopolicy.rego")
		policyContent := `package auto
import rego.v1
default allow := true
`
		err = os.WriteFile(policyPath, []byte(policyContent), 0644)
		require.NoError(t, err)

		assert.Equal(t, "autopolicy", awaitReload(t, reloaded))

		// Verify policy was loaded
		_, err = engine.GetPolicy("autopolicy")
		require.NoError(t, err)
	})

	t.Run("automatically unloads deleted policy", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create initial policy
		policyPath := filepath.Join(tmpDir, "deletable.rego")
		err := os.WriteFile(policyPath, []byte(`package deletable
import rego.v1
default allow := true
`), 0644)
		require.NoError(t, err)

		engine := NewOPAEngine()
		ctx := context.Background()

		cfg := &config.PolicyConfig{
			Engine:        config.PolicyEngineOPA,
			PolicyDir:     tmpDir,
			DefaultAction: config.DefaultActionDeny,
		}
		err = engine.Initialize(ctx, cfg)
		require.NoError(t, err)

		// Verify policy was loaded
		_, err = engine.GetPolicy("deletable")
		require.NoError(t, err)

		watchedEngine, err := NewWatchedEngine(engine, tmpDir)
		require.NoError(t, err)

		reloaded := reloadSignal(watchedEngine)

		err = watchedEngine.Start(ctx)
		require.NoError(t, err)
		defer func() { assert.NoError(t, watchedEngine.Stop()) }()

		// Delete the policy file
		err = os.Remove(policyPath)
		require.NoError(t, err)

		assert.Equal(t, "deletable", awaitReload(t, reloaded))

		// Verify policy was unloaded
		_, err = engine.GetPolicy("deletable")
		require.Error(t, err)

		var notFoundErr ErrPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})
}

// reloadSignal reports the policy names a WatchedEngine's watcher delivers.
// It registers after NewWatchedEngine's own callback, and notifyChange invokes
// callbacks in registration order, so a name read from this channel is one the
// engine has already applied.
func reloadSignal(we *WatchedEngine) <-chan string {
	names := make(chan string, 8)
	we.watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
		select {
		case names <- name:
		default: // the test is not reading; dropping keeps the watcher moving
		}
	})
	return names
}

// awaitReload returns the next policy name the watcher delivered.
func awaitReload(t *testing.T, names <-chan string) string {
	t.Helper()

	select {
	case name := <-names:
		return name
	case <-time.After(watcherDeadline):
		t.Fatalf("no policy reload delivered within %s", watcherDeadline)
		return ""
	}
}

// TestFileWatcher_Debouncing drives the debouncer directly rather than through
// fsnotify and the wall clock.
//
// The old form wrote the file five times with 20ms sleeps, slept 500ms, and
// asserted at most two callbacks. Both halves were defective. The sleeps were
// the synchronisation, so on a loaded host the writes spread past the debounce
// interval, each fired its own callback, and the assertion failed on branches
// that never touched this package. And every os.WriteFile error was discarded:
// had the writes failed there would have been no callbacks at all, the count
// would have been zero, and the assertion would have passed while testing
// nothing (#203).
//
// Delivering the events directly makes the assertion exact — five changes
// produce one reload, and a change inside the window produces none — with no
// clock in it and every error checked.
func TestFileWatcher_Debouncing(t *testing.T) {
	t.Run("rapid changes to one file coalesce into a single reload", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		var mu sync.Mutex
		var reloads []string
		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			mu.Lock()
			defer mu.Unlock()
			reloads = append(reloads, name)
		})

		policyPath := filepath.Join(tmpDir, "rapid.rego")
		require.NoError(t, os.WriteFile(policyPath, []byte("package rapid\ndefault allow = true\n"), 0644))

		// Five change events inside one debounce window, delivered exactly as
		// processEvents delivers them.
		for i := 0; i < 5; i++ {
			watcher.handleEvent(fsnotify.Event{Name: policyPath, Op: fsnotify.Write})
		}
		require.Equal(t, 1, pendingChangeCount(watcher), "repeat changes to one file share one queue entry")

		// A sweep while the window is still open must reload nothing: that
		// hold-off is what the debouncing is.
		watcher.processPendingChanges()
		mu.Lock()
		duringWindow := len(reloads)
		mu.Unlock()
		require.Equal(t, 0, duringWindow, "a change inside the debounce window must not reload")

		// Close the window and sweep again: the five changes collapse to one.
		backdatePendingChange(t, watcher, policyPath)
		watcher.processPendingChanges()

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, []string{"rapid"}, reloads, "five rapid changes must coalesce into one reload")
		assert.Equal(t, 0, pendingChangeCount(watcher), "a processed change is dequeued")
	})

	t.Run("a settled change reloads the content that is on disk", func(t *testing.T) {
		// The companion to the case above: coalescing must deliver the LAST
		// write, not the first. Discarding the write errors is exactly what
		// would have hidden a regression here.
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		var mu sync.Mutex
		var got []byte
		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			mu.Lock()
			defer mu.Unlock()
			got = content
		})

		policyPath := filepath.Join(tmpDir, "rapid.rego")
		for i, body := range []string{"package rapid\n# first\n", "package rapid\n# last\n"} {
			require.NoError(t, os.WriteFile(policyPath, []byte(body), 0644), "write %d", i)
			watcher.handleEvent(fsnotify.Event{Name: policyPath, Op: fsnotify.Write})
		}

		backdatePendingChange(t, watcher, policyPath)
		watcher.processPendingChanges()

		mu.Lock()
		defer mu.Unlock()
		assert.Equal(t, "package rapid\n# last\n", string(got))
	})
}
