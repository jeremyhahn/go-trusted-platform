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

package opa

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

		watcher.Stop()
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
	t.Run("callback registered", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			// Callback is registered but not invoked in this test
		})

		assert.Len(t, watcher.callbacks, 1)
	})

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
		defer watcher.Stop()

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
		case <-time.After(2 * time.Second):
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

		callbackCalled := false
		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			callbackCalled = true
		})

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		defer watcher.Stop()

		// Create a non-rego file
		filePath := filepath.Join(tmpDir, "notapolicy.txt")
		err = os.WriteFile(filePath, []byte("not a policy"), 0644)
		require.NoError(t, err)

		// Wait a bit and verify callback was not called
		time.Sleep(300 * time.Millisecond)
		assert.False(t, callbackCalled)
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
		defer watcher.Stop()

		// Delete the policy file
		err = os.Remove(policyPath)
		require.NoError(t, err)

		// Wait for callback or timeout
		select {
		case <-callbackDone:
		case <-time.After(2 * time.Second):
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

		// Wait a bit and ensure no panic
		time.Sleep(200 * time.Millisecond)

		// Watcher internal goroutines should have stopped
		// but running flag is not set to false by context cancellation alone
		// We need to call Stop() to clean up properly
		watcher.Stop()
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

func TestWatchedEngine_Start(t *testing.T) {
	t.Run("successful start", func(t *testing.T) {
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

		err = watchedEngine.Start(ctx)
		require.NoError(t, err)

		err = watchedEngine.Stop()
		require.NoError(t, err)
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

		err = watchedEngine.Start(ctx)
		require.NoError(t, err)
		defer watchedEngine.Stop()

		// Create a new policy file
		policyPath := filepath.Join(tmpDir, "autopolicy.rego")
		policyContent := `package auto
import rego.v1
default allow := true
`
		err = os.WriteFile(policyPath, []byte(policyContent), 0644)
		require.NoError(t, err)

		// Wait for auto-reload
		time.Sleep(500 * time.Millisecond)

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

		err = watchedEngine.Start(ctx)
		require.NoError(t, err)
		defer watchedEngine.Stop()

		// Delete the policy file
		err = os.Remove(policyPath)
		require.NoError(t, err)

		// Wait for auto-unload
		time.Sleep(500 * time.Millisecond)

		// Verify policy was unloaded
		_, err = engine.GetPolicy("deletable")
		require.Error(t, err)

		var notFoundErr ErrPolicyNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})
}

func TestFileWatcher_Debouncing(t *testing.T) {
	t.Run("debounces rapid file changes", func(t *testing.T) {
		tmpDir := t.TempDir()
		watcher, err := NewFileWatcher(tmpDir)
		require.NoError(t, err)

		var mu sync.Mutex
		callCount := 0

		watcher.OnPolicyChange(func(name string, content []byte, deleted bool) {
			mu.Lock()
			callCount++
			mu.Unlock()
		})

		ctx := context.Background()
		err = watcher.Start(ctx)
		require.NoError(t, err)
		defer watcher.Stop()

		// Make rapid changes to same file
		policyPath := filepath.Join(tmpDir, "rapid.rego")
		for i := 0; i < 5; i++ {
			content := []byte(`package rapid
default allow = true
`)
			os.WriteFile(policyPath, content, 0644)
			time.Sleep(20 * time.Millisecond)
		}

		// Wait for debounce to settle
		time.Sleep(500 * time.Millisecond)

		mu.Lock()
		// Should have fewer calls than writes due to debouncing
		assert.LessOrEqual(t, callCount, 2)
		mu.Unlock()
	})
}
