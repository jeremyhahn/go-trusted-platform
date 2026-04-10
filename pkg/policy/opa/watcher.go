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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	// debounceInterval is the time to wait before processing file changes.
	debounceInterval = 100 * time.Millisecond
)

// FileWatcher implements the PolicyWatcher interface using fsnotify.
type FileWatcher struct {
	watchDir  string
	watcher   *fsnotify.Watcher
	running   atomic.Bool
	callbacks []func(name string, content []byte, deleted bool)
	mu        sync.RWMutex
	done      chan struct{}
	wg        sync.WaitGroup

	// Debouncing
	pendingChanges map[string]time.Time
	debounceMu     sync.Mutex
}

// NewFileWatcher creates a new file watcher for the specified directory.
func NewFileWatcher(watchDir string) (*FileWatcher, error) {
	if watchDir == "" {
		return nil, ErrPolicyDirNotFound{Path: ""}
	}

	info, err := os.Stat(watchDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrPolicyDirNotFound{Path: watchDir}
		}
		return nil, ErrWatcherFailed{Reason: err.Error()}
	}

	if !info.IsDir() {
		return nil, ErrPolicyDirNotFound{Path: watchDir}
	}

	return &FileWatcher{
		watchDir:       watchDir,
		callbacks:      make([]func(name string, content []byte, deleted bool), 0),
		done:           make(chan struct{}),
		pendingChanges: make(map[string]time.Time),
	}, nil
}

// Start begins watching for policy file changes.
func (w *FileWatcher) Start(ctx context.Context) error {
	if w.running.Load() {
		return ErrWatcherAlreadyStarted{}
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return ErrWatcherFailed{Reason: err.Error()}
	}

	if err := watcher.Add(w.watchDir); err != nil {
		watcher.Close()
		return ErrWatcherFailed{Reason: err.Error()}
	}

	w.watcher = watcher
	w.done = make(chan struct{})
	w.running.Store(true)

	// Start the event processing goroutine
	w.wg.Add(1)
	go w.processEvents(ctx)

	// Start the debounce processor
	w.wg.Add(1)
	go w.processDebouncedChanges(ctx)

	return nil
}

// Stop stops watching for policy file changes.
func (w *FileWatcher) Stop() error {
	if !w.running.Load() {
		return ErrWatcherNotStarted{}
	}

	w.running.Store(false)
	close(w.done)

	if w.watcher != nil {
		w.watcher.Close()
	}

	w.wg.Wait()
	return nil
}

// OnPolicyChange registers a callback for policy change events.
func (w *FileWatcher) OnPolicyChange(callback func(name string, content []byte, deleted bool)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks = append(w.callbacks, callback)
}

// IsRunning returns whether the watcher is currently running.
func (w *FileWatcher) IsRunning() bool {
	return w.running.Load()
}

// processEvents handles fsnotify events.
func (w *FileWatcher) processEvents(ctx context.Context) {
	defer w.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			// Log error but continue watching
			_ = err
		}
	}
}

// handleEvent processes a single fsnotify event.
func (w *FileWatcher) handleEvent(event fsnotify.Event) {
	// Only process .rego files
	if !strings.HasSuffix(event.Name, regoFileExtension) {
		return
	}

	// Schedule for debounced processing
	w.debounceMu.Lock()
	w.pendingChanges[event.Name] = time.Now()
	w.debounceMu.Unlock()
}

// processDebouncedChanges processes file changes after debouncing.
func (w *FileWatcher) processDebouncedChanges(ctx context.Context) {
	defer w.wg.Done()

	ticker := time.NewTicker(debounceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.done:
			return
		case <-ticker.C:
			w.processPendingChanges()
		}
	}
}

// processPendingChanges processes any pending file changes.
func (w *FileWatcher) processPendingChanges() {
	now := time.Now()

	w.debounceMu.Lock()
	toProcess := make(map[string]struct{})
	for path, timestamp := range w.pendingChanges {
		if now.Sub(timestamp) >= debounceInterval {
			toProcess[path] = struct{}{}
			delete(w.pendingChanges, path)
		}
	}
	w.debounceMu.Unlock()

	for path := range toProcess {
		w.notifyChange(path)
	}
}

// notifyChange reads the file and notifies all callbacks.
func (w *FileWatcher) notifyChange(path string) {
	name := strings.TrimSuffix(filepath.Base(path), regoFileExtension)

	// Check if file exists
	_, err := os.Stat(path)
	deleted := os.IsNotExist(err)

	var content []byte
	if !deleted {
		content, err = os.ReadFile(path)
		if err != nil {
			// File might have been deleted between stat and read
			if os.IsNotExist(err) {
				deleted = true
			} else {
				return // Can't read file, skip
			}
		}
	}

	w.mu.RLock()
	callbacks := make([]func(string, []byte, bool), len(w.callbacks))
	copy(callbacks, w.callbacks)
	w.mu.RUnlock()

	for _, callback := range callbacks {
		callback(name, content, deleted)
	}
}

// WatchedEngine wraps an OPAEngine with automatic policy reloading.
type WatchedEngine struct {
	engine  *OPAEngine
	watcher *FileWatcher
	mu      sync.RWMutex
}

// NewWatchedEngine creates a new engine that automatically reloads policies on file changes.
func NewWatchedEngine(engine *OPAEngine, watchDir string) (*WatchedEngine, error) {
	watcher, err := NewFileWatcher(watchDir)
	if err != nil {
		return nil, err
	}

	we := &WatchedEngine{
		engine:  engine,
		watcher: watcher,
	}

	watcher.OnPolicyChange(we.handlePolicyChange)

	return we, nil
}

// Start begins watching for policy changes.
func (we *WatchedEngine) Start(ctx context.Context) error {
	return we.watcher.Start(ctx)
}

// Stop stops watching for policy changes.
func (we *WatchedEngine) Stop() error {
	return we.watcher.Stop()
}

// Engine returns the underlying OPA engine.
func (we *WatchedEngine) Engine() *OPAEngine {
	we.mu.RLock()
	defer we.mu.RUnlock()
	return we.engine
}

// handlePolicyChange handles policy file change events.
func (we *WatchedEngine) handlePolicyChange(name string, content []byte, deleted bool) {
	we.mu.Lock()
	defer we.mu.Unlock()

	ctx := context.Background()

	if deleted {
		we.engine.UnloadPolicy(ctx, name)
		return
	}

	// Try to load/update the policy
	we.engine.UnloadPolicy(ctx, name)
	we.engine.LoadPolicy(ctx, name, content)
}
