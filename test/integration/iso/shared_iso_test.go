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

//go:build integration

package iso

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDownloader is an ISOCommands whose Download fails on the calls named
// in fail (0-based) and otherwise writes a stand-in ISO at
// alpineISOPath(opts.WorkDir). Every other method panics through the nil
// embedded interface.
type fakeDownloader struct {
	ISOCommands
	fail  map[int]bool
	calls []DownloadOptions
}

func (f *fakeDownloader) Download(_ context.Context, opts DownloadOptions) (*DownloadResult, error) {
	n := len(f.calls)
	f.calls = append(f.calls, opts)
	if f.fail[n] {
		return nil, fmt.Errorf("fake download %d from %s failed", n, opts.Mirror)
	}
	p := alpineISOPath(opts.WorkDir)
	if err := os.WriteFile(p, []byte("iso"), 0o600); err != nil {
		return nil, err
	}
	return &DownloadResult{Success: true, ISOPath: p, Verified: true}, nil
}

// fatalTB records a Fatalf and ends the calling goroutine, as testing.T does.
type fatalTB struct {
	testing.TB
	fatal string
}

func (f *fatalTB) Fatalf(format string, args ...any) {
	f.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func newSharedISO(t *testing.T) *sharedISO {
	s := &sharedISO{}
	t.Cleanup(func() {
		if s.dir != "" {
			_ = os.RemoveAll(s.dir)
		}
	})
	return s
}

func assertDefaultDownload(t *testing.T, opts DownloadOptions, mirror string) {
	t.Helper()
	assert.Equal(t, mirror, opts.Mirror)
	assert.True(t, opts.Verify, "the checksum is verified on %s", mirror)
	assert.Equal(t, DefaultAlpineVersion, opts.Version)
	assert.Equal(t, DefaultArch, opts.Arch)
}

func TestSharedISO_FallbackMirrorServesWhenPrimaryFails(t *testing.T) {
	s := newSharedISO(t)
	fake := &fakeDownloader{fail: map[int]bool{0: true}}

	iso := s.get(t, context.Background(), fake)

	require.Len(t, fake.calls, 2)
	assertDefaultDownload(t, fake.calls[0], DefaultMirror)
	assertDefaultDownload(t, fake.calls[1], FallbackMirror)
	assert.Equal(t, alpineISOPath(s.dir), iso)
	assert.True(t, FileExists(iso), "the fallback download created %s", iso)

	t.Run("second get reuses the fixture", func(t *testing.T) {
		again := s.get(t, context.Background(), fake)
		assert.Equal(t, iso, again)
		assert.Len(t, fake.calls, 2, "no further download")
	})
}

func TestSharedISO_BothMirrorsFail(t *testing.T) {
	s := newSharedISO(t)
	fake := &fakeDownloader{fail: map[int]bool{0: true, 1: true}}
	tb := &fatalTB{TB: t}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.get(tb, context.Background(), fake)
	}()
	<-done

	require.Len(t, fake.calls, 2)
	assert.Contains(t, tb.fatal, "missing prerequisite")
	assert.Contains(t, tb.fatal, DefaultMirror+": fake download 0 from "+DefaultMirror+" failed")
	assert.Contains(t, tb.fatal, FallbackMirror+": fake download 1 from "+FallbackMirror+" failed")
	assert.Equal(t, 2, countWrapped(s.err), "both mirrors' errors are wrapped")
}

func TestSharedISO_PrimaryServes(t *testing.T) {
	s := newSharedISO(t)
	fake := &fakeDownloader{}

	iso := s.get(t, context.Background(), fake)

	require.Len(t, fake.calls, 1)
	assertDefaultDownload(t, fake.calls[0], DefaultMirror)
	assert.True(t, FileExists(iso))
}

// countWrapped returns how many errors err wraps directly.
func countWrapped(err error) int {
	var multi interface{ Unwrap() []error }
	if errors.As(err, &multi) {
		return len(multi.Unwrap())
	}
	return 0
}
