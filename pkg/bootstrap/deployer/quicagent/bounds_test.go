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

package quicagent

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A source that keeps growing after its size was announced is cut at that
// size: the upload neither stalls on QUIC flow control nor mismatches.
func TestCopyFromGrowingSourceSendsAnnouncedSize(t *testing.T) {
	c := connectedPair(t)
	payload := make([]byte, 1<<20+5)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "staged.img")
	// rand.Reader never ends: without the cut the body would overrun.
	src := bytesThenEndless(payload)

	done := make(chan error, 1)
	go func() { done <- c.copyFrom(testCtx(t), src, int64(len(payload)), "growing.img", dst) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("copyFrom: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("copyFrom of a growing source stalled")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read copy: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("copy holds %d bytes, not the %d announced", len(got), len(payload))
	}
}

// A source that ends before its announced size fails with ErrSourceChanged
// and leaves no destination behind.
func TestCopyFromShrunkSourceFails(t *testing.T) {
	c := connectedPair(t)
	payload := make([]byte, 64<<10)
	dst := filepath.Join(t.TempDir(), "staged.img")
	err := c.copyFrom(testCtx(t), bytes.NewReader(payload[:len(payload)/2]), int64(len(payload)), "shrunk.img", dst)
	var changed ErrSourceChanged
	if !errors.As(err, &changed) {
		t.Fatalf("copyFrom err = %v; want ErrSourceChanged", err)
	}
	if changed.Sent != int64(len(payload)/2) || changed.Announced != int64(len(payload)) {
		t.Fatalf("ErrSourceChanged = %+v", changed)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("destination after a shrunk source: stat err = %v; want not exist", err)
	}
}

// An endless, verbose command is killed once its output passes the budget,
// and Run returns a bounded error instead of the output.
func TestRunEndlessOutputIsKilled(t *testing.T) {
	c := connectedPair(t)
	done := make(chan error, 1)
	go func() {
		_, err := c.Run(testCtx(t), "yes deploy-output-flood")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "output passed") {
			t.Fatalf("Run(yes) err = %v; want the output budget error", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Run of an endless command did not stop at the output budget")
	}
}

// The budget is shared by stdout and stderr, holds at most limit bytes,
// and cancels the command exactly once when passed.
func TestOutputBudgetBoundsBothStreams(t *testing.T) {
	cancels := 0
	b := &outputBudget{limit: 10, exceeded: func() { cancels++ }}
	var out, errOut bytes.Buffer
	so, se := b.writer(&out), b.writer(&errOut)
	if _, err := so.Write([]byte("123456")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := se.Write([]byte("7890")); err != nil {
		t.Fatalf("write to the limit: %v", err)
	}
	if b.over() {
		t.Fatalf("budget over at exactly the limit")
	}
	if _, err := se.Write([]byte("x")); err == nil {
		t.Fatalf("write past the limit succeeded")
	}
	if _, err := so.Write(make([]byte, 1<<20)); err == nil {
		t.Fatalf("write after the budget was passed succeeded")
	}
	if !b.over() || cancels != 1 {
		t.Fatalf("over = %v, cancels = %d; want true, 1", b.over(), cancels)
	}
	if out.Len()+errOut.Len() != 10 {
		t.Fatalf("buffered %d bytes; want 10", out.Len()+errOut.Len())
	}
}

func bytesThenEndless(p []byte) *endlessReader {
	return &endlessReader{head: bytes.NewReader(p)}
}

// endlessReader yields head and then random bytes for ever, like a file
// appended to faster than it is read.
type endlessReader struct{ head *bytes.Reader }

func (r *endlessReader) Read(p []byte) (int, error) {
	if r.head.Len() > 0 {
		return r.head.Read(p)
	}
	return rand.Read(p)
}
