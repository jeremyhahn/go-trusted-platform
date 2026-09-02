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

package bootstrap

import (
	"context"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

const (
	// consoleTranscriptMaxBytes bounds the transcript held in memory for
	// one boot attempt. A boot through the installer's log upload is tens
	// of kilobytes; when the bound is exceeded the oldest half is dropped,
	// so the end of the transcript — the part that says where the boot
	// stopped — is always kept.
	consoleTranscriptMaxBytes = 1 << 20

	// consoleTailLines is how many transcript lines ride in an error.
	consoleTailLines = 40

	// consoleReadChunk is the buffer one SOLSession.Read fills. A SOL
	// packet carries at most the BMC's outbound payload size (well under
	// this), and Read drops whatever does not fit.
	consoleReadChunk = 64 * 1024
)

// ansiEscapeRE matches the CSI and two-byte escape sequences a firmware
// or installer console emits for colour and cursor movement; they are
// stripped from the tail quoted in an error, never from the uploaded
// transcript.
var ansiEscapeRE = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[\x20-\x2f]*[\x40-\x7e]|[\x40-\x5f])`)

// ConsoleTranscript is what the host wrote to its serial console, over
// the board controller's Serial-over-LAN, during one boot attempt — as
// far as it could be captured. It is the diagnostic that rides in
// ErrInstallLogNotFound.
//
// BIOS POST is not redirected to SOL on the boards this platform runs on
// (verified silent on COM1 and COM2 through a full POST on the mini
// fleet, 2026-08-29), so the transcript starts with the first thing the
// OS — the installer's kernel, or an on-disk system — prints. A silent
// transcript therefore means the host never reached an OS, or the BIOS
// has console redirection disabled; it never means "booted from disk".
type ConsoleTranscript struct {
	// URL is where the full transcript was stored on the bootstrap
	// container's install sink; empty when nothing was captured or the
	// upload failed.
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
	// Bytes is how much console output was captured.
	Bytes int `json:"bytes" yaml:"bytes"`
	// Tail is the last consoleTailLines non-empty lines, with terminal
	// escape sequences removed.
	Tail []string `json:"tail,omitempty" yaml:"tail,omitempty"`
	// Error records why there is no transcript, or why the one captured
	// could not be uploaded.
	Error string `json:"error,omitempty" yaml:"error,omitempty"`
}

// Summary renders the transcript for an error message: where it is and
// what it ends with, or why there is none — and, for a silent console,
// what silence means on this hardware.
func (c *ConsoleTranscript) Summary() string {
	if c == nil {
		return "console transcript not captured"
	}
	if c.Bytes == 0 {
		if c.Error != "" {
			return "console transcript not captured: " + c.Error
		}
		return "console silent for the whole window — BIOS POST is not redirected to SOL on this hardware, so the firmware halted before the OS, or console redirection is disabled in BIOS"
	}
	var b strings.Builder
	if c.URL != "" {
		b.WriteString("console transcript: " + c.URL)
	} else {
		b.WriteString("console transcript captured (" + strconv.Itoa(c.Bytes) + " bytes)")
	}
	if c.Error != "" {
		b.WriteString(" [upload failed: " + c.Error + "]")
	}
	if len(c.Tail) > 0 {
		b.WriteString("; last " + strconv.Itoa(len(c.Tail)) + " lines:\n")
		b.WriteString(strings.Join(c.Tail, "\n"))
	}
	return b.String()
}

// consoleTail returns the last n non-empty lines of a console
// transcript with carriage returns, terminal escape sequences and other
// control characters removed.
func consoleTail(transcript []byte, n int) []string {
	clean := ansiEscapeRE.ReplaceAll(transcript, nil)
	lines := strings.Split(string(clean), "\n")
	tail := make([]string, 0, n)
	for i := len(lines) - 1; i >= 0 && len(tail) < n; i-- {
		line := strings.TrimRightFunc(strings.Map(dropControl, lines[i]), unicode.IsSpace)
		if line == "" {
			continue
		}
		tail = append(tail, line)
	}
	for i, j := 0, len(tail)-1; i < j; i, j = i+1, j-1 {
		tail[i], tail[j] = tail[j], tail[i]
	}
	return tail
}

// dropControl maps control characters other than tab to -1 (removed) for
// strings.Map.
func dropControl(r rune) rune {
	if r == '\t' {
		return r
	}
	if unicode.IsControl(r) || r == unicode.ReplacementChar {
		return -1
	}
	return r
}

// consoleOpener opens a host's serial console for the duration of a
// boot attempt. The orchestrator's default is openSOLConsole; tests
// substitute a reader they control.
type consoleOpener func(ctx context.Context, cfg *bmc.Config) (io.ReadCloser, error)

// openSOLConsole activates SOL on a BMC client of its own. The SOL
// receive loop takes over the client's RMCP+ socket (it rebinds to the
// SOL port and consumes every packet), so the console can never share
// the client the power and boot commands go through.
func (o *Orchestrator) openSOLConsole(ctx context.Context, cfg *bmc.Config) (io.ReadCloser, error) {
	client, err := o.bmcFactory.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	sol, err := client.Console(ctx)
	if err != nil {
		client.Close()
		return nil, err
	}
	return &solConsole{sol: sol, client: client}, nil
}

// solConsole is an open SOL session and the client it was activated on;
// closing it deactivates the payload and releases the client.
type solConsole struct {
	sol    *bmc.SOLSession
	client bmc.Client
}

func (s *solConsole) Read(p []byte) (int, error) { return s.sol.Read(p) }

// Close deactivates SOL and closes the client. Closing the client is
// what unblocks the session's receive loop, so both always run.
func (s *solConsole) Close() error {
	solErr := s.sol.Close()
	clientErr := s.client.Close()
	if solErr != nil {
		return solErr
	}
	return clientErr
}

// consoleRecorder streams one console into a bounded buffer for the life
// of a boot attempt. A recorder whose console could not be opened is
// still a valid recorder: it records nothing and reports why.
type consoleRecorder struct {
	console io.ReadCloser
	openErr string

	mu  sync.Mutex
	buf []byte

	// done is closed when the reading goroutine has exited; stopOnce
	// guards the close of the console that makes it exit.
	done     chan struct{}
	stopOnce sync.Once
}

// startConsoleTranscript opens the node's console and starts recording.
// It never fails: a console that cannot be opened is logged at WARN and
// the attempt continues without a transcript.
func (o *Orchestrator) startConsoleTranscript(ctx context.Context, cfg *bmc.Config, hostname string) *consoleRecorder {
	open := o.consoleOpener
	if open == nil {
		open = o.openSOLConsole
	}
	rec := &consoleRecorder{done: make(chan struct{})}
	console, err := open(ctx, cfg)
	if err != nil {
		rec.openErr = err.Error()
		close(rec.done)
		o.logger.Warn("bootstrap: virtual-media: console transcript unavailable; continuing without it",
			slog.String("hostname", hostname),
			slog.String("error", err.Error()))
		return rec
	}
	rec.console = console
	go rec.record()
	return rec
}

// record copies the console into the buffer until the console reports
// an error, which is how a closed SOL session ends.
func (r *consoleRecorder) record() {
	defer close(r.done)
	chunk := make([]byte, consoleReadChunk)
	for {
		n, err := r.console.Read(chunk)
		if n > 0 {
			r.append(chunk[:n])
		}
		if err != nil {
			return
		}
	}
}

// append adds console bytes, dropping the oldest half of the buffer
// once the bound is exceeded.
func (r *consoleRecorder) append(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, b...)
	if len(r.buf) > consoleTranscriptMaxBytes {
		keep := r.buf[len(r.buf)-consoleTranscriptMaxBytes/2:]
		r.buf = append(make([]byte, 0, consoleTranscriptMaxBytes), keep...)
	}
}

// stop closes the console and waits for the reader to drain. Safe to
// call more than once.
func (r *consoleRecorder) stop() {
	r.stopOnce.Do(func() {
		if r.console != nil {
			r.console.Close()
		}
	})
	<-r.done
}

// transcript returns a copy of everything recorded so far.
func (r *consoleRecorder) transcript() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}

// finish stops recording, uploads the transcript to the sink as
// /installs/<host>/console-attempt<N>.log when there is one, and
// returns the diagnostic. Every step is best-effort: the result explains
// what is missing, and the caller's error stands on its own without it.
// The upload runs on its own context, detached from the attempt's: the
// transcript is a forensic artifact for exactly the case where that
// context has expired, and inheriting it made every upload die with
// "context deadline exceeded" at the moment it mattered (#126). The
// detached context carries the whole upload budget — every attempt and
// the pauses between them — because one attempt is not enough (#136).
func (o *Orchestrator) finishConsoleTranscript(rec *consoleRecorder, installURL, hostname string, attempt int) *ConsoleTranscript {
	rec.stop()
	out := &ConsoleTranscript{Error: rec.openErr}
	data := rec.transcript()
	out.Bytes = len(data)
	if out.Bytes == 0 {
		return out
	}
	out.Tail = consoleTail(data, consoleTailLines)
	uploadCtx, cancel := context.WithTimeout(context.Background(), forensicUploadBudget)
	defer cancel()
	filename := "console-attempt" + strconv.Itoa(attempt) + ".log"
	uploaded, err := o.uploadForensic(uploadCtx, installURL, hostname, filename, data, "text/plain; charset=utf-8")
	if err != nil {
		out.Error = err.Error()
		o.logger.Warn("bootstrap: virtual-media: console transcript upload failed",
			slog.String("hostname", hostname),
			slog.Int("attempt", attempt),
			slog.Int("bytes", out.Bytes),
			slog.String("url", "PUT "+installURL+"/installs/"+sanitizeHostnameForInstallPath(hostname)+"/"+filename),
			slog.String("error", err.Error()))
		return out
	}
	out.URL = uploaded
	o.logger.Info("bootstrap: virtual-media: console transcript uploaded",
		slog.String("hostname", hostname),
		slog.Int("attempt", attempt),
		slog.Int("bytes", out.Bytes),
		slog.String("url", uploaded))
	return out
}
