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

package jsonfile

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// levelNames spells the platform's custom slog levels the way Filter and
// the console Logs page read them. slog names an unregistered level as an
// offset from the nearest standard one ("ERROR+12"), which would rank as
// INFO under a level filter and render as an unknown level.
var levelNames = map[slog.Level]string{
	logging.LevelFatal:    "FATAL",
	logging.LevelSecurity: "SECURITY",
}

// levelName returns the on-disk name of a record level.
func levelName(level slog.Level) string {
	if name, ok := levelNames[level]; ok {
		return name
	}
	return level.String()
}

// Options configures a JSON-lines file handler.
type Options struct {
	// Dir is the directory holding <service>.jsonl plus rotated history.
	Dir string

	// Service is the logical service name. It becomes the file basename
	// and is emitted as the "service" attribute on every record so
	// downstream consumers can demultiplex when files share storage.
	Service string

	// Level is the minimum slog level written.
	Level slog.Level

	// MaxSize caps the active file in bytes before rotation. Zero
	// disables size-based rotation (still time-rotated by the daemon's
	// configured policy if any).
	MaxSize int64

	// MaxFiles caps the number of rotated history files kept; older
	// files are deleted. Zero keeps everything.
	MaxFiles int

	// MaxAge caps how long rotated files are retained. Zero keeps
	// everything until MaxFiles culls them.
	MaxAge time.Duration

	// SubscriberBuffer is the channel buffer size handed to each
	// Subscribe caller. Default 256.
	SubscriberBuffer int

	// Inner is the optional fan-out handler. When set, every Handle
	// call is also forwarded so the existing stderr / stdout logger
	// behavior is preserved. Slog already supports this via
	// slog.NewMultiHandler-style composition, but accepting one inline
	// avoids wiring a separate multi handler in every caller.
	Inner slog.Handler
}

// Handler is a slog.Handler that writes JSON-lines to a rotated file
// and fans live records out to in-memory subscribers for tail / stream
// callers. It also exposes Query for offline scans of the rotated
// history.
type Handler struct {
	opts    Options
	service string
	dir     string
	out     *output
	attrs   []slog.Attr
	group   string
}

// output holds the mutable file + subscriber state shared by every
// Handler clone produced via WithAttrs / WithGroup. It lives behind a
// pointer so cloning a Handler never copies its locks — all clones
// write through the same mutex to the same file and fan out to the
// same subscriber set.
type output struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
	written  int64
	subsMu   sync.RWMutex
	subs     map[uint64]chan []byte
	nextID   atomic.Uint64
}

// NewHandler opens (or creates) the active JSON-lines file for
// opts.Service. It does not pre-create the directory if missing —
// callers configure where the platform writes logs and creating the
// directory there is their responsibility, the same way slog.JSONHandler
// is.
func NewHandler(opts Options) (*Handler, error) {
	if opts.Dir == "" {
		return nil, ErrInvalidConfig{Field: "Dir", Reason: "cannot be empty"}
	}
	if opts.Service == "" {
		return nil, ErrInvalidConfig{Field: "Service", Reason: "cannot be empty"}
	}
	if opts.SubscriberBuffer <= 0 {
		opts.SubscriberBuffer = 256
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, ErrIO{Op: "mkdir", Path: opts.Dir, Err: err}
	}
	h := &Handler{
		opts:    opts,
		service: opts.Service,
		dir:     opts.Dir,
		out:     &output{subs: make(map[uint64]chan []byte)},
	}
	if err := h.openActive(); err != nil {
		return nil, err
	}
	return h, nil
}

// activePath returns the path of the live file.
func (h *Handler) activePath() string {
	return filepath.Join(h.dir, h.service+".jsonl")
}

// openActive opens (or creates) the live file and seeks to EOF so
// existing content survives a restart.
func (h *Handler) openActive() error {
	p := h.activePath()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return ErrIO{Op: "open", Path: p, Err: err}
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return ErrIO{Op: "stat", Path: p, Err: err}
	}
	h.out.file = f
	h.out.filePath = p
	h.out.written = st.Size()
	return nil
}

// Enabled returns true if the handler is enabled for the given level.
func (h *Handler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.opts.Level
}

// WithAttrs returns a new Handler whose records carry the supplied
// attrs. The underlying file + subscribers are shared.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append([]slog.Attr(nil), h.attrs...)
	cp.attrs = append(cp.attrs, attrs...)
	if h.opts.Inner != nil {
		cp.opts.Inner = h.opts.Inner.WithAttrs(attrs)
	}
	return &cp
}

// WithGroup returns a new Handler whose records group subsequent attrs
// under the supplied name.
func (h *Handler) WithGroup(name string) slog.Handler {
	cp := *h
	if cp.group == "" {
		cp.group = name
	} else {
		cp.group = cp.group + "." + name
	}
	if h.opts.Inner != nil {
		cp.opts.Inner = h.opts.Inner.WithGroup(name)
	}
	return &cp
}

// Handle writes the record as JSON-lines, rotates if needed, fans out
// to live subscribers, and forwards to the inner handler if any.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	if err := encodeRecord(buf, r, h.service, h.attrs, h.group); err != nil {
		return err
	}
	line := buf.Bytes()

	h.out.mu.Lock()
	if h.opts.MaxSize > 0 && h.out.written+int64(len(line)) > h.opts.MaxSize {
		if err := h.rotateLocked(); err != nil {
			h.out.mu.Unlock()
			return err
		}
	}
	n, err := h.out.file.Write(line)
	if err == nil {
		h.out.written += int64(n)
	}
	h.out.mu.Unlock()
	if err != nil {
		return ErrIO{Op: "write", Path: h.out.filePath, Err: err}
	}

	// Fan-out without holding the file mutex.
	h.broadcast(line)

	if h.opts.Inner != nil {
		// Fire-and-forget; inner handler failures must not poison the
		// primary file path. The platform's existing stderr handler
		// never returns an error.
		_ = h.opts.Inner.Handle(ctx, r)
	}
	return nil
}

// rotateLocked must be called with h.out.mu held.
func (h *Handler) rotateLocked() error {
	if h.out.file == nil {
		return nil
	}
	if err := h.out.file.Close(); err != nil {
		return ErrIO{Op: "close", Path: h.out.filePath, Err: err}
	}
	// Include nanoseconds so multiple rotations within the same wall
	// second don't collide on rename. Format chosen to sort
	// lexicographically by mod time for the cull pass.
	ts := time.Now().UTC().Format("20060102T150405.000000000Z")
	target := filepath.Join(h.dir, h.service+".jsonl."+ts)
	if err := os.Rename(h.out.filePath, target); err != nil {
		return ErrIO{Op: "rotate", Path: h.out.filePath, Err: err}
	}
	if err := h.openActive(); err != nil {
		return err
	}
	h.cullLocked()
	return nil
}

// rotatedFile captures a rotated history file plus its mtime for the
// cull pass. Declared at package scope so the helper method can name
// it in its signature.
type rotatedFile struct {
	path string
	mod  time.Time
}

// cullLocked applies MaxFiles / MaxAge to rotated history. Must be
// called with h.out.mu held.
func (h *Handler) cullLocked() {
	if h.opts.MaxFiles <= 0 && h.opts.MaxAge <= 0 {
		return
	}
	entries, err := os.ReadDir(h.dir)
	if err != nil {
		return
	}
	prefix := h.service + ".jsonl."
	var rs []rotatedFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rs = append(rs, rotatedFile{filepath.Join(h.dir, name), info.ModTime()})
	}
	// Oldest first.
	for i := 0; i < len(rs); i++ {
		for j := i + 1; j < len(rs); j++ {
			if rs[j].mod.Before(rs[i].mod) {
				rs[i], rs[j] = rs[j], rs[i]
			}
		}
	}
	now := time.Now()
	for _, r := range rs {
		drop := false
		if h.opts.MaxAge > 0 && now.Sub(r.mod) > h.opts.MaxAge {
			drop = true
		}
		if !drop && h.opts.MaxFiles > 0 && len(rs)-h.numKeptAbove(rs, r) > h.opts.MaxFiles {
			drop = true
		}
		if drop {
			_ = os.Remove(r.path)
		}
	}
}

// numKeptAbove counts entries with mod >= r.mod inclusive — used to
// keep the N newest. Avoids importing sort just for this tiny case.
func (h *Handler) numKeptAbove(rs []rotatedFile, r rotatedFile) int {
	cnt := 0
	for _, x := range rs {
		if !x.mod.Before(r.mod) {
			cnt++
		}
	}
	return cnt
}

// Close flushes and closes the underlying file. After Close, the
// handler is unusable.
func (h *Handler) Close() error {
	h.out.mu.Lock()
	defer h.out.mu.Unlock()
	if h.out.file == nil {
		return nil
	}
	err := h.out.file.Close()
	h.out.file = nil
	return err
}

// Subscribe registers a new live subscriber. The returned channel
// receives raw JSON-line bytes including the trailing newline. The
// unsubscribe func MUST be called when the subscriber is done; it is
// safe to call more than once.
func (h *Handler) Subscribe() (<-chan []byte, func()) {
	id := h.out.nextID.Add(1)
	ch := make(chan []byte, h.opts.SubscriberBuffer)
	h.out.subsMu.Lock()
	h.out.subs[id] = ch
	h.out.subsMu.Unlock()
	once := sync.Once{}
	return ch, func() {
		once.Do(func() {
			h.out.subsMu.Lock()
			delete(h.out.subs, id)
			h.out.subsMu.Unlock()
			close(ch)
		})
	}
}

// broadcast sends the line to every live subscriber. Slow subscribers
// drop oldest behavior: if the buffer is full we drop the new line
// for that subscriber rather than block, so a stalled WebUI tab can't
// stall production logging.
func (h *Handler) broadcast(line []byte) {
	cp := make([]byte, len(line))
	copy(cp, line)
	h.out.subsMu.RLock()
	defer h.out.subsMu.RUnlock()
	for _, ch := range h.out.subs {
		select {
		case ch <- cp:
		default:
		}
	}
}

// encodeRecord writes a single JSON object representing the record
// followed by a newline. We do not delegate to slog.JSONHandler so
// that the wire shape stays under our control — "service" is always
// the first attribute, attrs are nested under an "attrs" object, and
// the timestamp is RFC3339 with nanoseconds.
//
// A "service" attribute on the record (or in baseAttrs from a
// WithAttrs chain) overrides the handler's default service name, so
// subsystem code that does `logger.With("service","ca")` lands the
// per-call service under "ca" in the on-disk shape.
func encodeRecord(buf *bytes.Buffer, r slog.Record, service string, baseAttrs []slog.Attr, group string) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)

	attrs := make(map[string]any, len(baseAttrs)+r.NumAttrs())
	for _, a := range baseAttrs {
		mergeAttr(attrs, a, group)
	}
	r.Attrs(func(a slog.Attr) bool {
		mergeAttr(attrs, a, group)
		return true
	})

	effectiveService := service
	if v, ok := attrs["service"].(string); ok && v != "" {
		effectiveService = v
		delete(attrs, "service")
	}

	obj := map[string]any{
		"time":    r.Time.UTC().Format(time.RFC3339Nano),
		"level":   levelName(r.Level),
		"msg":     r.Message,
		"service": effectiveService,
	}
	if src, ok := attrs["source"].(string); ok && src != "" {
		obj["source"] = src
		delete(attrs, "source")
	}
	if len(attrs) > 0 {
		obj["attrs"] = attrs
	}
	return enc.Encode(obj)
}

// mergeAttr flattens a slog.Attr into the provided map, honoring
// group prefixing. Group names are dot-separated to keep the JSON
// shape predictable for downstream tooling.
func mergeAttr(dst map[string]any, a slog.Attr, group string) {
	if a.Key == "" {
		return
	}
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	v := a.Value.Resolve()
	switch v.Kind() {
	case slog.KindGroup:
		inner := map[string]any{}
		sub := key
		for _, ga := range v.Group() {
			mergeAttr(inner, ga, sub)
		}
		dst[key] = inner
	default:
		dst[key] = v.Any()
	}
}
