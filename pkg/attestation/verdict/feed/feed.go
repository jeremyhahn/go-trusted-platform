// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package feed keeps the device verdicts platformd recorded most recently, so
// every transport can follow them from a cursor: gRPC as a server stream, and
// REST, QUIC and MCP by long-polling the same cursor.
//
// A follower never silently misses a verdict. A cursor older than the
// verdicts the feed still keeps, or from an earlier platformd run, is refused
// with ErrMissedVerdicts, and the follower starts again from now and re-reads
// what it missed elsewhere.
package feed

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

const (
	// DefaultCapacity is how many recent verdicts a feed keeps for its
	// followers.
	DefaultCapacity = 256

	// MaxWait is the longest one poll waits for a verdict. It stays under the
	// 30-second request timeouts of the REST, QUIC and MCP servers.
	MaxWait = 20 * time.Second

	// PlatformTenantID is the system tenant firstboot creates and the
	// platform operates as. A principal of this tenant sees the verdicts of
	// every device.
	PlatformTenantID = "system"
)

// ErrClosed is returned once the feed is closed: platformd is shutting down.
type ErrClosed struct{}

func (ErrClosed) Error() string {
	return "attestation: the device verdict feed is closed"
}

// ErrMissedVerdicts is returned for a cursor the feed can no longer serve
// without a gap: it is older than every verdict the feed keeps, or it comes
// from an earlier platformd run.
type ErrMissedVerdicts struct{}

func (ErrMissedVerdicts) Error() string {
	return "attestation: the device verdict follower fell behind and missed verdicts"
}

// ErrInvalidCursor is returned for a cursor this feed never handed out.
type ErrInvalidCursor struct {
	Cursor string
	Reason string
}

func (e ErrInvalidCursor) Error() string {
	return "attestation: invalid device verdict cursor " + strconv.Quote(e.Cursor) + ": " + e.Reason
}

// Audience is the set of tenants whose device verdicts a follower may see.
type Audience struct {
	tenantID    string
	everyTenant bool
}

// EveryTenant is the audience of infrastructure that acts on every device,
// such as an overlay gateway.
func EveryTenant() Audience {
	return Audience{everyTenant: true}
}

// Tenant is the audience of a principal of tenantID: that tenant's devices,
// or every device for the system tenant. An empty tenant sees nothing.
func Tenant(tenantID string) Audience {
	if tenantID == PlatformTenantID {
		return EveryTenant()
	}
	return Audience{tenantID: tenantID}
}

// Admits reports whether a verdict on a device of tenantID may reach the
// audience. A device with no tenant is the platform's own and reaches only
// audiences that see every tenant.
func (a Audience) Admits(tenantID string) bool {
	return a.everyTenant || (tenantID != "" && tenantID == a.tenantID)
}

// Cursor is a follower's position in a feed. The zero cursor means "from
// now on".
type Cursor struct {
	epoch    uint64
	position uint64
}

// IsZero reports whether the cursor is the zero cursor.
func (c Cursor) IsZero() bool {
	return c.epoch == 0
}

// String renders the cursor for the wire; the zero cursor is empty.
func (c Cursor) String() string {
	if c.IsZero() {
		return ""
	}
	return strconv.FormatUint(c.epoch, 16) + "." + strconv.FormatUint(c.position, 10)
}

// ParseCursor reads a cursor from the wire. The empty string is the zero
// cursor.
func ParseCursor(raw string) (Cursor, error) {
	if raw == "" {
		return Cursor{}, nil
	}
	epochText, positionText, found := strings.Cut(raw, ".")
	if !found {
		return Cursor{}, ErrInvalidCursor{Cursor: raw, Reason: "want <epoch>.<position>"}
	}
	epoch, err := strconv.ParseUint(epochText, 16, 64)
	if err != nil || epoch == 0 {
		return Cursor{}, ErrInvalidCursor{Cursor: raw, Reason: "malformed epoch"}
	}
	position, err := strconv.ParseUint(positionText, 10, 64)
	if err != nil {
		return Cursor{}, ErrInvalidCursor{Cursor: raw, Reason: "malformed position"}
	}
	return Cursor{epoch: epoch, position: position}, nil
}

// Page is the answer to one poll: the admitted verdicts in the order
// platformd recorded them, and the cursor to poll from next.
type Page struct {
	Verdicts []verdict.RecordedDeviceVerdict
	Next     Cursor
}

// ClampWait bounds a requested poll wait to [0, MaxWait].
func ClampWait(wait time.Duration) time.Duration {
	return min(max(wait, 0), MaxWait)
}

// Option configures a Feed.
type Option func(*Feed)

// WithCapacity sets how many recent verdicts the feed keeps.
func WithCapacity(capacity int) Option {
	return func(f *Feed) {
		if capacity > 0 {
			f.ring = make([]verdict.RecordedDeviceVerdict, capacity)
		}
	}
}

// WithOnFollow runs fn each time a follower takes the head cursor. Tests use
// it to record verdicts only once a follower will see them.
func WithOnFollow(fn func()) Option {
	return func(f *Feed) {
		f.onFollow = fn
	}
}

// lastEpoch keeps the epochs of the feeds in one process distinct.
var lastEpoch atomic.Uint64

// newEpoch returns an epoch no earlier feed in this process or earlier
// platformd run has used: the clock, nudged past the previous epoch.
func newEpoch() uint64 {
	for {
		previous := lastEpoch.Load()
		epoch := max(uint64(time.Now().UnixNano()), previous+1)
		if lastEpoch.CompareAndSwap(previous, epoch) {
			return epoch
		}
	}
}

// Feed keeps the most recent device verdicts in a ring and serves them to
// followers by cursor. It is a verdict.Observer: the attestation service
// calls it synchronously, and it never blocks there.
type Feed struct {
	mu     sync.Mutex
	epoch  uint64
	ring   []verdict.RecordedDeviceVerdict
	head   uint64 // position of the next verdict recorded
	wake   chan struct{}
	closed bool
	done   chan struct{}

	onFollow func()
}

// New returns an empty feed.
func New(opts ...Option) *Feed {
	f := &Feed{
		epoch: newEpoch(),
		ring:  make([]verdict.RecordedDeviceVerdict, DefaultCapacity),
		wake:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// OnDeviceVerdict implements verdict.Observer: it keeps the verdict and wakes
// every waiting poll.
func (f *Feed) OnDeviceVerdict(_ context.Context, recorded verdict.RecordedDeviceVerdict) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.ring[f.head%uint64(len(f.ring))] = recorded
	f.head++
	close(f.wake)
	f.wake = make(chan struct{})
}

// Follow returns the head cursor: a follower polling from it sees every
// verdict recorded from now on.
func (f *Feed) Follow() (Cursor, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return Cursor{}, ErrClosed{}
	}
	head := Cursor{epoch: f.epoch, position: f.head}
	f.mu.Unlock()
	if f.onFollow != nil {
		f.onFollow()
	}
	return head, nil
}

// Poll returns the verdicts after from that audience may see. With none yet,
// it waits up to wait for one; an expired wait is an empty page, not an
// error. The zero cursor returns the head cursor at once.
func (f *Feed) Poll(ctx context.Context, audience Audience, from Cursor, wait time.Duration) (Page, error) {
	if from.IsZero() {
		head, err := f.Follow()
		return Page{Next: head}, err
	}
	var expired <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		expired = timer.C
	}
	for {
		page, wake, err := f.read(audience, from)
		if err != nil || len(page.Verdicts) > 0 || expired == nil {
			return page, err
		}
		from = page.Next
		select {
		case <-ctx.Done():
			return Page{}, ctx.Err()
		case <-f.done:
			return Page{}, ErrClosed{}
		case <-expired:
			return page, nil
		case <-wake:
		}
	}
}

// read collects the admitted verdicts from from to the head, and returns the
// channel the next recorded verdict closes.
func (f *Feed) read(audience Audience, from Cursor) (Page, <-chan struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return Page{}, nil, ErrClosed{}
	}
	if from.epoch != f.epoch {
		return Page{}, nil, ErrMissedVerdicts{}
	}
	if from.position > f.head {
		return Page{}, nil, ErrInvalidCursor{Cursor: from.String(), Reason: "ahead of the feed"}
	}
	capacity := uint64(len(f.ring))
	if f.head-from.position > capacity {
		return Page{}, nil, ErrMissedVerdicts{}
	}
	var admitted []verdict.RecordedDeviceVerdict
	for position := from.position; position < f.head; position++ {
		recorded := f.ring[position%capacity]
		if audience.Admits(recorded.Verdict.TenantID) {
			admitted = append(admitted, recorded)
		}
	}
	return Page{Verdicts: admitted, Next: Cursor{epoch: f.epoch, position: f.head}}, f.wake, nil
}

// Close ends every waiting poll and refuses new ones. platformd closes the
// feed before it stops its servers, whose graceful stop waits for open
// streams to end.
func (f *Feed) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	close(f.done)
}
