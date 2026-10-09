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

package ipsec

import (
	"context"
	"log/slog"
	"time"
)

// Reconnect backoff bounds.
const (
	// MinBackoff is the wait before redialling charon after a session
	// ends, and the first wait after a failed dial.
	MinBackoff = 500 * time.Millisecond
	// MaxBackoff caps the wait, which doubles with every failed attempt.
	MaxBackoff = 30 * time.Second
)

// Runner keeps the controller attached to charon. It opens an event
// stream and a command session, attaches the controller, which pushes the
// identity, CRLs and connections, and checks every ike-updown event. When
// either connection ends it detaches, waits, and starts over, so a charon
// restart re-converges. The wait doubles from MinBackoff to MaxBackoff
// while attempts fail and starts again at MinBackoff after a session that
// attached.
type Runner struct {
	ctl    *Controller
	dialer Dialer
	logger *slog.Logger
	after  func(time.Duration) <-chan time.Time
}

// NewRunner builds a runner. A nil logger discards.
func NewRunner(ctl *Controller, dialer Dialer, logger *slog.Logger) (*Runner, error) {
	if ctl == nil || dialer == nil {
		return nil, ErrMissingDependency
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Runner{ctl: ctl, dialer: dialer, logger: logger, after: time.After}, nil
}

// Run keeps the controller attached until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	backoff := MinBackoff
	for {
		attached, err := r.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if attached {
			backoff = MinBackoff
		}
		r.logger.Warn("ipsec: charon session ended", "error", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-r.after(backoff):
		}
		backoff = min(2*backoff, MaxBackoff)
	}
}

// session runs one pair of connections until either ends or ctx does. It
// reports whether the controller attached, and why the session ended.
func (r *Runner) session(ctx context.Context) (bool, error) {
	// Subscribe first, so no ike-updown of an SA the attach triggers is
	// missed.
	events, err := r.dialer.Subscribe(ctx)
	if err != nil {
		return false, err
	}
	defer r.close("event stream", events)
	sess, err := r.dialer.Dial(ctx)
	if err != nil {
		return false, err
	}
	defer r.close("command session", sess)

	if err := r.ctl.Attach(ctx, sess); err != nil {
		if !r.ctl.attached() {
			return false, err
		}
		r.logger.Warn("ipsec: peer connections failed to load", "error", err)
	}
	defer r.ctl.Detach()

	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-sess.Done():
			return true, ErrCharonGone
		case ev, ok := <-events.Events():
			if !ok {
				return true, ErrCharonGone
			}
			if err := r.ctl.HandleEvent(ctx, ev); err != nil {
				r.logger.Warn("ipsec: identity check failed", "error", err)
			}
		}
	}
}

func (r *Runner) close(what string, c interface{ Close() error }) {
	if err := c.Close(); err != nil {
		r.logger.Debug("ipsec: close failed", "connection", what, "error", err)
	}
}
