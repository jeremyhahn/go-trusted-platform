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

package verdict

import (
	"context"
	"time"
)

// StreamPrincipal is the caller of a device verdict stream, as a transport
// reports it. Every transport (gRPC, Unix socket, REST) authenticates in its
// own way and hands the stream service this one shape, so one resolver decides
// who may follow which tenant's verdicts.
type StreamPrincipal struct {
	// TenantID is the tenant the transport's credential names. Empty when
	// the credential names none.
	TenantID string
	// HasCertificate reports that the caller presented a client certificate.
	// A certificate that names no tenant is refused.
	HasCertificate bool
	// UnixPeer reports that the Unix socket admitted the caller by its
	// kernel-verified peer credentials. It is the only caller allowed to
	// follow without a credential.
	UnixPeer bool
}

// StreamHeartbeat asks a subscription to call Beat every Every while no
// verdict is sent, so a transport can keep an idle connection alive. A zero
// Every sends no heartbeat.
type StreamHeartbeat struct {
	Every time.Duration
	Beat  func() error
}

// StreamSubscription is one admitted follower of the device verdict stream.
type StreamSubscription interface {
	// Serve calls send for every verdict the principal may see, until ctx is
	// done, the stream is closed, the subscriber falls behind or send fails.
	Serve(ctx context.Context, send func(RecordedDeviceVerdict) error, heartbeat StreamHeartbeat) error
	// Close releases the subscription. It is safe to call more than once.
	Close()
}

// StreamOpener admits a principal to the device verdict stream.
type StreamOpener interface {
	OpenVerdictStream(principal StreamPrincipal) (StreamSubscription, error)
}

// ErrStreamUnavailable is returned when the daemon has no verdict stream to
// serve: the attestation service cannot hand out its verdicts.
type ErrStreamUnavailable struct{}

func (ErrStreamUnavailable) Error() string {
	return "attestation: the device verdict stream is not available"
}

// ErrStreamClosed is returned when the daemon is shutting down.
type ErrStreamClosed struct{}

func (ErrStreamClosed) Error() string {
	return "attestation: the device verdict stream is closed"
}

// ErrSubscriberBehind ends the stream of a subscriber that fell too far
// behind. Ending the stream, rather than dropping verdicts, tells the
// subscriber it missed some.
type ErrSubscriberBehind struct{}

func (ErrSubscriberBehind) Error() string {
	return "attestation: the device verdict subscriber fell behind and missed verdicts"
}

// ErrStreamForbidden is returned when the caller may not follow device
// verdicts.
type ErrStreamForbidden struct {
	Reason string
}

func (e ErrStreamForbidden) Error() string {
	return "attestation: device verdict stream denied: " + e.Reason
}
