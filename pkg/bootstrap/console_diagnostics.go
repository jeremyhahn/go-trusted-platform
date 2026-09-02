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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// forensicUploadTimeout bounds ONE attempt at an upload to the
	// bootstrap container's install sink.
	//
	// The transfer itself is not what needs seconds. A transcript is
	// capped at consoleTranscriptMaxBytes (1 MiB) and the sink is one
	// routed hop from the orchestrator on the provisioning network —
	// 0.25 ms RTT and a clean 1500-byte path MTU end to end, measured
	// vm-host-1 -> 198.18.1.91 — so a whole transcript is milliseconds
	// on the wire. This matches the 10s every other client of this same
	// sink already uses (InstallLogPoller, MediaReadProbe, per-MAC config
	// staging), and it is still three orders of magnitude more than the
	// body costs.
	forensicUploadTimeout = 10 * time.Second

	// forensicUploadAttempts is how many connections one upload may spend.
	//
	// This is the number that was wrong in #136, not the timeout. The
	// upload is the only request in a bootstrap run that gets exactly one
	// chance: the install-log poller and the media-read probe both sit in
	// polling loops, so a single stalled connection is invisible to them,
	// and net/http will not paper over it here either — Request.
	// isReplayable excludes PUT, so once any request byte is on the wire
	// the transport will not re-dial. A connection the peer has silently
	// discarded therefore consumed the entire deadline and the transcript
	// was lost, while the run's own logs showed the sink answering GETs
	// seconds earlier.
	forensicUploadAttempts = 3

	// forensicUploadRetryDelay spaces the attempts so a sink that is
	// momentarily wedged has time to recover before the next dial.
	forensicUploadRetryDelay = 2 * time.Second

	// forensicUploadBudget bounds the whole upload — every attempt and
	// every pause between them. It is deliberately close to the 30s a
	// single attempt used to be allowed: an upload on the failure path
	// still must not extend the failure by much. What changed is that the
	// budget now buys three independent connections instead of gambling
	// all of it on one.
	forensicUploadBudget = forensicUploadAttempts*forensicUploadTimeout +
		(forensicUploadAttempts-1)*forensicUploadRetryDelay
)

// forensicTransport dials a fresh connection for every forensic upload
// and keeps none.
//
// A whole bootstrap run contacts the install sink a handful of times, so
// pooling buys nothing — and costs the artifact. The sink sits behind a
// router that ages idle flows out of its connection table, and a pooled
// connection the far side has discarded still accepts the request bytes
// and then never answers. That failure is indistinguishable from a slow
// server until the deadline passes, and for a PUT net/http cannot
// recover from it (see forensicUploadAttempts). Not reusing connections
// removes the failure mode rather than retrying around it.
var forensicTransport = &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	DisableKeepAlives:     true,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: time.Second,
}

// awaitMediaRead waits for the bootstrap container's media watcher to
// report the staged ISO opened by smbd since the attempt began, bounded
// by the media-read window. The returned error is the
// run's own context error when the run was cancelled or timed out; the
// window elapsing is not an error, it is the result.
func (o *Orchestrator) awaitMediaRead(ctx context.Context, installURL string, node *DiscoveredNode, since time.Time, baseline *MediaReadBaseline) (*MediaReadResult, error) {
	window := o.mediaReadWindow
	if window <= 0 {
		window = defaultMediaReadWindow
	}
	readCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	probe := o.mediaReadProbe(installURL, node)
	probe.Since = since
	probe.Baseline = baseline
	hostname := node.Hostname
	res, err := probe.Wait(readCtx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		o.logger.Info("bootstrap: virtual-media: media-read wait interrupted by run cancellation",
			slog.String("hostname", hostname),
			slog.String("error", ctxErr.Error()))
		return res, ctxErr
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return res, err
	}
	return res, nil
}

// mediaReadBaseline records smbd's activity count for the ISO at the
// instant the chassis is confirmed off (powerCycleNode's whileOff), so
// the attempt's evidence must be newer than anything the previous boot
// did. A baseline that cannot be fetched is nil: the probe then falls
// back to the wall-clock filter alone, which is what it had before.
func (o *Orchestrator) mediaReadBaseline(ctx context.Context, installURL string, node *DiscoveredNode) *MediaReadBaseline {
	hostname := node.Hostname
	baseline, err := o.mediaReadProbe(installURL, node).Snapshot(ctx)
	if err != nil {
		o.logger.Warn("bootstrap: virtual-media: media-read baseline not captured; relying on timestamps alone",
			slog.String("hostname", hostname),
			slog.String("error", err.Error()))
		return nil
	}
	return baseline
}

// mediaReadProbe builds the probe for one node: the staged ISO, and the
// node's BMC address as the SMB client whose reads count.
func (o *Orchestrator) mediaReadProbe(installURL string, node *DiscoveredNode) *MediaReadProbe {
	return &MediaReadProbe{
		BaseURL:  installURL,
		ISOName:  o.stagedISOName(),
		Client:   node.BMCAddress,
		Interval: defaultMediaReadPollInterval,
		Logger:   o.logger,
	}
}

// stagedISOName is the base name of the ISO the BMC mounts, or "" when
// the operator inserted media out of band.
func (o *Orchestrator) stagedISOName() string {
	if o.config.ISOPath == "" {
		return ""
	}
	return filepath.Base(o.config.ISOPath)
}

// uploadForensic PUTs a file into the bootstrap container's install sink
// under the node's hostname and returns its URL.
//
// Transport failures are retried on a fresh connection, and every attempt
// reports which phase of the request it reached. A sink that answers with
// a status is not retried: it spoke, so a second identical PUT would get
// the same answer.
func (o *Orchestrator) uploadForensic(ctx context.Context, installURL, hostname, filename string, data []byte, contentType string) (string, error) {
	target, err := url.JoinPath(installURL, "installs", sanitizeHostnameForInstallPath(hostname), filename)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: forensicTransport}

	// Do not replace this loop by setting Idempotency-Key or
	// X-Idempotency-Key on the request. Either header does flip
	// Request.isReplayable to true for a PUT, so deleting the loop in
	// favour of one header looks like the more idiomatic move — but it
	// would not cover the failure the loop exists for.
	// shouldRetryRequest gates on nothingWrittenError: net/http re-dials
	// only when no request byte reached the wire. The mode measured in
	// #136 is a peer that accepts the whole body and then never answers,
	// which is past that gate, so the header buys nothing.
	var lastErr error
	for attempt := 1; attempt <= forensicUploadAttempts; attempt++ {
		if attempt > 1 {
			timer := time.NewTimer(o.forensicUploadRetryDelay())
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", lastErr
			case <-timer.C:
			}
		}
		retryable, attemptErr := o.putForensic(ctx, client, target, data, contentType, hostname, filename, attempt)
		if attemptErr == nil {
			return target, nil
		}
		lastErr = attemptErr
		if !retryable {
			return "", attemptErr
		}
	}
	return "", lastErr
}

// forensicUploadRetryDelay is the pause between upload attempts.
func (o *Orchestrator) forensicUploadRetryDelay() time.Duration {
	if o.forensicRetryDelay > 0 {
		return o.forensicRetryDelay
	}
	return forensicUploadRetryDelay
}

// putForensic performs one PUT and reports whether the failure is worth
// another connection.
func (o *Orchestrator) putForensic(ctx context.Context, client *http.Client, target string, data []byte, contentType, hostname, filename string, attempt int) (retryable bool, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, forensicUploadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPut, target, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", contentType)

	phases := &uploadPhases{start: time.Now()}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), phases.trace()))

	resp, doErr := client.Do(req)
	if doErr != nil {
		o.logger.Warn("bootstrap: forensic upload attempt failed",
			slog.String("hostname", hostname),
			slog.String("filename", filename),
			slog.Int("attempt", attempt),
			slog.Int("bytes", len(data)),
			slog.Duration("elapsed", time.Since(phases.start)),
			slog.String("stalled_in", phases.stalledIn()),
			slog.String("error", doErr.Error()))
		return true, doErr
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, &MessageError{Msg: "PUT " + target + ": status " + strconv.Itoa(resp.StatusCode)}
	}
	return false, nil
}

// uploadPhases records how far one upload attempt got before it stopped,
// so a stalled upload says WHICH phase stalled rather than only that a
// deadline passed. httptrace may invoke the hooks from other goroutines
// and after the round trip returns, so the fields are guarded.
type uploadPhases struct {
	start time.Time

	mu        sync.Mutex
	connected bool
	wrote     bool
	responded bool
}

func (p *uploadPhases) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			p.mu.Lock()
			p.connected = true
			p.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				return
			}
			p.mu.Lock()
			p.wrote = true
			p.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			p.mu.Lock()
			p.responded = true
			p.mu.Unlock()
		},
	}
}

// stalledIn names the phase the attempt was in when it stopped. The
// distinction matters: "response" means the sink took the whole body and
// went quiet — a connection the far side had already discarded, or a
// wedged handler — whereas "connect" means it was never reached at all.
func (p *uploadPhases) stalledIn() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.responded:
		return "reading response body"
	case p.wrote:
		return "awaiting response after sending the whole body"
	case p.connected:
		return "sending the request body"
	default:
		return "connecting to the sink"
	}
}
