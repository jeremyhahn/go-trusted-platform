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
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

// mediaStatusPath is the bootstrap container endpoint that reports which
// files under its data directory are open and how far they have been read
// (pkg/ipxe handleMediaStatus).
const mediaStatusPath = "/media/status"

// maxMediaStatusBody caps a /media/status response read; the document
// lists a handful of open files and never approaches this.
const maxMediaStatusBody = 256 * 1024

// MediaReadResult is the outcome of MediaReadProbe.Wait.
type MediaReadResult struct {
	// Supported is false when no usable evidence was obtained: the
	// bootstrap container does not serve /media/status (an image that
	// predates it), or it never answered usefully within the window.
	// The caller then has no evidence either way and must not treat
	// silence as a failure. Err carries the last monitoring error in
	// the second case.
	Supported bool
	// Err is the last transport, status or decode error when Supported is
	// false because no valid answer arrived; nil otherwise.
	Err error
	// ValidSamples counts the /media/status answers that decoded.
	ValidSamples int
	// probesSinceValid counts the answers that failed since the last
	// decoded one. Only the trailing run matters: the watcher's record is
	// cumulative, so a read that happened while the endpoint was
	// unreachable mid-window is still on the next decoded answer, but
	// nothing after the last decoded answer was ever seen. A window that
	// ends on a run longer than mediaReadStaleProbes has no evidence for
	// its decisive tail.
	probesSinceValid int
	// Observed is true once the ISO was seen open, i.e. the host firmware
	// started reading the emulated CD.
	Observed bool
	// Opens and MaxPos are the last values reported for the ISO: the
	// descriptors open at the last sample, and the furthest read offset
	// the watcher has ever seen.
	Opens  int
	MaxPos int64
	// Elapsed is how long the probe waited before returning.
	Elapsed time.Duration
}

// MediaReadBaseline is the watcher's record of smbd's activity on the
// ISO at one instant, used as the cursor an attempt's evidence must move
// past.
type MediaReadBaseline struct {
	// Supported is false when the container does not serve /media/status.
	Supported bool
	// WatcherSince identifies the watcher instance the counters belong to.
	WatcherSince time.Time
	// Activity is smbd's open-event plus position-change count at the time.
	Activity int
}

// mediaProbeResult is one /media/status fetch, decoded.
type mediaProbeResult struct {
	// open is the ISO's record, zero when it was never seen.
	open ipxe.MediaOpen
	// watcherSince identifies the watcher instance.
	watcherSince time.Time
	// supported is false when the endpoint does not exist (404/405).
	supported bool
	// ok is true when the fetch produced a decodable answer.
	ok bool
	// err explains why ok is false, when it is.
	err error
}

// Snapshot fetches /media/status once and returns the ISO's current
// record as a baseline. Transport errors are returned; an unsupported
// endpoint yields Supported=false and no error.
func (p *MediaReadProbe) Snapshot(ctx context.Context) (*MediaReadBaseline, error) {
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	url := strings.TrimRight(p.BaseURL, "/") + mediaStatusPath
	r := p.probe(ctx, client, url, logger)
	if r.err != nil {
		return nil, r.err
	}
	if !r.supported {
		return &MediaReadBaseline{}, nil
	}
	if !r.ok {
		return nil, ErrMediaStatusUnavailable{URL: url}
	}
	activity, _ := p.smbdActivity(r.open)
	return &MediaReadBaseline{Supported: true, WatcherSince: r.watcherSince, Activity: activity}, nil
}

// smbdActivity sums the activity of the smbd workers that count for this
// probe (see Client) and returns the latest of their LastActivity.
func (p *MediaReadProbe) smbdActivity(open ipxe.MediaOpen) (int, time.Time) {
	workers := open.OpenersNamed(smbProcessName)
	tagged := false
	for i := range workers {
		if workers[i].Client != "" {
			tagged = true
			break
		}
	}
	activity := 0
	var last time.Time
	for i := range workers {
		if tagged && p.Client != "" && !workerServesClient(&workers[i], p.Client) {
			continue
		}
		activity += workers[i].Activity()
		if workers[i].LastActivity.After(last) {
			last = workers[i].LastActivity
		}
	}
	return activity, last
}

// MediaReadProbe watches the bootstrap container's /media/status until
// the staged ISO is opened by the host (through smbd, for the BMC's
// virtual-media client) or the context expires. The BMC's SMB session is
// established at mount time, but a descriptor on the ISO exists only
// while a booting host is reading it — so "never opened" within a window
// that covers POST is the evidence that the firmware never booted the
// media at all, which the install-log poller alone cannot tell apart from
// a slow install.
type MediaReadProbe struct {
	// BaseURL is the HTTP base of the bootstrap container, no trailing slash.
	BaseURL string
	// ISOName is the staged ISO's file name inside the share (the base
	// name of the file the BMC mounts). Empty matches any *.iso, for
	// runs where the operator inserted the media out of band.
	ISOName string
	// Since filters out reads from a previous attempt: an observation
	// counts only if the watcher last saw the ISO open at or after this
	// time (with the same two-second slack the install-log poller uses).
	// Zero accepts any observation since the watcher started.
	Since time.Time
	// Client is the address the node's BMC reads the share from — its
	// BMC address. When the watcher tags smbd workers with their client
	// (Debian smbd retitles each per-connection worker
	// "smbd: client [ip]"; Alpine/musl smbd titles it "smbd[ip]", which
	// the kernel's comm limit may truncate to an IP prefix), only the
	// workers serving this address count, so concurrent nodes reading
	// the same ISO cannot vouch for each other; a truncated capture is
	// matched as a prefix. When no smbd worker on the record carries a
	// client tag at all, attribution is unavailable and every smbd
	// worker counts, as it would with an older Samba that does not
	// retitle.
	Client string
	// Baseline is smbd's record for the ISO taken while the chassis is
	// confirmed off, between the power-off and the power-on
	// (MediaReadProbe.Snapshot). With it set, an observation must carry
	// MORE smbd activity than the baseline — wall-clock filtering alone
	// cannot tell a read that ended a second before the cycle from one
	// after it. A baseline from a different watcher instance (the
	// container restarted) is ignored.
	Baseline *MediaReadBaseline
	// Interval is the poll cadence. Defaults to 10s when zero.
	Interval time.Duration
	// HTTPClient is the HTTP client to use. Defaults to a 10s timeout
	// client when nil.
	HTTPClient *http.Client
	// Logger is optional; slog.Default is used when nil.
	Logger *slog.Logger
}

// Wait polls until the ISO is observed open, the endpoint turns out to be
// unsupported, or ctx is done. The context error is returned with
// Observed=false on timeout; an unsupported endpoint returns
// Supported=false and a nil error on the first probe, because there is
// nothing to wait for.
func (p *MediaReadProbe) Wait(ctx context.Context) (*MediaReadResult, error) {
	interval := p.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	client := p.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	url := strings.TrimRight(p.BaseURL, "/") + mediaStatusPath
	start := time.Now()

	logger.Info("bootstrap: media-read-probe: waiting for the host to open the ISO",
		slog.String("iso", p.ISOName),
		slog.String("url", url),
		slog.Duration("interval", interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	res := &MediaReadResult{Supported: true}
	probe := func() bool {
		r := p.probe(ctx, client, url, logger)
		res.Elapsed = time.Since(start)
		if !r.supported {
			res.Supported = false
			return true
		}
		if !r.ok {
			// Transport errors and 5xx are "no answer yet"; the next
			// tick asks again. r.err has already been logged.
			res.Err = r.err
			res.probesSinceValid++
			return false
		}
		res.ValidSamples++
		res.probesSinceValid = 0
		res.Err = nil
		res.Opens, res.MaxPos = r.open.Opens, r.open.MaxPos
		if activity, last, ok := p.observed(r.open, r.watcherSince); ok {
			res.Observed = true
			logger.Info("bootstrap: media-read-probe: host is reading the ISO",
				slog.String("iso", p.ISOName),
				slog.String("client", p.Client),
				slog.Int("smbd_activity", activity),
				slog.Int64("max_pos", r.open.MaxPos),
				slog.Time("last_activity", last),
				slog.Duration("after", res.Elapsed))
			return true
		}
		return false
	}

	if probe() {
		return res, nil
	}
	for {
		select {
		case <-ctx.Done():
			res.Elapsed = time.Since(start)
			switch {
			case res.ValidSamples == 0:
				// The window closed without a single usable answer:
				// that is a monitoring outage, not a host that never
				// read the media, and it must not be reported as one.
				res.Supported = false
				logger.Warn("bootstrap: media-read-probe: no usable /media/status answer within the window; media-read evidence unavailable",
					slog.String("url", url),
					slog.Duration("window", res.Elapsed),
					slog.Any("last_error", res.Err))
			case res.probesSinceValid > mediaReadStaleProbes:
				// Evidence stopped arriving well before the window
				// closed: the tail of the window — where a slow POST
				// would have shown its first read — was not observed.
				res.Supported = false
				logger.Warn("bootstrap: media-read-probe: /media/status stopped answering before the window closed; media-read evidence unavailable",
					slog.String("url", url),
					slog.Int("failed_probes_since_last_answer", res.probesSinceValid),
					slog.Any("last_error", res.Err))
			default:
				// Evidence was obtained through the window; a brief
				// outage at its very end is not the result.
				res.Err = nil
			}
			return res, ctx.Err()
		case <-ticker.C:
			// A tick and the end of the window can be ready in the
			// same select, and the choice between two ready arms is
			// random. A probe spent on a context that is already done
			// never reaches the endpoint — the client short-circuits
			// on the cancelled context — but it does count against
			// probesSinceValid, and enough of those turn a result
			// that did carry evidence into an unsupported one. The
			// window is over; take the other arm rather than ask a
			// question whose answer is already known.
			if ctx.Err() != nil {
				continue
			}
			if probe() {
				return res, nil
			}
		}
	}
}

// smbProcessName is the Samba file server process that acts for the
// BMC's virtual-media client.
const smbProcessName = "smbd"

// mediaReadStaleProbes is how many consecutive failed probes at the end
// of the window a result may carry and still count as evidence; more
// than that and the window's decisive tail went unobserved.
const mediaReadStaleProbes = 2

// mediaReadSlack is how far before Since an observation may fall and
// still count, covering clock skew between the orchestrator and the
// container the same way the install-log poller's Last-Modified check
// does.
const mediaReadSlack = 2 * time.Second

// workerServesClient reports whether an smbd worker's captured client
// names the BMC address: exactly (modulo port and IP normalisation), or
// as a prefix when the kernel's 15-byte comm limit truncated the title
// — "smbd[192.168.50" is all that survives of 198.18.1.103 (#126).
func workerServesClient(w *ipxe.MediaOpener, bmc string) bool {
	if w.ClientTruncated {
		return strings.HasPrefix(clientHost(bmc), w.Client)
	}
	return sameClient(w.Client, bmc)
}

// sameClient reports whether two client addresses name the same host:
// a port suffix on either side is ignored and IP literals are compared
// as addresses, so "fe80::1" and "[fe80::1]:445" match; anything that
// does not parse as an IP is compared as text.
func sameClient(a, b string) bool {
	return clientHost(a) == clientHost(b)
}

// clientHost normalises a client address for comparison.
func clientHost(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// observed reports whether the watcher says this node's BMC — smbd's
// workers for Client, or every smbd worker when the record carries no
// client tags — did something new with the ISO during this attempt:
// opened it or moved through it, more times than the pre-cycle baseline
// (when the baseline comes from this same watcher instance) or at least
// once (otherwise), and last did so no earlier than Since. It returns
// the activity count and its last time. Only smbd counts: another
// process holding the ISO, however recently, says nothing about the
// host, and a record with no process names is a scan that saw nothing.
func (p *MediaReadProbe) observed(open ipxe.MediaOpen, watcherSince time.Time) (int, time.Time, bool) {
	activity, last := p.smbdActivity(open)
	floor := 0
	if p.Baseline != nil && p.Baseline.Supported && p.Baseline.WatcherSince.Equal(watcherSince) {
		floor = p.Baseline.Activity
	}
	if activity <= floor {
		return activity, last, false
	}
	if !p.Since.IsZero() && last.Before(p.Since.Add(-mediaReadSlack)) {
		return activity, last, false
	}
	return activity, last, true
}

// probe fetches /media/status once. Transport errors and 5xx are "no
// answer yet" — the container may be briefly unreachable during BMC or
// switch churn — while 404/405 means the container image predates the
// endpoint.
func (p *MediaReadProbe) probe(ctx context.Context, client *http.Client, url string, logger *slog.Logger) mediaProbeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.Debug("bootstrap: media-read-probe: request build failed",
			slog.String("error", err.Error()))
		return mediaProbeResult{supported: true, err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("bootstrap: media-read-probe: transport error (retrying)",
			slog.String("error", err.Error()))
		return mediaProbeResult{supported: true, err: err}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		logger.Warn("bootstrap: media-read-probe: container does not serve /media/status; media-read evidence unavailable",
			slog.String("url", url),
			slog.Int("status", resp.StatusCode))
		return mediaProbeResult{}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		logger.Warn("bootstrap: media-read-probe: unexpected status (retrying)",
			slog.Int("status", resp.StatusCode))
		return mediaProbeResult{supported: true, err: ErrMediaStatusUnavailable{URL: url, StatusCode: resp.StatusCode}}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMediaStatusBody))
	if err != nil {
		logger.Warn("bootstrap: media-read-probe: body read failed (retrying)",
			slog.String("error", err.Error()))
		return mediaProbeResult{supported: true, err: err}
	}
	var status ipxe.MediaStatus
	if err := json.Unmarshal(body, &status); err != nil {
		logger.Warn("bootstrap: media-read-probe: malformed status (retrying)",
			slog.String("error", err.Error()))
		return mediaProbeResult{supported: true, err: err}
	}
	result := mediaProbeResult{watcherSince: status.Since, supported: true, ok: true}
	for _, f := range status.Files {
		name := path.Base(strings.TrimSuffix(f.Path, " (deleted)"))
		if name == p.ISOName || (p.ISOName == "" && strings.HasSuffix(strings.ToLower(name), ".iso")) {
			result.open = f
			break
		}
	}
	return result
}
