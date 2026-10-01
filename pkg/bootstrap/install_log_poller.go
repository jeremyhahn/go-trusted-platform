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
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// InstallLogResult is the outcome of polling the bootstrap container's
// forensic install-log endpoint for a particular node. The log is always
// uploaded on both success and failure paths by autoinstall.sh, so the
// presence of a log is the authoritative "install attempted and ran to
// conclusion" signal.
type InstallLogResult struct {
	// Hostname is the node hostname that keyed the upload. Matches the
	// platform_hostname=... kernel cmdline baked into the ISO.
	Hostname string
	// Raw is the full install.log body.
	Raw string
	// ExitCode is the installer's captured exit code parsed from the
	// postmortem manifest appended at the end of install.log. Zero means
	// the installer exited cleanly.
	ExitCode int
	// Found is true when a log was retrieved. When Found is false the
	// poll ran out its deadline without ever seeing a log upload.
	Found bool
}

// Success reports whether the installer exited with exit code 0.
func (r *InstallLogResult) Success() bool {
	return r.Found && r.ExitCode == 0
}

// InstallLogPoller watches the pxeboot HTTP server's /installs/{key}/
// forensic sink for a specific node's install.log. A log upload is
// accepted only when its server-reported Last-Modified timestamp is at
// or after the poller's Since value; this rejects stale logs from prior
// runs of the same host without requiring a DELETE-before-install cycle.
//
// Probe keys are tried in this order on every tick:
//  1. /installs/mac/<mac>/install.log for each MAC in MACs. MAC is the
//     most reliable match because the live-ISO environment knows its own
//     MAC from /sys/class/net and the orchestrator knows each node's MAC
//     from bootstrap.yaml — no ISO-level customization needed.
//  2. /installs/<hostname>/install.log — fallback for installers/ISOs
//     that pre-date the MAC-based upload path.
type InstallLogPoller struct {
	// BaseURL is the HTTP base of the pxeboot container, e.g.
	// "http://10.4.2.91:8080". No trailing slash.
	BaseURL string
	// Hostname is the sanitized hostname key used in the upload path.
	// Kept for fallback / human-readable URLs; prefer MACs when set.
	Hostname string
	// MACs lists the node's known NIC MAC addresses. When non-empty,
	// the poller probes /installs/mac/<normalized-mac>/install.log for
	// each MAC before falling back to the hostname path. The installer
	// uploads under its primary interface MAC to survive the generic
	// "server" hostname baked into shared ISOs.
	MACs []string
	// Since filters out stale log uploads from prior runs. When set,
	// the poller only accepts logs whose Last-Modified header is at
	// or after this timestamp. When zero, any existing log is accepted
	// (legacy behavior).
	Since time.Time
	// Interval is the poll cadence. Defaults to 10s when zero.
	Interval time.Duration
	// HTTPClient is the HTTP client to use. Defaults to a 10s timeout
	// client when nil.
	HTTPClient *http.Client
	// Logger is optional; a no-op logger is used when nil.
	Logger *slog.Logger
}

// Wait polls until the install log is found or the context is done.
// Returns an InstallLogResult with Found=true and the parsed exit code
// on success. Returns the context error (typically
// context.DeadlineExceeded) with Found=false on timeout.
func (p *InstallLogPoller) Wait(ctx context.Context) (*InstallLogResult, error) {
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

	base := strings.TrimRight(p.BaseURL, "/")
	urls := p.candidateURLs(base)

	logger.Info("bootstrap: install-log-poller: waiting for install log upload",
		slog.String("hostname", p.Hostname),
		slog.Any("urls", urls),
		slog.Duration("interval", interval))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Try all candidate URLs once immediately so a fast installer doesn't
	// have to wait a whole interval for the first probe.
	if res, done := p.probeAll(ctx, client, urls, logger); done {
		return res, nil
	}

	for {
		select {
		case <-ctx.Done():
			return &InstallLogResult{Hostname: p.Hostname, Found: false}, ctx.Err()
		case <-ticker.C:
			if res, done := p.probeAll(ctx, client, urls, logger); done {
				return res, nil
			}
		}
	}
}

// candidateURLs returns the ordered list of install-log URLs the poller
// should try on each tick. MAC-based paths come first (most reliable),
// then the hostname path (human-readable fallback / pre-MAC ISOs).
func (p *InstallLogPoller) candidateURLs(base string) []string {
	urls := make([]string, 0, len(p.MACs)+1)
	for _, m := range p.MACs {
		if sanitized := sanitizeMACForPath(m); sanitized != "" {
			urls = append(urls, base+"/installs/mac/"+sanitized+"/install.log")
		}
	}
	if p.Hostname != "" {
		urls = append(urls, base+"/installs/"+p.Hostname+"/install.log")
	}
	return urls
}

// probeAll tries each candidate URL in order. Returns the first
// terminal result, or (nil, false) when none of the URLs have a log
// yet.
func (p *InstallLogPoller) probeAll(ctx context.Context, client *http.Client, urls []string, logger *slog.Logger) (*InstallLogResult, bool) {
	for _, url := range urls {
		if res, done := p.probe(ctx, client, url, logger); done {
			return res, true
		}
	}
	return nil, false
}

// sanitizeMACForPath normalizes a MAC address to the URL-safe form
// used in /installs/mac/<mac>/install.log. Lowercase, dash-separated,
// non-hex characters stripped. "aa:BB:cc:DD:ee:ff" → "aa-bb-cc-dd-ee-ff".
// Returns empty string when the input has no hex digits.
func sanitizeMACForPath(mac string) string {
	var hex strings.Builder
	hex.Grow(12)
	for _, r := range strings.ToLower(mac) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		}
	}
	h := hex.String()
	if len(h) != 12 {
		return ""
	}
	var out strings.Builder
	out.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out.WriteByte('-')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}

// probe makes a single HTTP GET against the install log URL. Returns
// (result, true) when a log is available (terminal, caller should stop
// polling), or (nil, false) when the log isn't there yet and the caller
// should keep polling. All errors are treated as "not there yet" — the
// container may be transiently unreachable during BMC or switch churn
// and we don't want a single transient failure to abort the install.
func (p *InstallLogPoller) probe(ctx context.Context, client *http.Client, url string, logger *slog.Logger) (*InstallLogResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		logger.Debug("bootstrap: install-log-poller: request build failed",
			slog.String("error", err.Error()))
		return nil, false
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Debug("bootstrap: install-log-poller: transport error (retrying)",
			slog.String("error", err.Error()))
		return nil, false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warn("bootstrap: install-log-poller: unexpected status (retrying)",
			slog.Int("status", resp.StatusCode))
		return nil, false
	}

	// Freshness gate: if Since is set and the server reports a
	// Last-Modified older than Since, this is a stale log from a
	// prior run and we keep polling. Without this check, a
	// previously-successful install.log sitting in the container's
	// forensic sink causes the orchestrator to report instant
	// success for a brand-new install that hasn't actually started
	// yet.
	if !p.Since.IsZero() {
		lastMod := resp.Header.Get("Last-Modified")
		if lastMod != "" {
			if ts, parseErr := http.ParseTime(lastMod); parseErr == nil {
				if ts.Before(p.Since.Add(-2 * time.Second)) {
					logger.Info("bootstrap: install-log-poller: stale log (waiting for fresh)",
						slog.Time("last_modified", ts),
						slog.Time("since", p.Since))
					return nil, false
				}
				logger.Info("bootstrap: install-log-poller: log is fresh",
					slog.Time("last_modified", ts),
					slog.Time("since", p.Since))
			} else {
				logger.Warn("bootstrap: install-log-poller: failed to parse Last-Modified",
					slog.String("value", lastMod),
					slog.String("error", parseErr.Error()))
			}
		} else {
			logger.Info("bootstrap: install-log-poller: no Last-Modified header, accepting")
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("bootstrap: install-log-poller: body read failed (retrying)",
			slog.String("error", err.Error()))
		return nil, false
	}

	raw := string(body)
	exit := parseInstallLogExitCode(raw)
	logger.Info("bootstrap: install-log-poller: log retrieved",
		slog.String("hostname", p.Hostname),
		slog.Int("bytes", len(body)),
		slog.Int("exit_code", exit))
	return &InstallLogResult{
		Hostname: p.Hostname,
		Raw:      raw,
		ExitCode: exit,
		Found:    true,
	}, true
}

// exitCodeRE matches the "exit_code: N" line in the postmortem manifest
// appended at the end of install.log by upload_install_log_with_code in
// pkg/iso/customize.go. The manifest header is "=== POSTMORTEM MANIFEST ===".
// We intentionally do not anchor strictly to the manifest header — any
// "exit_code:" line in the log is taken, and the LAST occurrence wins so
// that multiple uploads over retries land on the most recent result.
var exitCodeRE = regexp.MustCompile(`(?m)^\s*exit_code:\s*(-?\d+)\s*$`)

// parseInstallLogExitCode extracts the installer exit code from a log
// body. Returns 0 when no exit_code line is present (the old-format
// logs lacked one; treating them as success is the historical
// convention). Returns the last match when multiple are present.
func parseInstallLogExitCode(log string) int {
	matches := exitCodeRE.FindAllStringSubmatch(log, -1)
	if len(matches) == 0 {
		return 0
	}
	last := matches[len(matches)-1]
	if len(last) < 2 {
		return 0
	}
	n, err := strconv.Atoi(last[1])
	if err != nil {
		return 0
	}
	return n
}
