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
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

// forensicUploadTimeout bounds one upload to the bootstrap container's
// install sink; uploads happen on a failure path and must not extend the
// failure by much.
const forensicUploadTimeout = 30 * time.Second

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
func (o *Orchestrator) uploadForensic(ctx context.Context, installURL, hostname, filename string, data []byte, contentType string) (string, error) {
	target, err := url.JoinPath(installURL, "installs", sanitizeHostnameForInstallPath(hostname), filename)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	client := &http.Client{Timeout: forensicUploadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &MessageError{Msg: "PUT " + target + ": status " + strconv.Itoa(resp.StatusCode)}
	}
	return target, nil
}
