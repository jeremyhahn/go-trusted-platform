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

package main

import (
	"log/slog"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NTPBinding exposes the time-synchronization service to the Wails frontend.
// It mirrors the `platformctl ntp` CLI surface so the GUI and CLI stay at
// parity.
type NTPBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewNTPBinding creates a new NTPBinding.
func NewNTPBinding(logger *slog.Logger, conn *ConnectionBinding) *NTPBinding {
	return &NTPBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *NTPBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// GetStatus returns the node's clock synchronization state.
func (b *NTPBinding) GetStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.NTP().GetStatus(b.conn.ctx, &platformv1.GetNTPStatusRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListSources returns every configured time source and its live state.
func (b *NTPBinding) ListSources() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.NTP().ListSources(b.conn.ctx, &platformv1.ListNTPSourcesRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Step forces an immediate clock correction. It fails when no time source is
// reachable rather than moving the clock on stale data.
func (b *NTPBinding) Step() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.NTP().Step(b.conn.ctx, &platformv1.StepNTPClockRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}
