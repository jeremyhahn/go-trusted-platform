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

package iso

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForCSServerReady_CanceledContextReturnsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitForCSServerReady(ctx, createCSLogger(false), "192.0.2.1", time.Hour)
	require.ErrorIs(t, err, context.Canceled)
}

func TestWaitForCSServerReady_ExpiredTimeoutReportsUnreachable(t *testing.T) {
	err := waitForCSServerReady(context.Background(), createCSLogger(false), "192.0.2.1", 0)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, msgErr.Msg, "did not become reachable via ping")
}

func TestWaitForCSServerReadyUserNetwork_CanceledContextReturnsAtOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitForCSServerReadyUserNetwork(ctx, createCSLogger(false), &clientServerFlags{}, time.Hour)
	require.ErrorIs(t, err, context.Canceled)
}
