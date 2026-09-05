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

package reporting

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViews_RenderVerdictWithAgeAndFreshness(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	clk := newFakeClock(now)
	c := newCacheWithClock(time.Hour, clk)
	c.Store(&Report{DeviceID: "b", Serial: "SN-B", Verified: true, AKCertificateVerified: true, SignatureValid: true, NonceValid: true, PCRsValid: true,
		PCRBaselineSource: "tofu", PCRBaselineCaptured: true, Status: "verified", CollectedAt: now.Add(-10 * time.Minute), AttestedAt: now.Add(-10 * time.Minute)})
	c.Store(&Report{DeviceID: "a", Verified: false, Cryptographic: true, Status: "failed", Message: "bad signature", CollectedAt: now.Add(-2 * time.Hour)})

	views := c.Views()
	require.Len(t, views, 2)
	assert.Equal(t, "a", views[0].DeviceID)
	assert.False(t, views[0].Verified)
	assert.True(t, views[0].CryptographicFailure)
	assert.False(t, views[0].Fresh)
	assert.Equal(t, int64(7200), views[0].AgeSeconds)
	assert.Equal(t, now, views[0].AsOf)
	assert.Equal(t, "bad signature", views[0].Message)

	assert.Equal(t, "b", views[1].DeviceID)
	assert.True(t, views[1].Fresh)
	assert.Equal(t, int64(600), views[1].AgeSeconds)
	assert.Equal(t, "tofu", views[1].PCRBaselineSource)
	assert.True(t, views[1].PCRBaselineCaptured)
	assert.True(t, views[1].AKCertificateVerified)
	assert.Equal(t, "SN-B", views[1].Serial)

	v, ok := c.View("b")
	require.True(t, ok)
	assert.True(t, v.Fresh)

	_, ok = c.View("never")
	assert.False(t, ok, "never collected is not a view, and not a failed verdict")
	r, _ := c.Report("b")
	assert.True(t, c.IsFresh(r))
	assert.False(t, c.IsFresh(nil))
	assert.Equal(t, now, c.Now())
}

func TestCollectorRefresh_RequiresDeviceAndRunningCollector(t *testing.T) {
	src := newCountingSource()
	c := testCollector(t, Config{Source: src}, newFakeClock(time.Unix(1, 0)))
	err := c.Refresh("")
	var required ErrDeviceIDRequired
	require.ErrorAs(t, err, &required)

	err = c.Refresh("dev")
	var stopped ErrCollectorStopped
	require.ErrorAs(t, err, &stopped)
	assert.Equal(t, 0, src.count())
}

func TestCollectorRefresh_EnqueuesWhenRunning(t *testing.T) {
	src := newCountingSource()
	clk := newFakeClock(time.Unix(1, 0))
	c := testCollector(t, Config{Source: src}, clk)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()
	waitFor(t, func() bool { return clk.waiters_() > 0 }, "loop running")
	require.NoError(t, c.Refresh("dev-1"))
	waitFor(t, func() bool { return src.count() == 1 }, "refresh collected")
	cancel()
	<-done
	_, ok := c.Cache().Report("dev-1")
	assert.True(t, ok)
}
