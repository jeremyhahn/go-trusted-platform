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

package commands

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// externalIDsClient answers only the bridge external_ids read the terminal
// lookup makes; anything else panics via the embedded nil interface.
type externalIDsClient struct {
	ovs.ClientInterface
	ids map[string]string
	err error
}

func (c *externalIDsClient) GetBridgeExternalIDs(ctx context.Context, name string) (map[string]string, error) {
	return c.ids, c.err
}

// TestPipelineTerminalForBridge pins the #567 seam in platformd: the owner
// is read and logged, and the hand-off stays dormant (normal) in every case
// until owner-change reconcile exists.
func TestPipelineTerminalForBridge(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	owned := &externalIDsClient{ids: map[string]string{zoneflows.PipelineOwnerKey: "gatewayd:lab-node-1-gateway"}}
	assert.Equal(t, zoneflows.TerminalNormal, pipelineTerminalForBridge(context.Background(), owned, "br-int", logger))
	assert.Contains(t, buf.String(), "gatewayd:lab-node-1-gateway", "the owner is observed")
	assert.Contains(t, buf.String(), "dormant")

	buf.Reset()
	unowned := &externalIDsClient{ids: map[string]string{}}
	assert.Equal(t, zoneflows.TerminalNormal, pipelineTerminalForBridge(context.Background(), unowned, "br-int", logger))
	assert.NotContains(t, buf.String(), "dormant")

	broken := &externalIDsClient{err: errors.New("ovsdb unavailable")}
	assert.Equal(t, zoneflows.TerminalNormal, pipelineTerminalForBridge(context.Background(), broken, "br-int", logger))
	assert.Contains(t, buf.String(), "unreadable")

	assert.Equal(t, zoneflows.TerminalNormal, pipelineTerminalForBridge(context.Background(), nil, "br-int", logger))
	assert.Equal(t, zoneflows.TerminalNormal, pipelineTerminalForBridge(context.Background(), owned, "", logger))
}
