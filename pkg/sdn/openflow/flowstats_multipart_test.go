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

package openflow

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClient_QueryFlowStats_ReadsEveryMultipartPart has the switch spread the
// flow stats over two multipart replies, the first flagged OFPMPF_REPLY_MORE.
// A flow that only the second part carries must still be returned: a caller
// deciding whether a flow key is free relies on the full table.
func TestClient_QueryFlowStats_ReadsEveryMultipartPart(t *testing.T) {
	server, client := connectMock(t)
	server.setFlowStats([]FlowStats{
		{TableID: 0, Priority: 100, Cookie: 0x1},
		{TableID: 0, Priority: 100, Cookie: 0x2},
	})
	server.splitFlowStatsAt(1)

	stats, err := client.QueryFlowStats(context.Background(), FlowStatsFilter{TableID: OFPTTAll})
	require.NoError(t, err)
	require.Len(t, stats, 2, "QueryFlowStats must return the entries of every multipart part")
	require.Equal(t, uint64(0x1), stats[0].Cookie)
	require.Equal(t, uint64(0x2), stats[1].Cookie)
}
