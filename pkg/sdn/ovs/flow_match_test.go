package ovs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// ListFlows and GetFlowStats build their Flow values through flowFromStats,
// so a flow listed from the switch carries its match: the SDN policy
// collision guard compares matches of the entries ListFlows returns.
func TestFlowFromStatsFillsMatch(t *testing.T) {
	match := openflow.NewMatch()
	require.NoError(t, parseMatchString(match, "in_port=1,dl_type=0x0800"))

	flow := flowFromStats(openflow.FlowStats{
		TableID:     2,
		Priority:    100,
		Match:       match,
		DurationSec: 60,
		IdleTimeout: 30,
		HardTimeout: 300,
		Cookie:      0x1234,
		PacketCount: 1000,
		ByteCount:   65000,
	})

	require.NotNil(t, flow)
	assert.Equal(t, formatMatchString(match), flow.Match)
	assert.NotEmpty(t, flow.Match, "a listed flow must carry its match")
	assert.Contains(t, flow.Match, "in_port=1")
	assert.Equal(t, 2, flow.Table)
	assert.Equal(t, 100, flow.Priority)
	assert.Equal(t, "0x1234", flow.Cookie)
	assert.Equal(t, int64(1000), flow.PacketCount)
	assert.Equal(t, int64(65000), flow.ByteCount)
}
