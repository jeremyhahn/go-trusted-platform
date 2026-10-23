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

package ovs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shapingTest is a client on a mock OVSDB with port eth-shape on a bridge.
func shapingTest(t *testing.T) *Client {
	t.Helper()
	client, server := setupPortTest(t)
	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })
	_, err := client.AddPort(context.Background(), "br-port-test", "eth-shape")
	require.NoError(t, err)
	return client
}

// rowsOf selects every row of table.
func rowsOf(t *testing.T, client *Client, table string) []map[string]interface{} {
	t.Helper()
	rows, err := client.Select(context.Background(), table, nil, nil)
	require.NoError(t, err)
	return rows
}

// attachedQoS is the QoS UUID the named port references, or "".
func attachedQoS(t *testing.T, client *Client, port string) string {
	t.Helper()
	_, qos, err := client.portQoS(context.Background(), port)
	require.NoError(t, err)
	if len(qos) == 0 {
		return ""
	}
	return qos[0]
}

func TestClient_SetEgressShaping(t *testing.T) {
	client := shapingTest(t)
	ctx := context.Background()

	require.NoError(t, client.SetEgressShaping(ctx, "eth-shape", 10_000_000, 1_000_000))

	qosRows := rowsOf(t, client, qosTable)
	require.Len(t, qosRows, 1)
	qos := qosRows[0]
	assert.Equal(t, "linux-htb", qos["type"])
	assert.Equal(t, "10000000", parseMap(qos["other_config"])["max-rate"])
	assert.Equal(t, "true", parseMap(qos["external_ids"])[egressShapingKey])

	qosUUID, err := UnmarshalUUID(qos["_uuid"])
	require.NoError(t, err)
	assert.Equal(t, qosUUID, attachedQoS(t, client, "eth-shape"), "the port does not reference the new QoS")

	queueRows := rowsOf(t, client, queueTable)
	require.Len(t, queueRows, 1)
	queueUUID, err := UnmarshalUUID(queueRows[0]["_uuid"])
	require.NoError(t, err)
	assert.Equal(t, []string{queueUUID}, parseUUIDMapValues(qos["queues"]), "queue 0 is not the shaping queue")
	queueConfig := parseMap(queueRows[0]["other_config"])
	assert.Equal(t, "10000000", queueConfig["max-rate"])
	assert.Equal(t, "1000000", queueConfig["burst"])
}

func TestClient_SetEgressShapingReplacesItsOwnShaping(t *testing.T) {
	client := shapingTest(t)
	ctx := context.Background()

	require.NoError(t, client.SetEgressShaping(ctx, "eth-shape", 10_000_000, 1_000_000))
	require.NoError(t, client.SetEgressShaping(ctx, "eth-shape", 20_000_000, 0))

	qosRows := rowsOf(t, client, qosTable)
	require.Len(t, qosRows, 1, "the earlier QoS was left behind")
	assert.Equal(t, "20000000", parseMap(qosRows[0]["other_config"])["max-rate"])
	queueRows := rowsOf(t, client, queueTable)
	require.Len(t, queueRows, 1, "the earlier queue was left behind")
	_, hasBurst := parseMap(queueRows[0]["other_config"])["burst"]
	assert.False(t, hasBurst, "a zero burst must leave the burst to Open vSwitch")
}

func TestClient_SetEgressShapingRateZeroRemovesIt(t *testing.T) {
	client := shapingTest(t)
	ctx := context.Background()

	require.NoError(t, client.SetEgressShaping(ctx, "eth-shape", 10_000_000, 0))
	require.NoError(t, client.SetEgressShaping(ctx, "eth-shape", 0, 0))

	assert.Empty(t, attachedQoS(t, client, "eth-shape"))
	assert.Empty(t, rowsOf(t, client, qosTable))
	assert.Empty(t, rowsOf(t, client, queueTable))
}

func TestClient_SetEgressShapingLeavesAForeignQoS(t *testing.T) {
	client := shapingTest(t)
	ctx := context.Background()

	results, err := client.Transact(ctx,
		NewInsertOperation(qosTable, map[string]interface{}{"type": "linux-hfsc"}, "foreign"),
		NewUpdateOperation(portTable, []Condition{NewCondition("name", "==", "eth-shape")},
			map[string]interface{}{"qos": NamedUUID{NamedUUID: "foreign"}}),
	)
	require.NoError(t, err)
	foreign := results[0].UUID.UUID

	require.NoError(t, client.SetEgressShaping(ctx, "eth-shape", 10_000_000, 0))

	assert.NotEqual(t, foreign, attachedQoS(t, client, "eth-shape"))
	assert.Len(t, rowsOf(t, client, qosTable), 2, "a QoS the platform did not create was deleted")
}

func TestClient_SetEgressShapingRefusals(t *testing.T) {
	client := shapingTest(t)
	ctx := context.Background()

	t.Run("empty name", func(t *testing.T) {
		assert.ErrorIs(t, client.SetEgressShaping(ctx, "", 1000, 0), ErrInvalidPortName)
	})

	t.Run("unknown port", func(t *testing.T) {
		assert.ErrorIs(t, client.SetEgressShaping(ctx, "eth-missing", 1000, 0), ErrPortNotFound)
	})

	t.Run("burst without a rate", func(t *testing.T) {
		var shaping *ErrInvalidShaping
		require.ErrorAs(t, client.SetEgressShaping(ctx, "eth-shape", 0, 1000), &shaping)
		assert.Empty(t, rowsOf(t, client, qosTable), "a refused pair reached the database")
	})
}

func TestValidateEgressShaping(t *testing.T) {
	for _, v := range []struct{ rate, burst uint64 }{{0, 0}, {1, 0}, {1500, 1}, {10_000_000, 1_000_000}} {
		assert.NoError(t, ValidateEgressShaping(v.rate, v.burst), "rate %d burst %d", v.rate, v.burst)
	}

	err := ValidateEgressShaping(0, 1000)
	var shaping *ErrInvalidShaping
	require.ErrorAs(t, err, &shaping)
	assert.Equal(t, uint64(0), shaping.RateBps)
	assert.Equal(t, uint64(1000), shaping.BurstBits)
	assert.Contains(t, err.Error(), "a burst needs a rate")
}

func TestParseUUIDMapValues(t *testing.T) {
	queues := []interface{}{"map", []interface{}{
		[]interface{}{float64(0), []interface{}{"uuid", "q0"}},
		[]interface{}{float64(1), []interface{}{"uuid", "q1"}},
	}}
	assert.Equal(t, []string{"q0", "q1"}, parseUUIDMapValues(queues))

	for _, bad := range []interface{}{nil, "q0", []interface{}{"set", []interface{}{}}, []interface{}{"map", "q0"}} {
		assert.Empty(t, parseUUIDMapValues(bad), "%v", bad)
	}
}
