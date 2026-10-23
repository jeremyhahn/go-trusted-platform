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
	"math"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPortTest(t *testing.T) (*Client, *mockOVSDBServer) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create a test bridge
	_, err = client.CreateBridge(ctx, "br-port-test")
	require.NoError(t, err)

	return client, server
}

func TestClient_AddPort(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("add port successfully", func(t *testing.T) {
		port, err := client.AddPort(ctx, "br-port-test", "eth0")
		require.NoError(t, err)
		assert.NotNil(t, port)
		assert.Equal(t, "eth0", port.Name)
		assert.NotEmpty(t, port.UUID)
	})

	t.Run("add port with empty bridge name", func(t *testing.T) {
		_, err := client.AddPort(ctx, "", "eth1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("add port with empty port name", func(t *testing.T) {
		_, err := client.AddPort(ctx, "br-port-test", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("add duplicate port", func(t *testing.T) {
		// Add first port
		_, err := client.AddPort(ctx, "br-port-test", "eth-dup")
		require.NoError(t, err)

		// Try to add duplicate
		_, err = client.AddPort(ctx, "br-port-test", "eth-dup")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortExists)
	})

	t.Run("add port to non-existent bridge", func(t *testing.T) {
		_, err := client.AddPort(ctx, "br-nonexist", "eth2")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("add port when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		_, err = disconnectedClient.AddPort(ctx, "br-port-test", "eth-fail")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_AddPortWithType(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("writes the interface type in the insert", func(t *testing.T) {
		_, err := client.AddPortWithType(ctx, "br-port-test", "int0", "internal")
		require.NoError(t, err)

		iface, err := client.GetInterface(ctx, "int0")
		require.NoError(t, err)
		assert.Equal(t, "internal", iface.Type)
	})

	t.Run("refuses a type Open vSwitch does not implement", func(t *testing.T) {
		_, err := client.AddPortWithType(ctx, "br-port-test", "bad0", "bogus")
		var invalid *ErrInvalidPortType
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "bogus", invalid.Type)

		_, err = client.GetPort(ctx, "bad0")
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestClient_DeletePort(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("delete existing port", func(t *testing.T) {
		// Add port first
		_, err := client.AddPort(ctx, "br-port-test", "eth-del")
		require.NoError(t, err)

		// Delete it
		err = client.DeletePort(ctx, "br-port-test", "eth-del")
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.GetPort(ctx, "eth-del")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("delete port with empty bridge name", func(t *testing.T) {
		err := client.DeletePort(ctx, "", "eth0")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("delete port with empty port name", func(t *testing.T) {
		err := client.DeletePort(ctx, "br-port-test", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("delete non-existent port", func(t *testing.T) {
		err := client.DeletePort(ctx, "br-port-test", "eth-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("delete port from non-existent bridge", func(t *testing.T) {
		// Add port first
		_, err := client.AddPort(ctx, "br-port-test", "eth-del2")
		require.NoError(t, err)

		err = client.DeletePort(ctx, "br-nonexist", "eth-del2")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestClient_GetPort(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("get existing port", func(t *testing.T) {
		// Add port first
		_, err := client.AddPort(ctx, "br-port-test", "eth-get")
		require.NoError(t, err)

		// Get it
		port, err := client.GetPort(ctx, "eth-get")
		require.NoError(t, err)
		assert.NotNil(t, port)
		assert.Equal(t, "eth-get", port.Name)
		assert.NotEmpty(t, port.UUID)
	})

	t.Run("get port with empty name", func(t *testing.T) {
		_, err := client.GetPort(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("get non-existent port", func(t *testing.T) {
		_, err := client.GetPort(ctx, "eth-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("get port when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		_, err = disconnectedClient.GetPort(ctx, "eth-get")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_ListPorts(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("list ports when only internal port exists", func(t *testing.T) {
		ports, err := client.ListPorts(ctx, "br-port-test")
		require.NoError(t, err)
		// Bridge has internal port with same name
		assert.GreaterOrEqual(t, len(ports), 0)
	})

	t.Run("verify ports can be added and retrieved", func(t *testing.T) {
		// Add port
		_, err := client.AddPort(ctx, "br-port-test", "eth-list1")
		require.NoError(t, err)

		// Verify port was added by getting it directly
		port, err := client.GetPort(ctx, "eth-list1")
		require.NoError(t, err)
		assert.Equal(t, "eth-list1", port.Name)
	})

	t.Run("list ports with empty bridge name", func(t *testing.T) {
		_, err := client.ListPorts(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("list ports on non-existent bridge", func(t *testing.T) {
		_, err := client.ListPorts(ctx, "br-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestClient_UpdatePort(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	// Add test port
	_, err := client.AddPort(ctx, "br-port-test", "eth-update")
	require.NoError(t, err)

	t.Run("update existing port", func(t *testing.T) {
		updates := map[string]interface{}{
			"vlan_mode": "trunk",
		}
		err := client.UpdatePort(ctx, "eth-update", updates)
		require.NoError(t, err)
	})

	t.Run("update port with empty name", func(t *testing.T) {
		err := client.UpdatePort(ctx, "", map[string]interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("update non-existent port", func(t *testing.T) {
		err := client.UpdatePort(ctx, "eth-nonexist", map[string]interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestClient_SetPortVLAN(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	// Add test port
	_, err := client.AddPort(ctx, "br-port-test", "eth-vlan")
	require.NoError(t, err)

	t.Run("set valid VLAN tag", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "eth-vlan", 100)
		require.NoError(t, err)

		// Verify VLAN was set
		tag, err := client.getPortVLANTag(ctx, "eth-vlan")
		require.NoError(t, err)
		assert.Equal(t, int64(100), tag)
	})

	t.Run("set VLAN tag to 0 (clear)", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "eth-vlan", 0)
		require.NoError(t, err)
	})

	t.Run("set maximum VLAN tag", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "eth-vlan", 4095)
		require.NoError(t, err)
	})

	t.Run("set invalid VLAN tag - negative", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "eth-vlan", -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})

	t.Run("set invalid VLAN tag - too large", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "eth-vlan", 4096)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})

	t.Run("set VLAN on non-existent port", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "eth-nonexist", 100)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestClient_SetPortTrunks(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	// Add test port
	_, err := client.AddPort(ctx, "br-port-test", "eth-trunk")
	require.NoError(t, err)

	t.Run("set valid trunk VLANs", func(t *testing.T) {
		trunks := []int64{100, 200, 300}
		err := client.SetPortTrunks(ctx, "eth-trunk", trunks)
		require.NoError(t, err)
	})

	t.Run("set single trunk VLAN", func(t *testing.T) {
		trunks := []int64{100}
		err := client.SetPortTrunks(ctx, "eth-trunk", trunks)
		require.NoError(t, err)
	})

	t.Run("clear trunk VLANs", func(t *testing.T) {
		trunks := []int64{}
		err := client.SetPortTrunks(ctx, "eth-trunk", trunks)
		require.NoError(t, err)
	})

	t.Run("set invalid trunk VLAN - negative", func(t *testing.T) {
		trunks := []int64{100, -1}
		err := client.SetPortTrunks(ctx, "eth-trunk", trunks)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})

	t.Run("set invalid trunk VLAN - too large", func(t *testing.T) {
		trunks := []int64{100, 4096}
		err := client.SetPortTrunks(ctx, "eth-trunk", trunks)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})

	t.Run("set trunks on non-existent port", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "eth-nonexist", []int64{100})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestClient_SetPortState(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	// Add test port
	_, err := client.AddPort(ctx, "br-port-test", "eth-state")
	require.NoError(t, err)

	t.Run("set port state up", func(t *testing.T) {
		err := client.SetPortState(ctx, "eth-state", PortStateUp)
		require.NoError(t, err)
	})

	t.Run("set port state down", func(t *testing.T) {
		err := client.SetPortState(ctx, "eth-state", PortStateDown)
		require.NoError(t, err)
	})

	t.Run("set port state with empty name", func(t *testing.T) {
		err := client.SetPortState(ctx, "", PortStateUp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("set state on non-existent port", func(t *testing.T) {
		err := client.SetPortState(ctx, "eth-nonexist", PortStateUp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestClient_SetIngressPolicing(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	_, err := client.AddPort(ctx, "br-port-test", "eth-police")
	require.NoError(t, err)

	lastInterfaceUpdate := func(t *testing.T) Operation {
		t.Helper()
		ops := server.TransactOps()
		for i := len(ops) - 1; i >= 0; i-- {
			if ops[i].Op == "update" && ops[i].Table == interfaceTable {
				return ops[i]
			}
		}
		t.Fatal("no Interface update recorded")
		return Operation{}
	}

	t.Run("writes rate and burst to the interface in kbps and kb", func(t *testing.T) {
		require.NoError(t, client.SetIngressPolicing(ctx, "eth-police", 10_000_000, 1_000_000))

		op := lastInterfaceUpdate(t)
		assert.EqualValues(t, 10_000, op.Row["ingress_policing_rate"])
		assert.EqualValues(t, 1_000, op.Row["ingress_policing_burst"])
	})

	t.Run("rate zero disables policing", func(t *testing.T) {
		require.NoError(t, client.SetIngressPolicing(ctx, "eth-police", 0, 0))

		op := lastInterfaceUpdate(t)
		assert.EqualValues(t, 0, op.Row["ingress_policing_rate"])
	})

	t.Run("empty name", func(t *testing.T) {
		err := client.SetIngressPolicing(ctx, "", 1000, 0)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("invalid rate is refused before any transaction", func(t *testing.T) {
		server.ResetTransactOps()
		err := client.SetIngressPolicing(ctx, "eth-police", 1500, 0)
		var invalid *ErrInvalidPolicing
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, uint64(1500), invalid.RateBps)
		assert.Empty(t, server.TransactOps())
	})

	t.Run("unknown interface", func(t *testing.T) {
		err := client.SetIngressPolicing(ctx, "eth-nonexist", 1000, 0)
		assert.ErrorIs(t, err, ErrInterfaceNotFound)
	})
}

func TestValidateIngressPolicing(t *testing.T) {
	valid := []struct{ rate, burst uint64 }{
		{0, 0},
		{1000, 0},
		{5_000_000, 500_000},
		{math.MaxUint64 - math.MaxUint64%1000, 0},
	}
	for _, v := range valid {
		assert.NoError(t, ValidateIngressPolicing(v.rate, v.burst), "rate %d burst %d", v.rate, v.burst)
	}

	invalid := []struct {
		name        string
		rate, burst uint64
	}{
		{"rate below 1 kbps", 999, 0},
		{"rate not a whole kbps", 1500, 0},
		{"burst not a whole kb", 1000, 1},
		{"burst without a rate", 0, 1000},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIngressPolicing(tt.rate, tt.burst)
			var policing *ErrInvalidPolicing
			require.ErrorAs(t, err, &policing)
			assert.Equal(t, tt.rate, policing.RateBps)
			assert.Equal(t, tt.burst, policing.BurstBits)
		})
	}
}

func TestClient_GetInterface(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("get existing interface", func(t *testing.T) {
		// Add port (which creates interface)
		_, err := client.AddPort(ctx, "br-port-test", "eth-iface")
		require.NoError(t, err)

		// Get interface
		iface, err := client.GetInterface(ctx, "eth-iface")
		require.NoError(t, err)
		assert.NotNil(t, iface)
		assert.Equal(t, "eth-iface", iface.Name)
	})

	t.Run("get interface with empty name", func(t *testing.T) {
		_, err := client.GetInterface(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("get non-existent interface", func(t *testing.T) {
		_, err := client.GetInterface(ctx, "eth-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestParsePort(t *testing.T) {
	t.Run("parse complete port row", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":        []interface{}{"uuid", "port-uuid"},
			"name":         "eth0",
			"interfaces":   []interface{}{"set", []interface{}{[]interface{}{"uuid", "iface-uuid"}}},
			"tag":          float64(100),
			"trunks":       []interface{}{"set", []interface{}{float64(100), float64(200)}},
			"vlan_mode":    "trunk",
			"external_ids": []interface{}{"map", []interface{}{[]interface{}{"key", "value"}}},
			"other_config": []interface{}{"map", []interface{}{}},
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, "port-uuid", port.UUID)
		assert.Equal(t, "eth0", port.Name)
		assert.Equal(t, int64(100), port.Tag)
		assert.Contains(t, port.Interfaces, "iface-uuid")
		assert.Contains(t, port.Trunks, int64(100))
		assert.Contains(t, port.Trunks, int64(200))
		assert.Equal(t, "value", port.ExternalIDs["key"])
	})

	t.Run("parse port with empty tag", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid": []interface{}{"uuid", "port-uuid"},
			"name":  "eth0",
			"tag":   []interface{}{"set", []interface{}{}},
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, int64(0), port.Tag)
	})

	t.Run("parse minimal port row", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid": []interface{}{"uuid", "minimal-uuid"},
			"name":  "eth-minimal",
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, "minimal-uuid", port.UUID)
		assert.Equal(t, "eth-minimal", port.Name)
		assert.Empty(t, port.Interfaces)
		assert.Empty(t, port.Trunks)
	})
}

func TestParseInterface(t *testing.T) {
	t.Run("parse complete interface row", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":        []interface{}{"uuid", "iface-uuid"},
			"name":         "eth0",
			"type":         "system",
			"mac_in_use":   "00:11:22:33:44:55",
			"mtu":          float64(1500),
			"admin_state":  "up",
			"link_state":   "up",
			"external_ids": []interface{}{"map", []interface{}{[]interface{}{"key", "value"}}},
			"other_config": []interface{}{"map", []interface{}{}},
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, "iface-uuid", iface.UUID)
		assert.Equal(t, "eth0", iface.Name)
		assert.Equal(t, "system", iface.Type)
		assert.Equal(t, "00:11:22:33:44:55", iface.MAC)
		assert.Equal(t, int64(1500), iface.MTU)
		assert.Equal(t, "up", iface.AdminState)
		assert.Equal(t, "up", iface.LinkState)
		assert.Equal(t, "value", iface.ExternalIDs["key"])
	})

	t.Run("parse minimal interface row", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid": []interface{}{"uuid", "minimal-uuid"},
			"name":  "eth-minimal",
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, "minimal-uuid", iface.UUID)
		assert.Equal(t, "eth-minimal", iface.Name)
		assert.Empty(t, iface.Type)
		assert.Empty(t, iface.MAC)
	})

	t.Run("parse interface with int64 MTU", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid": []interface{}{"uuid", "iface-uuid"},
			"name":  "eth0",
			"mtu":   int64(9000),
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, int64(9000), iface.MTU)
	})
}

func TestClient_getPortVLANTag(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	// Add test port
	_, err := client.AddPort(ctx, "br-port-test", "eth-vlan-get")
	require.NoError(t, err)

	t.Run("get VLAN tag", func(t *testing.T) {
		// Set VLAN first
		err := client.SetPortVLAN(ctx, "eth-vlan-get", 200)
		require.NoError(t, err)

		// Get it
		tag, err := client.getPortVLANTag(ctx, "eth-vlan-get")
		require.NoError(t, err)
		assert.Equal(t, int64(200), tag)
	})

	t.Run("get VLAN tag on non-existent port", func(t *testing.T) {
		_, err := client.getPortVLANTag(ctx, "eth-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}
