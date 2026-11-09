package ovs

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_AddBond(t *testing.T) {
	client, server := setupPortTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("creates the bond port with its mode and both members", func(t *testing.T) {
		port, err := client.AddBond(ctx, "br-port-test", "bond0", []string{"eth10", "eth11"}, "balance-slb", "active")
		require.NoError(t, err)
		require.NotNil(t, port)
		assert.Equal(t, "bond0", port.Name)
		assert.Len(t, port.Interfaces, 2)

		// The Port row carries the bond mode and LACP setting as written.
		rows, err := client.Select(ctx, portTable,
			[]Condition{NewCondition("name", "==", "bond0")},
			[]string{"bond_mode", "lacp"})
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, "balance-slb", rows[0]["bond_mode"])
		assert.Equal(t, "active", rows[0]["lacp"])

		// The bridge holds the bond port.
		br, err := client.GetBridge(ctx, "br-port-test")
		require.NoError(t, err)
		assert.Contains(t, br.Ports, port.UUID)

		// The bond's interface references are exactly the requested members.
		var memberUUIDs []string
		for _, member := range []string{"eth10", "eth11"} {
			iface, err := client.GetInterface(ctx, member)
			require.NoError(t, err)
			assert.Equal(t, member, iface.Name)
			memberUUIDs = append(memberUUIDs, iface.UUID)
		}
		assert.ElementsMatch(t, memberUUIDs, port.Interfaces)
	})

	t.Run("refuses a bond that already exists", func(t *testing.T) {
		_, err := client.AddBond(ctx, "br-port-test", "bond0", []string{"eth12", "eth13"}, "", "")
		assert.ErrorIs(t, err, ErrPortExists)
	})

	t.Run("returns the bridge lookup error for an unknown bridge", func(t *testing.T) {
		_, err := client.AddBond(ctx, "br-missing", "bond1", []string{"eth14", "eth15"}, "", "")
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	tests := []struct {
		name    string
		bridge  string
		bond    string
		members []string
		want    error
	}{
		{name: "empty bridge name", bridge: "", bond: "bond2", members: []string{"a", "b"}, want: ErrInvalidBridgeName},
		{name: "empty bond name", bridge: "br-port-test", bond: "", members: []string{"a", "b"}, want: ErrInvalidPortName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.AddBond(ctx, tc.bridge, tc.bond, tc.members, "", "")
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("refuses fewer than two members", func(t *testing.T) {
		_, err := client.AddBond(ctx, "br-port-test", "bond3", []string{"eth16"}, "", "")
		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Contains(t, msgErr.Msg, "got 1")

		_, err = client.GetPort(ctx, "bond3")
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

func TestErrorTypes_Messages(t *testing.T) {
	cause := errors.New("boom")

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "sentinel with cause",
			err:  &SentinelCauseError{Sentinel: ErrPortExists, Cause: cause},
			want: ErrPortExists.Error() + ": boom",
		},
		{
			name: "invalid cookie",
			err:  &ErrInvalidCookie{Cookie: "0xzz", Err: cause},
			want: "ovs: invalid flow cookie " + strconv.Quote("0xzz") + ": boom",
		},
		{
			name: "invalid port type",
			err:  &ErrInvalidPortType{Type: "bogus"},
			want: "invalid port type: bogus",
		},
		{
			name: "invalid policing",
			err:  &ErrInvalidPolicing{RateBps: 1500, BurstBits: 2000},
			want: "ovs: invalid ingress policing: rate 1500 bps, burst 2000 bits (each must be 0 or a whole multiple of 1000, and a burst needs a rate)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.err.Error())
		})
	}
}

func TestErrorTypes_Unwrap(t *testing.T) {
	cause := errors.New("parse failure")

	sentinel := &SentinelCauseError{Sentinel: ErrPortExists, Cause: cause}
	assert.ErrorIs(t, sentinel, ErrPortExists)
	assert.ErrorIs(t, sentinel, cause)

	cookie := &ErrInvalidCookie{Cookie: "x", Err: cause}
	assert.ErrorIs(t, cookie, cause)
	assert.NotErrorIs(t, cookie, ErrPortExists)
}
