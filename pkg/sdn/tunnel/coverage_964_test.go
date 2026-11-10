package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

var errCause964 = errors.New("kernel said no")

func TestErrorMessages_964(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"rekey failed", &ErrRekeyFailed{Name: "t1", Cause: errCause964},
			"tunnel t1: rekey failed: kernel said no"},
		{"foreign policy", &ErrIPsecForeignPolicy{Src: "10.0.0.1", Dst: "10.0.0.2", Dir: "out"},
			"ipsec policy 10.0.0.1 -> 10.0.0.2 out is another installer's"},
		{"foreign SA", &ErrIPsecForeignSA{Dst: "10.0.0.2", SPI: 4097},
			"ipsec SA 10.0.0.2 spi 4097 is another installer's"},
		{"peer invalid", &ErrPeerInvalid{Name: "hub", Reason: "bad key"},
			"tunnel hub: invalid peer: bad key"},
		{"peer configure failed", &ErrPeerConfigureFailed{Name: "hub", Cause: errCause964},
			"tunnel hub: peer configuration failed: kernel said no"},
		{"device not up", &ErrDeviceNotUp{Name: "tun0"},
			"tunnel tun0: device is not up"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestErrorUnwrap_964(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"rekey failed", &ErrRekeyFailed{Name: "t1", Cause: errCause964}},
		{"peer configure failed", &ErrPeerConfigureFailed{Name: "hub", Cause: errCause964}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.err, errCause964)
		})
	}

	// An error without a cause in its chain does not match.
	assert.False(t, errors.Is(&ErrDeviceNotUp{Name: "tun0"}, errCause964))
}

func TestManagerUplinks_964(t *testing.T) {
	t.Run("no uplink manager returns nil", func(t *testing.T) {
		m := newManagerWithOps(testLogger(), newMockNetlinkOps())
		assert.Nil(t, m.Uplinks())
	})

	t.Run("lists the configured uplinks", func(t *testing.T) {
		mock := uplinkMock()
		u := newUplinkManagerWithOps(testLogger(), mock)
		require.NoError(t, u.EnsureUplink(context.Background(), attUplink()))
		m := newManagerWithOps(testLogger(), mock, WithUplinks(u))

		got := m.Uplinks()
		require.Len(t, got, 1)
		assert.Equal(t, "isp-a", got[0].Name)
		assert.Equal(t, "eth6", got[0].Interface)
		assert.Equal(t, 101, got[0].Table)
		assert.Equal(t, 2, got[0].RuleCount)
	})
}

func TestNewUplinkManager_964(t *testing.T) {
	u := NewUplinkManager(testLogger())
	require.NotNil(t, u)
	assert.Empty(t, u.List())
	assert.False(t, u.Has("isp-a"))

	var nf *ErrUplinkNotFound
	require.ErrorAs(t, u.RemoveUplink(context.Background(), "isp-a"), &nf)
	assert.Equal(t, "isp-a", nf.Name)
}

func TestEffectiveReplayWindow_964(t *testing.T) {
	assert.Equal(t, 128, (&IPsecConfig{ReplayWindow: 128}).effectiveReplayWindow())
	assert.Equal(t, DefaultReplayWindow, (&IPsecConfig{}).effectiveReplayWindow())
	assert.Equal(t, DefaultReplayWindow, (&IPsecConfig{ReplayWindow: -1}).effectiveReplayWindow())
}

func TestEffectiveKeepalive_964(t *testing.T) {
	assert.Equal(t, 7*time.Second, (&WireGuardConfig{PersistentKeepalive: 7 * time.Second}).effectiveKeepalive())
	assert.Equal(t, DefaultWireGuardKeepalive, (&WireGuardConfig{}).effectiveKeepalive())
	assert.Equal(t, DefaultWireGuardKeepalive, (&WireGuardConfig{PersistentKeepalive: -time.Second}).effectiveKeepalive())
}

func TestLinkOperState_964(t *testing.T) {
	tests := []struct {
		name  string
		attrs vnl.LinkAttrs
		want  TunnelState
	}{
		{"oper up", vnl.LinkAttrs{OperState: vnl.OperUp}, TunnelStateUp},
		{"oper down even if admin up", vnl.LinkAttrs{OperState: vnl.OperDown, Flags: net.FlagUp}, TunnelStateDown},
		{"unknown oper, admin up", vnl.LinkAttrs{OperState: vnl.OperUnknown, Flags: net.FlagUp}, TunnelStateUp},
		{"unknown oper, admin down", vnl.LinkAttrs{OperState: vnl.OperUnknown}, TunnelStateUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := tt.attrs
			assert.Equal(t, tt.want, linkOperState(&attrs))
		})
	}
}
