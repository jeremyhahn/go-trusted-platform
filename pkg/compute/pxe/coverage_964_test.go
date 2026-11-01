package pxe

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// planWithout numbers the default zones except the one named.
func planWithout(t *testing.T, missing zone.Zone) *netplan.Plan {
	t.Helper()
	var zones []zone.ZoneConfig
	for _, z := range zone.Defaults() {
		if z.Name != missing {
			zones = append(zones, z)
		}
	}
	p, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)
	return p
}

func TestErrIPXEServerExited_Error(t *testing.T) {
	var err error = ErrIPXEServerExited{}
	assert.Equal(t, "pxe: iPXE server exited before it was ready", err.Error())

	var exited ErrIPXEServerExited
	assert.True(t, errors.As(&WrappedError{Msg: "start", Err: err}, &exited))
}

func TestNewServiceConfig_VLANsFromPlan(t *testing.T) {
	cfg, err := NewServiceConfig(testNetPlan)
	require.NoError(t, err)

	quarantine, err := testNetPlan.MustZone(zone.ZoneQuarantine)
	require.NoError(t, err)
	provisioning, err := testNetPlan.MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)

	assert.Equal(t, quarantine.VLAN, cfg.QuarantineVLAN)
	assert.Equal(t, provisioning.VLAN, cfg.ProvisioningVLAN)
	assert.NotEqual(t, cfg.QuarantineVLAN, cfg.ProvisioningVLAN)
	assert.Equal(t, DefaultMaxRetries, cfg.MaxRetries)
	assert.True(t, cfg.EnableAutoQuarantine)
}

func TestNewServiceConfig_MissingZone(t *testing.T) {
	tests := []struct {
		name    string
		missing zone.Zone
		msg     string
	}{
		{name: "quarantine", missing: zone.ZoneQuarantine, msg: "quarantine zone"},
		{name: "provisioning", missing: zone.ZoneProvisioning, msg: "provisioning zone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewServiceConfig(planWithout(t, tt.missing))
			require.Error(t, err)
			assert.Nil(t, cfg)

			var wrapped *WrappedError
			require.True(t, errors.As(err, &wrapped))
			assert.Equal(t, tt.msg, wrapped.Msg)

			var unknown netplan.ErrUnknownZone
			require.True(t, errors.As(err, &unknown))
			assert.Equal(t, tt.missing, unknown.Zone)
		})
	}
}

func TestService_ApplyVLANForState_ZoneByState(t *testing.T) {
	quarantine, err := testNetPlan.MustZone(zone.ZoneQuarantine)
	require.NoError(t, err)
	provisioning, err := testNetPlan.MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)

	tests := []struct {
		state    ProvisioningState
		wantVLAN uint16 // zero: no flows are applied
	}{
		{state: StateBooting, wantVLAN: provisioning.VLAN},
		{state: StateInstalling, wantVLAN: provisioning.VLAN},
		{state: StateEnrolled, wantVLAN: provisioning.VLAN},
		{state: StateAuthorizing, wantVLAN: provisioning.VLAN},
		{state: StateQuarantined, wantVLAN: quarantine.VLAN},
		{state: StateFailed, wantVLAN: quarantine.VLAN},
		{state: StateDiscovered, wantVLAN: 0},
	}
	mac, err := net.ParseMAC("52:54:00:12:34:56")
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			ctx := context.Background()
			vlans := NewNoopVLANIntegration(testNetPlan)
			svc := &service{logger: logging.DefaultLogger(), vlanManager: vlans}
			device := &DeviceInfo{PortID: "port-1", MACAddress: mac}

			require.NoError(t, svc.applyVLANForState(ctx, device, tt.state))

			got, err := vlans.GetCurrentVLAN(ctx, "port-1")
			if tt.wantVLAN == 0 {
				var notFound ErrDeviceNotFound
				assert.True(t, errors.As(err, &notFound), "no flows expected, got VLAN %d", got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantVLAN, got)
		})
	}
}

func TestService_ApplyVLANForState_PropagatesFlowError(t *testing.T) {
	ctx := context.Background()
	vlans := NewNoopVLANIntegration(testNetPlan)
	require.NoError(t, vlans.Close())
	svc := &service{logger: logging.DefaultLogger(), vlanManager: vlans}
	mac, err := net.ParseMAC("52:54:00:12:34:56")
	require.NoError(t, err)

	err = svc.applyVLANForState(ctx, &DeviceInfo{PortID: "port-1", MACAddress: mac}, StateQuarantined)
	var notRunning ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunning))
}
