package commands

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDaemonOnlySwitchDaemon records the provider the daemon-only wiring
// mounts on the REST listener.
type fakeDaemonOnlySwitchDaemon struct {
	grpcSvc   *daemon.SwitchGRPCService
	mountErr  error
	mounted   bool
	mountedBy device.SwitchServiceProvider
}

func (f *fakeDaemonOnlySwitchDaemon) SwitchService() *daemon.SwitchGRPCService {
	return f.grpcSvc
}

func (f *fakeDaemonOnlySwitchDaemon) MountSwitchREST(svc device.SwitchServiceProvider) error {
	f.mounted = true
	f.mountedBy = svc
	return f.mountErr
}

func newFakeDaemonOnlySwitchDaemon() *fakeDaemonOnlySwitchDaemon {
	return &fakeDaemonOnlySwitchDaemon{grpcSvc: daemon.NewSwitchGRPCService(logging.DefaultLogger(), nil)}
}

func TestWireDaemonOnlySwitchService_MountsRESTAndGRPC(t *testing.T) {
	svc, err := newSwitchService(logging.DefaultLogger(), coreSwitchApp())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	fake := newFakeDaemonOnlySwitchDaemon()
	require.NoError(t, wireDaemonOnlySwitchService(fake, svc))
	assert.True(t, fake.mounted)
	assert.NotNil(t, fake.mountedBy)

	_, err = fake.grpcSvc.ListPorts(context.Background(), &platformv1.ListSwitchPortsRequest{SwitchName: "core-1"})
	require.NoError(t, err)
}

func TestWireDaemonOnlySwitchService_NoSwitchMountsNothing(t *testing.T) {
	fake := newFakeDaemonOnlySwitchDaemon()
	require.NoError(t, wireDaemonOnlySwitchService(fake, nil))
	assert.False(t, fake.mounted)
}

func TestWireDaemonOnlySwitchService_MountErrorStopsStartup(t *testing.T) {
	svc, err := newSwitchService(logging.DefaultLogger(), coreSwitchApp())
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	mountErr := errors.New("switch routes refused")
	fake := newFakeDaemonOnlySwitchDaemon()
	fake.mountErr = mountErr
	err = wireDaemonOnlySwitchService(fake, svc)
	require.Error(t, err)
	assert.True(t, errors.Is(err, mountErr), "error = %v", err)
}
