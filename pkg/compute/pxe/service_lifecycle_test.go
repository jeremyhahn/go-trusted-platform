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

package pxe

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
)

const lifecycleBindHost = "127.0.0.1"

// lifecyclePort asks the OS for a loopback TCP port nothing listens on.
func lifecyclePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(lifecycleBindHost, "0"))
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// lifecycleUDPPort asks the OS for a loopback UDP port nothing listens on.
func lifecycleUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", net.JoinHostPort(lifecycleBindHost, "0"))
	require.NoError(t, err)
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// lifecycleService returns an initialized service whose iPXE server binds
// HTTP on httpPort and TFTP on a free port, both on loopback.
func lifecycleService(t *testing.T, httpPort int) Service {
	t.Helper()
	ipxeCfg := ipxe.DefaultServerConfig()
	ipxeCfg.BindHost = lifecycleBindHost
	ipxeCfg.HTTPPort = httpPort
	ipxeCfg.TFTPPort = lifecycleUDPPort(t)
	ipxeCfg.LocalFilesDir = t.TempDir()
	ipxeCfg.InstallsDir = t.TempDir()
	ipxeCfg.BootEntries = []ipxe.BootEntry{
		{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
	}

	cfg := createTestConfig()
	cfg.IPXEConfig = ipxeCfg

	svc := NewService(WithVLANIntegration(NewNoopVLANIntegration(testNetPlan)))
	require.NoError(t, svc.Initialize(context.Background(), cfg))
	t.Cleanup(func() { assert.NoError(t, svc.Close()) })
	return svc
}

// dialHTTP requires the iPXE HTTP listener on port to accept a connection.
func dialHTTP(t *testing.T, port int) {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort(lifecycleBindHost, strconv.Itoa(port)))
	require.NoError(t, err, "the iPXE HTTP listener must accept connections")
	require.NoError(t, conn.Close())
}

// TestService_StartStopStart requires a stopped service to start again: an
// ipxe.Server is single-use, so the second Start must run a fresh one.
func TestService_StartStopStart(t *testing.T) {
	port := lifecyclePort(t)
	svc := lifecycleService(t, port)
	ctx := context.Background()

	require.NoError(t, svc.Start(ctx))
	require.True(t, svc.IsRunning())
	dialHTTP(t, port)

	require.NoError(t, svc.Stop(ctx))
	require.False(t, svc.IsRunning())

	require.NoError(t, svc.Start(ctx), "Start after Stop must run a fresh iPXE server")
	require.True(t, svc.IsRunning())
	dialHTTP(t, port)
	require.NoError(t, svc.Stop(ctx))
}

// TestService_StartOutlivesRequestContext requires the server started by a
// request to keep serving after that request's context ends: it runs until
// Stop or Close.
func TestService_StartOutlivesRequestContext(t *testing.T) {
	port := lifecyclePort(t)
	svc := lifecycleService(t, port)
	request, endRequest := context.WithCancel(context.Background())

	require.NoError(t, svc.Start(request))
	endRequest()

	run := svc.(*service).ipxeRun
	select {
	case <-run.exited:
		t.Fatalf("the iPXE server exited when the request context ended: %v", run.err)
	default:
	}
	require.True(t, svc.IsRunning())
	dialHTTP(t, port)

	require.NoError(t, svc.Stop(context.Background()))
	<-run.exited
}

// TestService_Start_ListenerBindFails requires Start to report a listener
// that cannot bind as ErrProvisioningFailed, leave the service stopped, and
// start a fresh server once the port is free.
func TestService_Start_ListenerBindFails(t *testing.T) {
	taken, err := net.Listen("tcp", net.JoinHostPort(lifecycleBindHost, "0"))
	require.NoError(t, err)
	port := taken.Addr().(*net.TCPAddr).Port
	svc := lifecycleService(t, port)
	ctx := context.Background()

	err = svc.Start(ctx)
	var failed ErrProvisioningFailed
	require.True(t, errors.As(err, &failed), "want ErrProvisioningFailed, got %v", err)
	assert.Equal(t, "failed to start iPXE server", failed.Reason)
	require.False(t, svc.IsRunning())

	require.NoError(t, taken.Close())
	require.NoError(t, svc.Start(ctx))
	dialHTTP(t, port)
	require.NoError(t, svc.Stop(ctx))
}

// TestService_Start_RequestAlreadyEnded requires Start to refuse a request
// whose context has ended with ErrProvisioningFailed carrying
// context.Canceled, and to start no server.
func TestService_Start_RequestAlreadyEnded(t *testing.T) {
	svc := lifecycleService(t, lifecyclePort(t))
	request, endRequest := context.WithCancel(context.Background())
	endRequest()

	err := svc.Start(request)
	var failed ErrProvisioningFailed
	require.True(t, errors.As(err, &failed), "want ErrProvisioningFailed, got %v", err)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, svc.IsRunning())
	assert.Nil(t, svc.(*service).ipxeRun, "no iPXE server may have been started")
}

// TestService_WatchIPXERun_ServerExitedOnItsOwn requires the service to be
// marked stopped when its running server exits without a Stop, so the
// next Start runs a fresh one instead of refusing as already running.
func TestService_WatchIPXERun_ServerExitedOnItsOwn(t *testing.T) {
	svc, _ := initializeTestService(t)
	inner := svc.(*service)
	run := &ipxeRun{exited: make(chan struct{}), err: &MessageError{Msg: "TFTP listener failed"}}
	close(run.exited)
	inner.ipxeRun = run
	inner.running.Store(true)

	inner.watchIPXERun(run)

	assert.False(t, svc.IsRunning())
	var notRunning ErrServiceNotRunning
	require.ErrorAs(t, svc.Stop(context.Background()), &notRunning)
}

// TestService_WatchIPXERun_ReplacedRunLeftAlone requires a watcher of a
// run that a later Start replaced to leave the running service alone.
func TestService_WatchIPXERun_ReplacedRunLeftAlone(t *testing.T) {
	svc, _ := initializeTestService(t)
	inner := svc.(*service)
	old := &ipxeRun{exited: make(chan struct{})}
	close(old.exited)
	inner.ipxeRun = &ipxeRun{exited: make(chan struct{})}
	inner.running.Store(true)

	inner.watchIPXERun(old)

	assert.True(t, svc.IsRunning())
}
