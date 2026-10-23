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

package cli

import (
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// healthyDaemon answers GetVersion, which is all the embedded tests call.
type healthyDaemon struct {
	platformv1.UnimplementedPlatformDaemonServer
}

func (healthyDaemon) GetVersion(context.Context, *platformv1.GetVersionRequest) (*platformv1.GetVersionResponse, error) {
	return &platformv1.GetVersionResponse{Version: "in-process"}, nil
}

// fakeEmbeddedHost records how the base command drives it.
type fakeEmbeddedHost struct {
	services *embedded.ServiceRegistry
	stops    int
	stopErr  error
}

func (h *fakeEmbeddedHost) Services() *embedded.ServiceRegistry { return h.services }

func (h *fakeEmbeddedHost) Stop(context.Context) error {
	h.stops++
	return h.stopErr
}

func embeddedFlags(c *Context, start func(context.Context, *Context) (EmbeddedHost, error)) *CommonFlags {
	return &CommonFlags{
		OutputFormat:  OutputFormatTable,
		GetContext:    func() (*Context, error) { return c, nil },
		StartEmbedded: start,
	}
}

// An embedded context hosts platformd in-process and the commands reach it
// through the SDK's embedded transport; closing the command stops the host.
// Before #691 every embedded command failed at connect: nothing built the
// ServiceRegistry the transport dispatches to.
func TestNewBaseCommand_EmbeddedContextHostsTheDaemon(t *testing.T) {
	host := &fakeEmbeddedHost{services: &embedded.ServiceRegistry{Daemon: healthyDaemon{}}}
	c := &Context{Name: "standalone", Type: ContextTypeEmbedded}
	var startedFor *Context
	flags := embeddedFlags(c, func(_ context.Context, got *Context) (EmbeddedHost, error) {
		startedFor = got
		return host, nil
	})

	base, err := NewBaseCommand(flags)
	require.NoError(t, err)
	assert.Same(t, c, startedFor)

	resp, err := base.Client().Daemon().GetVersion(base.Context(), &platformv1.GetVersionRequest{})
	require.NoError(t, err)
	assert.Equal(t, "in-process", resp.GetVersion())

	require.NoError(t, base.Close())
	assert.Equal(t, 1, host.stops)
}

// --transport embedded on a local context is embedded too.
func TestNewBaseCommand_EmbeddedTransportOverrideHostsTheDaemon(t *testing.T) {
	host := &fakeEmbeddedHost{services: &embedded.ServiceRegistry{Daemon: healthyDaemon{}}}
	c := &Context{Name: "local", Type: ContextTypeLocal, Protocol: "embedded", Local: &LocalContext{SocketPath: "/nonexistent.sock"}}

	base, err := NewBaseCommand(embeddedFlags(c, func(context.Context, *Context) (EmbeddedHost, error) {
		return host, nil
	}))
	require.NoError(t, err)
	require.NoError(t, base.Close())
	assert.Equal(t, 1, host.stops)
}

func TestNewBaseCommand_EmbeddedWithoutAHostIsRefused(t *testing.T) {
	c := &Context{Name: "standalone", Type: ContextTypeEmbedded}

	base, err := NewBaseCommand(embeddedFlags(c, nil))
	assert.Nil(t, base)
	var unavailable ErrEmbeddedHostUnavailable
	require.ErrorAs(t, err, &unavailable)
}

func TestNewBaseCommand_EmbeddedHostFailureIsReturned(t *testing.T) {
	c := &Context{Name: "standalone", Type: ContextTypeEmbedded}
	cause := errors.New("platformd config unreadable")

	base, err := NewBaseCommand(embeddedFlags(c, func(context.Context, *Context) (EmbeddedHost, error) {
		return nil, cause
	}))
	assert.Nil(t, base)
	require.ErrorIs(t, err, cause)
}

// A network context never starts a host.
func TestNewBaseCommand_NetworkContextStartsNoHost(t *testing.T) {
	c := &Context{Name: "remote", Type: ContextTypeRemote, Remote: &RemoteContext{Server: "127.0.0.1:1"}}
	started := false

	base, err := NewBaseCommand(embeddedFlags(c, func(context.Context, *Context) (EmbeddedHost, error) {
		started = true
		return nil, errors.New("must not start")
	}))
	if err == nil {
		require.NoError(t, base.Close())
	}
	assert.False(t, started)
}

// Close reports a host that fails to stop.
func TestBaseCommand_CloseReportsAHostStopFailure(t *testing.T) {
	cause := errors.New("stop failed")
	host := &fakeEmbeddedHost{services: &embedded.ServiceRegistry{Daemon: healthyDaemon{}}, stopErr: cause}
	c := &Context{Name: "standalone", Type: ContextTypeEmbedded}

	base, err := NewBaseCommand(embeddedFlags(c, func(context.Context, *Context) (EmbeddedHost, error) {
		return host, nil
	}))
	require.NoError(t, err)
	require.ErrorIs(t, base.Close(), cause)
}
