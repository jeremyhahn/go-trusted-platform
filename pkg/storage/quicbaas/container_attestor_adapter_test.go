// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package quicbaas

import (
	"context"
	"errors"
	"testing"

	baassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// recordingContainerAttestor records the request it receives and answers
// with a fixed response or error.
type recordingContainerAttestor struct {
	got  *service.AttestContainerRequest
	resp *service.AttestContainerResponse
	err  error
}

func (r *recordingContainerAttestor) AttestContainer(_ context.Context, req *service.AttestContainerRequest) (*service.AttestContainerResponse, error) {
	r.got = req
	return r.resp, r.err
}

var errRecordedAttestor = errors.New("recorded attestor failure")

func TestContainerAttestorAdapter_RefusesUntilSet(t *testing.T) {
	adapter := NewContainerAttestorAdapter()

	resp, err := adapter.AttestContainer(context.Background(), &service.AttestContainerRequest{ContainerID: "c1"})

	assert.Nil(t, resp)
	var notAvailable ErrContainerAttestorNotAvailable
	require.ErrorAs(t, err, &notAvailable)
	assert.Contains(t, err.Error(), "not wired on this node")
}

func TestContainerAttestorAdapter_ForwardsToInstalledAttestor(t *testing.T) {
	want := &service.AttestContainerResponse{Attested: true, DeviceID: "7"}
	inner := &recordingContainerAttestor{resp: want}
	adapter := NewContainerAttestorAdapter()
	adapter.SetAttestor(inner)

	req := &service.AttestContainerRequest{ContainerID: "c1", DeviceID: "7"}
	resp, err := adapter.AttestContainer(context.Background(), req)

	require.NoError(t, err)
	assert.Same(t, want, resp)
	assert.Same(t, req, inner.got)
}

func TestContainerAttestorAdapter_ForwardsAttestorError(t *testing.T) {
	adapter := NewContainerAttestorAdapter()
	adapter.SetAttestor(&recordingContainerAttestor{err: errRecordedAttestor})

	resp, err := adapter.AttestContainer(context.Background(), &service.AttestContainerRequest{})

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, errRecordedAttestor)
}

func TestContainerAttestorAdapter_SetNilClears(t *testing.T) {
	adapter := NewContainerAttestorAdapter()
	adapter.SetAttestor(&recordingContainerAttestor{resp: &service.AttestContainerResponse{Attested: true}})
	adapter.SetAttestor(nil)

	_, err := adapter.AttestContainer(context.Background(), &service.AttestContainerRequest{})

	var notAvailable ErrContainerAttestorNotAvailable
	assert.ErrorAs(t, err, &notAvailable)
}

func TestContainerAttestorAdapter_NilReceiver(t *testing.T) {
	var adapter *ContainerAttestorAdapter

	assert.NotPanics(t, func() { adapter.SetAttestor(&recordingContainerAttestor{}) })
	_, err := adapter.AttestContainer(context.Background(), &service.AttestContainerRequest{})

	var notAvailable ErrContainerAttestorNotAvailable
	assert.ErrorAs(t, err, &notAvailable)
}

func TestEmbeddedServer_ContainerAttestor(t *testing.T) {
	server, err := NewEmbeddedServer(TestConfig(t), logging.DefaultLogger())
	require.NoError(t, err)

	assert.NotNil(t, server.ContainerAttestor())
	assert.Nil(t, (*EmbeddedServer)(nil).ContainerAttestor())
}

func TestFactory_ContainerAttestor_NilWithoutEmbeddedServer(t *testing.T) {
	assert.Nil(t, (&Factory{}).ContainerAttestor())
}

// TestEmbeddedServer_ContainerAttestorRegistered proves the adapter is the
// attestor the SDK reaches: Security().Attestation().AttestContainer refuses
// until an attestor is installed, then returns what that attestor answers.
func TestEmbeddedServer_ContainerAttestorRegistered(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, server.Start(ctx))
	defer func() { _ = server.Stop(ctx) }()

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)
	require.NoError(t, client.StartWithService(ctx, server.Service()))
	defer func() { _ = client.Stop(ctx) }()

	attestation := client.SDK().Security().Attestation()
	req := &baassdk.AttestContainerRequest{ContainerID: "c1", DeviceID: "7", Image: "registry.test/app:1"}

	_, err = attestation.AttestContainer(ctx, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ErrContainerAttestorNotAvailable{}.Error())

	inner := &recordingContainerAttestor{resp: &service.AttestContainerResponse{Attested: true, DeviceID: "7"}}
	server.ContainerAttestor().SetAttestor(inner)

	resp, err := attestation.AttestContainer(ctx, req)
	require.NoError(t, err)
	assert.True(t, resp.Attested)
	assert.Equal(t, "7", resp.DeviceID)
	require.NotNil(t, inner.got)
	assert.Equal(t, "c1", inner.got.ContainerID)
}
