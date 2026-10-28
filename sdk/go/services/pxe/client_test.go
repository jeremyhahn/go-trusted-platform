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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingPXEClient records the UpdateState requests the client sends and
// answers each with the device in the requested state.
type recordingPXEClient struct {
	platformv1.PXEServiceClient
	requests []*platformv1.UpdatePXEStateRequest
	err      error
}

func (r *recordingPXEClient) UpdateState(_ context.Context, req *platformv1.UpdatePXEStateRequest, _ ...grpc.CallOption) (*platformv1.UpdatePXEStateResponse, error) {
	r.requests = append(r.requests, req)
	if r.err != nil {
		return nil, r.err
	}
	return &platformv1.UpdatePXEStateResponse{
		Device: &platformv1.PXEDeviceInfo{Id: req.GetDeviceId(), State: req.GetState()},
	}, nil
}

func TestSetDeviceInstalling_SendsTheBinding(t *testing.T) {
	recorder := &recordingPXEClient{}
	client := &Client{grpc: recorder}

	device, err := client.SetDeviceInstalling(context.Background(), "pxe-dev-1", "ab12", "installer started")

	require.NoError(t, err)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING, device.GetState())
	require.Len(t, recorder.requests, 1)
	assert.Equal(t, "pxe-dev-1", recorder.requests[0].GetDeviceId())
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING, recorder.requests[0].GetState())
	assert.Equal(t, "installer started", recorder.requests[0].GetReason())
	assert.Equal(t, "ab12", recorder.requests[0].GetInstallCertificateSha256())
}

// An empty fingerprint would turn the request into a plain state update that
// leaves the device installing with no binding (Codex review 7971): nothing
// is sent, so the device stays booting.
func TestSetDeviceInstalling_RefusesAnEmptyFingerprint(t *testing.T) {
	recorder := &recordingPXEClient{}
	client := &Client{grpc: recorder}

	device, err := client.SetDeviceInstalling(context.Background(), "pxe-dev-1", "", "installer started")

	assert.Nil(t, device)
	var required *ErrInstallCertificateRequired
	require.True(t, errors.As(err, &required), "got %v", err)
	assert.Equal(t, "pxe-dev-1", required.ID)
	assert.Empty(t, recorder.requests, "no request may reach the service")
}

func TestSetDeviceInstalling_WrapsAServiceError(t *testing.T) {
	refused := status.Error(codes.AlreadyExists, "certificate in use")
	client := &Client{grpc: &recordingPXEClient{err: refused}}

	device, err := client.SetDeviceInstalling(context.Background(), "pxe-dev-1", "ab12", "installer started")

	assert.Nil(t, device)
	var failed *ErrSetInstallingFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Equal(t, "pxe-dev-1", failed.ID)
	assert.Equal(t, codes.AlreadyExists, status.Code(errors.Unwrap(err)))
}
