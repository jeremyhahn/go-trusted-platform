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

package device

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// updateService answers GetDevice from stored and records UpdateDevice.
type updateService struct {
	platformv1.DeviceServiceClient

	stored    *platformv1.Device
	updated   *platformv1.Device
	getErr    error
	updateErr error
}

func (s *updateService) GetDevice(_ context.Context, _ *platformv1.GetDeviceRequest, _ ...grpc.CallOption) (*platformv1.GetDeviceResponse, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return &platformv1.GetDeviceResponse{Device: s.stored}, nil
}

func (s *updateService) UpdateDevice(_ context.Context, in *platformv1.UpdateDeviceRequest, _ ...grpc.CallOption) (*platformv1.UpdateDeviceResponse, error) {
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	s.updated = in.GetDevice()
	return &platformv1.UpdateDeviceResponse{Device: s.updated}, nil
}

func TestRunUpdate_ValidatesBeforeConnecting(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	assert.Equal(t, ErrInvalidDeviceID{ID: "abc"}, runUpdate(flags, "abc", &updateFlags{model: "r650"}))
	assert.Equal(t, ErrDeviceUpdateNoChanges{ID: 7}, runUpdate(flags, "7", &updateFlags{}))
}

func TestUpdateFlags_Changes(t *testing.T) {
	assert.False(t, (&updateFlags{}).changes())
	assert.True(t, (&updateFlags{hashAlgoSet: true}).changes(), "--hash-algo 0 is still a change")
	assert.True(t, (&updateFlags{signingPub: "pub"}).changes())
}

func TestUpdateAndPrint_ChangesOnlyNamedFields(t *testing.T) {
	stub := &updateService{stored: &platformv1.Device{
		Id: 7, Serial: "SN-7", Model: "r640", AttestPub: "keep", HashAlgoId: 11,
	}}
	printer, out := jsonPrinter()
	uf := &updateFlags{model: "r650"}
	require.NoError(t, updateAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON, 7, uf, ""))

	require.NotNil(t, stub.updated)
	assert.Equal(t, "r650", stub.updated.GetModel())
	assert.Equal(t, "SN-7", stub.updated.GetSerial())
	assert.Equal(t, "keep", stub.updated.GetAttestPub())
	assert.EqualValues(t, 11, stub.updated.GetHashAlgoId())
	assert.Equal(t, "r650", decodePrinted(t, out)["model"])
}

func TestUpdateAndPrint_Failures(t *testing.T) {
	printer, _ := jsonPrinter()

	missing := &updateService{getErr: status.Error(codes.NotFound, "no device")}
	err := updateAndPrint(context.Background(), device.NewClientFromGRPC(missing), printer, cli.OutputFormatJSON, 7, &updateFlags{model: "x"}, "")
	var getFailed ErrGetDeviceFailed
	require.ErrorAs(t, err, &getFailed)
	assert.Nil(t, missing.updated)

	empty := &updateService{}
	err = updateAndPrint(context.Background(), device.NewClientFromGRPC(empty), printer, cli.OutputFormatJSON, 7, &updateFlags{model: "x"}, "")
	assert.Equal(t, ErrDeviceNotFound{ID: 7}, err)

	rejected := &updateService{stored: &platformv1.Device{Id: 7}, updateErr: status.Error(codes.InvalidArgument, "bad")}
	err = updateAndPrint(context.Background(), device.NewClientFromGRPC(rejected), printer, cli.OutputFormatJSON, 7, &updateFlags{model: "x"}, "")
	var updateFailed ErrDeviceUpdateFailed
	require.ErrorAs(t, err, &updateFailed)
	assert.EqualValues(t, 7, updateFailed.ID)
}

func TestApplyUpdateFlags_HashAlgoOnlyWhenSet(t *testing.T) {
	d := &platformv1.Device{HashAlgoId: 11}
	applyUpdateFlags(d, &updateFlags{hashAlgo: 0}, "")
	assert.EqualValues(t, 11, d.GetHashAlgoId(), "an unset --hash-algo keeps the stored value")

	applyUpdateFlags(d, &updateFlags{hashAlgo: 12, hashAlgoSet: true}, "PEM")
	assert.EqualValues(t, 12, d.GetHashAlgoId())
	assert.Equal(t, "PEM", d.GetEkCert())
}
