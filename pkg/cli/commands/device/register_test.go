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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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

// recordingDeviceService is a DeviceServiceClient stub that records which
// create RPC register reached. Any RPC it does not override panics through
// the nil embedded interface, so a stray call fails the test.
type recordingDeviceService struct {
	platformv1.DeviceServiceClient

	createDeviceReq *platformv1.CreateDeviceRequest
	createProfiles  int
	reply           *platformv1.CreateDeviceResponse
	err             error
}

func (s *recordingDeviceService) CreateDevice(_ context.Context, in *platformv1.CreateDeviceRequest, _ ...grpc.CallOption) (*platformv1.CreateDeviceResponse, error) {
	s.createDeviceReq = in
	return s.reply, s.err
}

func (s *recordingDeviceService) CreateProfile(_ context.Context, _ *platformv1.CreateProfileRequest, _ ...grpc.CallOption) (*platformv1.CreateProfileResponse, error) {
	s.createProfiles++
	return &platformv1.CreateProfileResponse{}, nil
}

func TestNewRegisterCommand_Flags(t *testing.T) {
	cmd := newRegisterCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })

	for _, name := range []string{"serial", "model", "ek-cert", "attest-pub", "attest-cert", "signing-pub", "hash-algo"} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "flag --%s", name)
	}
	for _, name := range []string{"hostname", "mac", "role", "template", "override-file", "server", "ca-cert"} {
		assert.Nil(t, cmd.Flags().Lookup(name), "profile-era flag --%s must be gone", name)
	}
}

func TestNewRegisterCommand_RejectsArgs(t *testing.T) {
	cmd := newRegisterCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{"--serial", "SN-1", "extra"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	require.Error(t, cmd.Execute())
}

func TestBuildRegisterDevice(t *testing.T) {
	ekPEM := newCLITestEKCertPEM(t)
	ekPath := filepath.Join(t.TempDir(), "ek.pem")
	require.NoError(t, os.WriteFile(ekPath, []byte(ekPEM), 0o600))

	got, err := buildRegisterDevice(&registerFlags{
		serial:     "SN-0001",
		model:      "r640",
		ekCert:     ekPath,
		attestPub:  "attest-pub",
		attestCert: "attest-cert",
		signingPub: "signing-pub",
		hashAlgo:   11,
	})
	require.NoError(t, err)

	assert.Equal(t, "SN-0001", got.Serial)
	assert.Equal(t, "r640", got.Model)
	assert.Equal(t, ekPEM, got.EkCert)
	assert.Equal(t, "attest-pub", got.AttestPub)
	assert.Equal(t, "attest-cert", got.AttestCert)
	assert.Equal(t, "signing-pub", got.SigningPub)
	assert.Equal(t, uint32(11), got.HashAlgoId)
}

func TestBuildRegisterDevice_SerialRequired(t *testing.T) {
	_, err := buildRegisterDevice(&registerFlags{model: "r640"})
	require.ErrorAs(t, err, &ErrRegisterSerialRequired{})
}

func TestBuildRegisterDevice_InvalidEKCert(t *testing.T) {
	_, err := buildRegisterDevice(&registerFlags{
		serial: "SN-0001",
		ekCert: "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n",
	})
	require.ErrorAs(t, err, &ErrProfileEKCertInvalid{})
}

func TestRunRegister_ValidatesBeforeConnecting(t *testing.T) {
	// No GetContext: reaching the connect step would return ErrNoContextSet.
	err := runRegister(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, &registerFlags{})
	require.ErrorAs(t, err, &ErrRegisterSerialRequired{})
}

// TestRegisterAndPrint_CreatesDevice is the #534 regression: register must
// reach CreateDevice, never CreateProfile, and print the stored device.
func TestRegisterAndPrint_CreatesDevice(t *testing.T) {
	stub := &recordingDeviceService{
		reply: &platformv1.CreateDeviceResponse{Device: &platformv1.Device{
			Id:         4242,
			Serial:     "SN-0001",
			Model:      "r640",
			HashAlgoId: 11,
		}},
	}
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out)

	err := registerAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON,
		&platformv1.Device{Serial: "SN-0001", Model: "r640", HashAlgoId: 11})
	require.NoError(t, err)

	require.NotNil(t, stub.createDeviceReq, "register must call CreateDevice")
	assert.Equal(t, "SN-0001", stub.createDeviceReq.GetDevice().GetSerial())
	assert.Zero(t, stub.createProfiles, "register must not call CreateProfile")

	var printed map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &printed), out.String())
	assert.EqualValues(t, 4242, printed["id"])
	assert.Equal(t, "SN-0001", printed["serial"])
	assert.Equal(t, "r640", printed["model"])
}

func TestRegisterAndPrint_Table(t *testing.T) {
	stub := &recordingDeviceService{
		reply: &platformv1.CreateDeviceResponse{Device: &platformv1.Device{Id: 7, Serial: "SN-7"}},
	}
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &out)

	err := registerAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatTable,
		&platformv1.Device{Serial: "SN-7"})
	require.NoError(t, err)

	assert.Contains(t, out.String(), "SN-7")
	assert.Contains(t, out.String(), "7")
}

func TestRegisterAndPrint_ServerRejects(t *testing.T) {
	rejection := status.Error(codes.AlreadyExists, "device with serial SN-0001 already exists")
	stub := &recordingDeviceService{err: rejection}
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out)

	err := registerAndPrint(context.Background(), device.NewClientFromGRPC(stub), printer, cli.OutputFormatJSON,
		&platformv1.Device{Serial: "SN-0001"})

	var createErr ErrRegisterCreateDeviceFailed
	require.ErrorAs(t, err, &createErr)
	assert.Equal(t, "SN-0001", createErr.Serial)
	assert.ErrorIs(t, err, rejection, "the server's rejection must survive the wrapping")
	assert.Empty(t, out.String(), "nothing is printed for a rejected device")
}

func TestRegisterDevice_EmptyResponse(t *testing.T) {
	stub := &recordingDeviceService{reply: &platformv1.CreateDeviceResponse{}}

	_, err := registerDevice(context.Background(), device.NewClientFromGRPC(stub), &platformv1.Device{Serial: "SN-0001"})

	var emptyErr ErrRegisterEmptyResponse
	require.ErrorAs(t, err, &emptyErr)
	assert.Equal(t, "SN-0001", emptyErr.Serial)
}

func TestErrRegisterSerialRequired(t *testing.T) {
	assert.Equal(t, "device register: --serial is required", ErrRegisterSerialRequired{}.Error())
}

func TestErrRegisterCreateDeviceFailed(t *testing.T) {
	cause := errors.New("rejected")
	err := ErrRegisterCreateDeviceFailed{Serial: "SN-1", Cause: cause}

	assert.Equal(t, `device register: failed to create device "SN-1": rejected`, err.Error())
	assert.ErrorIs(t, err, cause)
}

func TestErrRegisterEmptyResponse(t *testing.T) {
	assert.Equal(t, `device register: control plane returned no device for serial "SN-1"`,
		ErrRegisterEmptyResponse{Serial: "SN-1"}.Error())
}
