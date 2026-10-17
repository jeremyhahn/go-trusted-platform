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

package device

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// inProcProfileServer is an in-memory DeviceService profile store served over
// a Unix socket in the test's temp directory, so the CLI run functions
// exercise the real SDK client and gRPC transport without a daemon.
type inProcProfileServer struct {
	platformv1.UnimplementedDeviceServiceServer
	mu         sync.Mutex
	profiles   map[uint64]*platformv1.DeviceProfile
	lastMatch  *platformv1.FindMatchingProfileRequest
	lastConfig *platformv1.FindConfigForDeviceRequest
	lastAttest *platformv1.AttestDeviceRequest
	fail       error
}

// AttestDevice answers a negative verdict for device 42, the one registered
// device, and NotFound for any other.
func (s *inProcProfileServer) AttestDevice(_ context.Context, r *platformv1.AttestDeviceRequest) (*platformv1.AttestDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastAttest = r
	if s.fail != nil {
		return nil, s.fail
	}
	if r.GetDeviceId() != "42" {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	return &platformv1.AttestDeviceResponse{
		DeviceId:          42,
		Serial:            "SN100-XYZ",
		NonceValid:        true,
		AttestationStatus: "failed",
		Message:           "RSA signature verification failed",
		AttestedAt:        timestamppb.Now(),
		PcrBaselineSource: "tofu",
	}, nil
}

func (s *inProcProfileServer) GetProfile(_ context.Context, r *platformv1.GetProfileRequest) (*platformv1.GetProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	p, ok := s.profiles[r.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	return &platformv1.GetProfileResponse{Profile: p}, nil
}

func (s *inProcProfileServer) ListProfiles(context.Context, *platformv1.ListProfilesRequest) (*platformv1.ListProfilesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	out := &platformv1.ListProfilesResponse{}
	for _, p := range s.profiles {
		out.Profiles = append(out.Profiles, p)
	}
	out.Pagination = &platformv1.PaginationResponse{TotalItems: uint64(len(out.Profiles))}
	return out, nil
}

func (s *inProcProfileServer) DeleteProfile(_ context.Context, r *platformv1.DeleteProfileRequest) (*platformv1.DeleteProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	if _, ok := s.profiles[r.GetId()]; !ok {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	delete(s.profiles, r.GetId())
	return &platformv1.DeleteProfileResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *inProcProfileServer) FindMatchingProfile(_ context.Context, r *platformv1.FindMatchingProfileRequest) (*platformv1.FindMatchingProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastMatch = r
	if s.fail != nil {
		return nil, s.fail
	}
	for _, p := range s.profiles {
		rules := p.GetMatchRules()
		if r.GetSerial() != "" && rules.GetSerialPrefix() != "" && strings.HasPrefix(r.GetSerial(), rules.GetSerialPrefix()) {
			return &platformv1.FindMatchingProfileResponse{Profile: p}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no matching profile")
}

func (s *inProcProfileServer) FindConfigForDevice(_ context.Context, r *platformv1.FindConfigForDeviceRequest) (*platformv1.FindConfigForDeviceResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastConfig = r
	if s.fail != nil {
		return nil, s.fail
	}
	for _, p := range s.profiles {
		if r.GetEkSerial() != "" && p.GetEkSerial() == r.GetEkSerial() {
			return &platformv1.FindConfigForDeviceResponse{Profile: p}, nil
		}
		if r.GetMacAddress() != "" && p.GetMacAddress() == r.GetMacAddress() {
			return &platformv1.FindConfigForDeviceResponse{Profile: p}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no config for device")
}

// startProfileServer starts an in-process profile server holding profile 42
// and returns it with CLI flags for each output format pointing at it.
func startProfileServer(t *testing.T) (*inProcProfileServer, func(cli.OutputFormat) *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &inProcProfileServer{profiles: map[uint64]*platformv1.DeviceProfile{
		42: {Id: 42, Name: "rack-a", EkSerial: "EK-42", MatchRules: &platformv1.ProfileMatchRules{SerialPrefix: "SN100"}},
	}}
	gs := grpc.NewServer()
	platformv1.RegisterDeviceServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	flags := func(format cli.OutputFormat) *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
	return srv, flags
}

func TestProfileLookupCommands_GetListMatchDelete(t *testing.T) {
	srv, flags := startProfileServer(t)

	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
		f := flags(format)
		require.NoError(t, runProfileGet(f, 42))
		require.NoError(t, runProfileList(f, 1, 20))
		require.NoError(t, runProfileMatch(f, profileMatchOptions{Serial: "SN100-XYZ", Model: "R640"}))
	}

	srv.mu.Lock()
	assert.Equal(t, "SN100-XYZ", srv.lastMatch.GetSerial(), "the serial reaches the control plane")
	assert.Equal(t, "R640", srv.lastMatch.GetModel())
	assert.Empty(t, srv.lastMatch.GetMacAddress(), "an unset attribute is not sent")
	srv.mu.Unlock()

	require.NoError(t, runProfileDelete(flags(cli.OutputFormatJSON), 42))
	srv.mu.Lock()
	_, kept := srv.profiles[42]
	srv.mu.Unlock()
	assert.False(t, kept, "delete removes the profile on the control plane")
}

// A missing profile is the SDK's not-found error, so callers and the exit
// message name it rather than a generic failure.
func TestProfileLookupCommands_NotFound(t *testing.T) {
	_, flags := startProfileServer(t)
	f := flags(cli.OutputFormatJSON)

	err := runProfileGet(f, 4242)
	assert.Equal(t, ErrProfileNotFound{ID: 4242}, err)
	assert.ErrorIs(t, err, common.ErrNotFound)
	assert.Equal(t, "device profile: profile 4242 not found", err.Error())

	err = runProfileDelete(f, 4242)
	assert.Equal(t, ErrProfileNotFound{ID: 4242}, err)

	err = runProfileMatch(f, profileMatchOptions{Serial: "SN999"})
	assert.Equal(t, ErrNoMatchingProfile{Serial: "SN999"}, err)
	assert.ErrorIs(t, err, common.ErrNotFound)
}

func TestProfileLookupCommands_ServerFailure(t *testing.T) {
	srv, flags := startProfileServer(t)
	f := flags(cli.OutputFormatJSON)
	srv.mu.Lock()
	srv.fail = status.Error(codes.Internal, "backend down")
	srv.mu.Unlock()

	var getErr ErrProfileGetFailed
	assert.True(t, errors.As(runProfileGet(f, 42), &getErr))
	var deleteErr ErrProfileDeleteFailed
	err := runProfileDelete(f, 42)
	require.True(t, errors.As(err, &deleteErr), "err = %v", err)
	assert.Contains(t, err.Error(), "backend down", "the server's reason is shown")
	assert.NotErrorIs(t, err, common.ErrNotFound)
	var matchErr ErrProfileMatchFailed
	assert.True(t, errors.As(runProfileMatch(f, profileMatchOptions{Model: "R640"}), &matchErr))
}

func TestRunProfileMatch_CriteriaRequired(t *testing.T) {
	err := runProfileMatch(&cli.CommonFlags{}, profileMatchOptions{})
	assert.Equal(t, ErrProfileMatchCriteriaRequired{}, err, "refused before connecting")
}

func TestRunProfileFindConfig(t *testing.T) {
	srv, flags := startProfileServer(t)

	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
		require.NoError(t, runProfileFindConfig(flags(format), profileFindConfigOptions{EKSerial: "EK-42"}))
	}

	srv.mu.Lock()
	assert.Equal(t, "EK-42", srv.lastConfig.GetEkSerial(), "the EK serial reaches the control plane")
	assert.Empty(t, srv.lastConfig.GetMacAddress(), "an unset identity is not sent")
	srv.mu.Unlock()
}

func TestRunProfileFindConfig_Errors(t *testing.T) {
	srv, flags := startProfileServer(t)
	f := flags(cli.OutputFormatJSON)

	t.Run("IdentityRequired", func(t *testing.T) {
		err := runProfileFindConfig(&cli.CommonFlags{}, profileFindConfigOptions{})
		assert.Equal(t, ErrProfileConfigIdentityRequired{}, err, "refused before connecting")
	})

	t.Run("NotFound", func(t *testing.T) {
		err := runProfileFindConfig(f, profileFindConfigOptions{MACAddress: "52:54:00:00:00:99"})
		assert.Equal(t, ErrNoConfigForDevice{MACAddress: "52:54:00:00:00:99"}, err)
		assert.ErrorIs(t, err, common.ErrNotFound)
	})

	t.Run("ServerFailure", func(t *testing.T) {
		srv.mu.Lock()
		srv.fail = status.Error(codes.Internal, "backend down")
		srv.mu.Unlock()
		err := runProfileFindConfig(f, profileFindConfigOptions{EKSerial: "EK-42"})
		var findErr ErrProfileFindConfigFailed
		require.True(t, errors.As(err, &findErr), "err = %v", err)
		assert.Contains(t, err.Error(), "backend down", "the server's reason is shown")
		assert.NotErrorIs(t, err, common.ErrNotFound)
	})

	findConfig := newProfileFindConfigCommand(nil)
	for _, flag := range []string{"ek-serial", "mac"} {
		assert.NotNil(t, findConfig.Flags().Lookup(flag), "find-config missing --%s", flag)
	}
}

func TestProfileDeleteCommand_InvalidID(t *testing.T) {
	cmd := newProfileDeleteCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{"abc"})
	err := cmd.Execute()
	assert.Equal(t, ErrInvalidProfileID{ID: "abc"}, err)
}

func TestNewProfileLookupCommands(t *testing.T) {
	names := []string{}
	for _, cmd := range NewProfileLookupCommands(nil) {
		names = append(names, cmd.Name())
	}
	assert.Equal(t, []string{"get", "list", "delete", "match", "find-config"}, names)

	match := newProfileMatchCommand(nil)
	for _, flag := range []string{"mac", "serial", "model"} {
		assert.NotNil(t, match.Flags().Lookup(flag), "match missing --%s", flag)
	}
}

func TestIsNotFound(t *testing.T) {
	assert.True(t, isNotFound(status.Error(codes.NotFound, "gone")))
	assert.False(t, isNotFound(status.Error(codes.Internal, "down")))
	assert.False(t, isNotFound(errors.New("plain")))
	assert.False(t, isNotFound(nil))
}
