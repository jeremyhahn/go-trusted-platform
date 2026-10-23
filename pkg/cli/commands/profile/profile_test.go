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

package profile

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// inProcDeviceServer serves profile 7 from memory over a Unix socket in the
// test's temp directory, so `platformctl profile` runs through the real SDK
// client and gRPC transport without a daemon.
type inProcDeviceServer struct {
	platformv1.UnimplementedDeviceServiceServer
	mu      sync.Mutex
	profile *platformv1.DeviceProfile
	matched string
}

func (s *inProcDeviceServer) GetProfile(_ context.Context, r *platformv1.GetProfileRequest) (*platformv1.GetProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profile == nil || r.GetId() != s.profile.GetId() {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	return &platformv1.GetProfileResponse{Profile: s.profile}, nil
}

func (s *inProcDeviceServer) ListProfiles(context.Context, *platformv1.ListProfilesRequest) (*platformv1.ListProfilesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &platformv1.ListProfilesResponse{
		Profiles:   []*platformv1.DeviceProfile{s.profile},
		Pagination: &platformv1.PaginationResponse{TotalItems: 1},
	}, nil
}

func (s *inProcDeviceServer) DeleteProfile(_ context.Context, r *platformv1.DeleteProfileRequest) (*platformv1.DeleteProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.profile == nil || r.GetId() != s.profile.GetId() {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	s.profile = nil
	return &platformv1.DeleteProfileResponse{}, nil
}

func (s *inProcDeviceServer) FindMatchingProfile(_ context.Context, r *platformv1.FindMatchingProfileRequest) (*platformv1.FindMatchingProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.matched = r.GetMacAddress()
	if r.GetMacAddress() != "00:25:90:ff:aa:02" {
		return nil, status.Error(codes.NotFound, "no matching profile")
	}
	return &platformv1.FindMatchingProfileResponse{Profile: s.profile}, nil
}

// newTestCommand starts the in-process server and returns the profile command
// pointed at it.
func newTestCommand(t *testing.T) (*inProcDeviceServer, func(args ...string) error) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &inProcDeviceServer{profile: &platformv1.DeviceProfile{Id: 7, Name: "rack-a"}}
	gs := grpc.NewServer()
	platformv1.RegisterDeviceServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
			NoColor:      true,
			GetContext: func() (*cli.Context, error) {
				return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
			},
		}
	}
	run := func(args ...string) error {
		cmd := NewCommand(getFlags)
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	return srv, run
}

func TestProfileCommand_ReachesTheControlPlane(t *testing.T) {
	srv, run := newTestCommand(t)

	require.NoError(t, run("get", "7"))
	require.NoError(t, run("list", "--page", "1", "--page-size", "10"))
	require.NoError(t, run("match", "--mac", "00:25:90:ff:aa:02"))
	srv.mu.Lock()
	assert.Equal(t, "00:25:90:ff:aa:02", srv.matched, "the MAC reaches the control plane")
	srv.mu.Unlock()

	require.NoError(t, run("delete", "7"))
	srv.mu.Lock()
	assert.Nil(t, srv.profile, "delete removes the profile on the control plane")
	srv.mu.Unlock()
}

// A missing profile exits non-zero with the SDK's not-found error and a
// message naming what is missing.
func TestProfileCommand_NotFound(t *testing.T) {
	_, run := newTestCommand(t)

	err := run("get", "99")
	assert.Equal(t, device.ErrProfileNotFound{ID: 99}, err)
	assert.ErrorIs(t, err, common.ErrNotFound)

	assert.Equal(t, device.ErrProfileNotFound{ID: 99}, run("delete", "99"))

	err = run("match", "--serial", "SN999")
	assert.Equal(t, device.ErrNoMatchingProfile{Serial: "SN999"}, err)
	assert.ErrorIs(t, err, common.ErrNotFound)
}

func TestProfileCommand_RefusesBadInput(t *testing.T) {
	_, run := newTestCommand(t)

	assert.Equal(t, device.ErrInvalidProfileID{ID: "abc"}, run("get", "abc"))
	assert.Equal(t, device.ErrInvalidProfileID{ID: "1.5"}, run("delete", "1.5"))
	assert.Equal(t, device.ErrProfileMatchCriteriaRequired{}, run("match"))
	var pagination device.ErrInvalidPagination
	assert.ErrorAs(t, run("list", "--page", "0"), &pagination)
	assert.Error(t, run("get"), "get takes exactly one id")
}

// The group mounts the canonical `device profile` verbs and nothing else.
func TestNewCommand_Verbs(t *testing.T) {
	cmd := NewCommand(nil)
	names := []string{}
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	assert.ElementsMatch(t, []string{"get", "list", "delete", "match", "find-config"}, names)
}
