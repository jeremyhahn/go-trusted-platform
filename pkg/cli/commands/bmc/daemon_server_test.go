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

package bmc

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// inProcBMCServer serves the BMC user and certificate RPCs from memory over a
// Unix socket in the test's temp directory, so the daemon-mode subcommands run
// through the real SDK client and gRPC transport without a daemon. Every
// request is recorded; err, when set, is returned by every RPC, and mutateErr
// by the delete, password and privilege RPCs only, so a username lookup
// succeeds before the mutation fails.
type inProcBMCServer struct {
	platformv1.UnimplementedBMCServiceServer

	mu         sync.Mutex
	err        error
	mutateErr  error
	users      []*platformv1.BMCUser
	createSlot uint32
	cert       *platformv1.BMCGetWebCertificateResponse
	replaceMsg string

	listReq     *platformv1.BMCListUsersRequest
	createReq   *platformv1.BMCCreateUserRequest
	deleteReq   *platformv1.BMCDeleteUserRequest
	passwordReq *platformv1.BMCSetUserPasswordRequest
	privReq     *platformv1.BMCSetUserPrivilegeRequest
	getCertReq  *platformv1.BMCGetWebCertificateRequest
	replaceReq  *platformv1.BMCReplaceWebCertificateRequest

	enrollResp  *platformv1.BMCEnrollResponse
	restoreResp *platformv1.BMCRestoreResponse
	enrollReq   *platformv1.BMCEnrollRequest
	restoreReq  *platformv1.BMCRestoreRequest
}

func (s *inProcBMCServer) ListUsers(_ context.Context, r *platformv1.BMCListUsersRequest) (*platformv1.BMCListUsersResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listReq = r
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.BMCListUsersResponse{Users: s.users}, nil
}

func (s *inProcBMCServer) CreateUser(_ context.Context, r *platformv1.BMCCreateUserRequest) (*platformv1.BMCCreateUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createReq = r
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.BMCCreateUserResponse{Slot: s.createSlot}, nil
}

func (s *inProcBMCServer) DeleteUser(_ context.Context, r *platformv1.BMCDeleteUserRequest) (*platformv1.BMCDeleteUserResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteReq = r
	if s.err != nil {
		return nil, s.err
	}
	if s.mutateErr != nil {
		return nil, s.mutateErr
	}
	return &platformv1.BMCDeleteUserResponse{}, nil
}

func (s *inProcBMCServer) SetUserPassword(_ context.Context, r *platformv1.BMCSetUserPasswordRequest) (*platformv1.BMCSetUserPasswordResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwordReq = r
	if s.err != nil {
		return nil, s.err
	}
	if s.mutateErr != nil {
		return nil, s.mutateErr
	}
	return &platformv1.BMCSetUserPasswordResponse{}, nil
}

func (s *inProcBMCServer) SetUserPrivilege(_ context.Context, r *platformv1.BMCSetUserPrivilegeRequest) (*platformv1.BMCSetUserPrivilegeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.privReq = r
	if s.err != nil {
		return nil, s.err
	}
	if s.mutateErr != nil {
		return nil, s.mutateErr
	}
	return &platformv1.BMCSetUserPrivilegeResponse{}, nil
}

func (s *inProcBMCServer) GetWebCertificate(_ context.Context, r *platformv1.BMCGetWebCertificateRequest) (*platformv1.BMCGetWebCertificateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getCertReq = r
	if s.err != nil {
		return nil, s.err
	}
	return s.cert, nil
}

func (s *inProcBMCServer) ReplaceWebCertificate(_ context.Context, r *platformv1.BMCReplaceWebCertificateRequest) (*platformv1.BMCReplaceWebCertificateResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaceReq = r
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.BMCReplaceWebCertificateResponse{Message: s.replaceMsg}, nil
}

func (s *inProcBMCServer) EnrollBMC(_ context.Context, r *platformv1.BMCEnrollRequest) (*platformv1.BMCEnrollResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollReq = r
	if s.err != nil {
		return nil, s.err
	}
	return s.enrollResp, nil
}

func (s *inProcBMCServer) RestoreFactoryCert(_ context.Context, r *platformv1.BMCRestoreRequest) (*platformv1.BMCRestoreResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restoreReq = r
	if s.err != nil {
		return nil, s.err
	}
	return s.restoreResp, nil
}

// serveInProcBMC starts srv on a Unix socket and returns getFlags builders
// for table and JSON output that point the CLI at it.
func serveInProcBMC(t *testing.T, srv *inProcBMCServer) (table, json func() *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	gs := grpc.NewServer()
	platformv1.RegisterBMCServiceServer(gs, srv)
	served := make(chan error, 1)
	go func() { served <- gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		// Stop can win the race with Serve when no RPC was made.
		if err := <-served; err != nil {
			require.ErrorIs(t, err, grpc.ErrServerStopped)
		}
	})

	flagsFor := func(format cli.OutputFormat) func() *cli.CommonFlags {
		return func() *cli.CommonFlags {
			return &cli.CommonFlags{
				OutputFormat: format,
				NoColor:      true,
				GetContext: func() (*cli.Context, error) {
					return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
				},
			}
		}
	}
	return flagsFor(cli.OutputFormat("table")), flagsFor(cli.OutputFormatJSON)
}
