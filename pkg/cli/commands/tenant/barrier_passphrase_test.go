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

package tenant

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// initRecordingServer records every InitTenantBarrier request so a test can
// assert which passphrase reached the daemon, or that none did.
type initRecordingServer struct {
	*inProcTenantServer
	initMu sync.Mutex
	inits  []*platformv1.InitTenantBarrierRequest
}

func (s *initRecordingServer) InitTenantBarrier(ctx context.Context, r *platformv1.InitTenantBarrierRequest) (*platformv1.InitTenantBarrierResponse, error) {
	s.initMu.Lock()
	s.inits = append(s.inits, r)
	s.initMu.Unlock()
	return s.inProcTenantServer.InitTenantBarrier(ctx, r)
}

func (s *initRecordingServer) initRequests() []*platformv1.InitTenantBarrierRequest {
	s.initMu.Lock()
	defer s.initMu.Unlock()
	return append([]*platformv1.InitTenantBarrierRequest(nil), s.inits...)
}

func startInitRecordingServer(t *testing.T) (*initRecordingServer, func() *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(shortSocketDir(t), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)
	srv := &initRecordingServer{inProcTenantServer: &inProcTenantServer{tenants: map[string]*platformv1.Tenant{}}}
	gs := grpc.NewServer()
	platformv1.RegisterTenantServiceServer(gs, srv)
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
	require.NoError(t, runTenantCreate(getFlags(), &createTenantOptions{Name: "acme"}))
	return srv, getFlags
}

func execInit(t *testing.T, getFlags func() *cli.CommonFlags, stdin io.Reader, args ...string) (string, error) {
	t.Helper()
	cmd := newBarrierInitCommand(getFlags)
	cmd.SetArgs(args)
	if stdin != nil {
		cmd.SetIn(stdin)
	}
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	cmd.SetOut(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.Execute()
	return errBuf.String(), err
}

func stubPrompt(t *testing.T, answer string, err error) {
	t.Helper()
	orig := readBarrierPassphrase
	readBarrierPassphrase = func(int) ([]byte, error) { return []byte(answer), err }
	t.Cleanup(func() { readBarrierPassphrase = orig })
}

func TestBarrierInitPassphrase_NoArgvFlag(t *testing.T) {
	srv, getFlags := startInitRecordingServer(t)
	assert.Nil(t, newBarrierInitCommand(getFlags).Flags().Lookup("passphrase"))

	_, err := execInit(t, getFlags, nil, "acme", "--passphrase", "argv-pass")
	require.Error(t, err)
	assert.Empty(t, srv.initRequests())
}

func TestBarrierInitPassphrase_FromFile(t *testing.T) {
	srv, getFlags := startInitRecordingServer(t)
	path := filepath.Join(t.TempDir(), "pp")
	require.NoError(t, os.WriteFile(path, []byte("file-pass\n"), 0o600))

	stderr, err := execInit(t, getFlags, nil, "acme", "--passphrase-file", path)
	require.NoError(t, err)
	reqs := srv.initRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "file-pass", reqs[0].GetPassphrase())
	assert.NotContains(t, stderr, "file-pass")
}

func TestBarrierInitPassphrase_FromStdin(t *testing.T) {
	srv, getFlags := startInitRecordingServer(t)

	_, err := execInit(t, getFlags, strings.NewReader("stdin-pass\r\n"), "acme", "--passphrase-file", "-")
	require.NoError(t, err)
	reqs := srv.initRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "stdin-pass", reqs[0].GetPassphrase())
}

func TestBarrierInitPassphrase_Prompt(t *testing.T) {
	srv, getFlags := startInitRecordingServer(t)
	stubPrompt(t, "typed-pass", nil)

	stderr, err := execInit(t, getFlags, nil, "acme")
	require.NoError(t, err)
	assert.Contains(t, stderr, "Barrier passphrase: ")
	assert.NotContains(t, stderr, "typed-pass")
	reqs := srv.initRequests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "typed-pass", reqs[0].GetPassphrase())
}

func TestBarrierInitPassphrase_EmptyOrUnreadableRefused(t *testing.T) {
	writeFile := func(t *testing.T, content string) string {
		path := filepath.Join(t.TempDir(), "pp")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		return path
	}
	cases := []struct {
		name  string
		setup func(t *testing.T) (stdin io.Reader, args []string)
	}{
		{"empty file", func(t *testing.T) (io.Reader, []string) {
			return nil, []string{"acme", "--passphrase-file", writeFile(t, "")}
		}},
		{"newline only file", func(t *testing.T) (io.Reader, []string) {
			return nil, []string{"acme", "--passphrase-file", writeFile(t, "\n")}
		}},
		{"empty stdin", func(t *testing.T) (io.Reader, []string) {
			return strings.NewReader(""), []string{"acme", "--passphrase-file", "-"}
		}},
		{"empty prompt answer", func(t *testing.T) (io.Reader, []string) {
			stubPrompt(t, "", nil)
			return nil, []string{"acme"}
		}},
		{"prompt read error", func(t *testing.T) (io.Reader, []string) {
			stubPrompt(t, "", errors.New("not a terminal"))
			return nil, []string{"acme"}
		}},
		{"missing file", func(t *testing.T) (io.Reader, []string) {
			return nil, []string{"acme", "--passphrase-file", filepath.Join(t.TempDir(), "missing")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, getFlags := startInitRecordingServer(t)
			stdin, args := tc.setup(t)
			_, err := execInit(t, getFlags, stdin, args...)
			var want ErrInvalidArguments
			require.ErrorAs(t, err, &want)
			assert.Empty(t, srv.initRequests(), "a refused passphrase must not reach the init RPC")
		})
	}
}
