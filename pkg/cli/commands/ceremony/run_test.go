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

package ceremony

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil/socktest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// fixedTime is the timestamp every in-process response carries, so the
// rendered JSON can be compared exactly.
var fixedTime = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// inProcCeremonyServer is a real CeremonyService gRPC server, served on a
// unix socket so the commands dial it through the SDK exactly as they dial
// platformd. It records the last request and fails every call once fail
// is set.
type inProcCeremonyServer struct {
	platformv1.UnimplementedCeremonyServiceServer

	mu   sync.Mutex
	fail error
	last proto.Message
}

func (s *inProcCeremonyServer) record(req proto.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = req
	return s.fail
}

func (s *inProcCeremonyServer) lastRequest() proto.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *inProcCeremonyServer) setFail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

func (s *inProcCeremonyServer) Status(_ context.Context, req *platformv1.CeremonyStatusRequest) (*platformv1.CeremonyStatusResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CeremonyStatusResponse{
		CeremonyId:       "cer-1",
		State:            platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS,
		Threshold:        "2-of-3",
		OfficersEnrolled: 1,
		OfficersRequired: 3,
		InitializedAt:    timestamppb.New(fixedTime),
	}, nil
}

func (s *inProcCeremonyServer) ClaimCertBegin(_ context.Context, req *platformv1.CeremonyClaimCertBeginRequest) (*platformv1.CeremonyClaimCertBeginResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CeremonyClaimCertBeginResponse{
		Nonce:       "bm9uY2U=",
		ChallengeId: "chal-1",
		ExpiresAt:   timestamppb.New(fixedTime),
	}, nil
}

func (s *inProcCeremonyServer) ClaimCertComplete(_ context.Context, req *platformv1.CeremonyClaimCertCompleteRequest) (*platformv1.CeremonyClaimCertCompleteResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CeremonyClaimCertCompleteResponse{CertificatePem: "CERT", ChainPem: "CHAIN"}, nil
}

func (s *inProcCeremonyServer) ClaimShareBegin(_ context.Context, req *platformv1.CeremonyClaimShareBeginRequest) (*platformv1.CeremonyClaimShareBeginResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CeremonyClaimShareBeginResponse{Nonce: "c2hhcmU=", ExpiresAt: timestamppb.New(fixedTime)}, nil
}

func (s *inProcCeremonyServer) ClaimShareComplete(_ context.Context, req *platformv1.CeremonyClaimShareCompleteRequest) (*platformv1.CeremonyClaimShareCompleteResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CeremonyClaimShareCompleteResponse{Share: "U0hBUkU=", Index: 2}, nil
}

func (s *inProcCeremonyServer) SignCSR(_ context.Context, req *platformv1.CeremonySignCSRRequest) (*platformv1.CeremonySignCSRResponse, error) {
	if err := s.record(req); err != nil {
		return nil, err
	}
	return &platformv1.CeremonySignCSRResponse{CertificatePem: "SIGNED", ChainPem: "CA"}, nil
}

// startCeremonyServer serves an inProcCeremonyServer on a fresh unix socket
// and returns it with JSON-output flags whose local context points at it.
func startCeremonyServer(t *testing.T) (*inProcCeremonyServer, *cli.CommonFlags) {
	t.Helper()
	sock := filepath.Join(socktest.Dir(t), "platformd.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &inProcCeremonyServer{}
	gs := grpc.NewServer()
	platformv1.RegisterCeremonyServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: sock}}, nil
		},
	}
	return srv, flags
}

// executeCeremony runs "ceremony <args>" through cobra and returns what the
// command wrote to stdout and the error it returned.
func executeCeremony(t *testing.T, flags *cli.CommonFlags, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand(func() *cli.CommonFlags { return flags })
	cmd.SetArgs(args)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := cmd.Execute()
	os.Stdout = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	return buf.String(), runErr
}

func writeCSR(t *testing.T) (string, []byte) {
	t.Helper()
	csr := []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n")
	path := filepath.Join(t.TempDir(), "csr.pem")
	if err := os.WriteFile(path, csr, 0o600); err != nil {
		t.Fatalf("write csr: %v", err)
	}
	return path, csr
}

// TestRunCommands_InProcess drives every dispatching subcommand over the
// SDK against a real gRPC server and checks both the request the server
// received and the JSON the operator sees.
func TestRunCommands_InProcess(t *testing.T) {
	csrPath, csr := writeCSR(t)
	stamp := fixedTime.Format(time.RFC3339)

	tests := []struct {
		name    string
		args    []string
		wantReq proto.Message
		wantOut map[string]any
	}{
		{
			name:    "status",
			args:    []string{"status"},
			wantReq: &platformv1.CeremonyStatusRequest{},
			wantOut: map[string]any{
				"ceremony_id": "cer-1", "state": "in_progress", "threshold": "2-of-3",
				"officers_enrolled": float64(1), "officers_required": float64(3), "initialized_at": stamp,
			},
		},
		{
			name: "claim-cert begin piv",
			args: []string{"claim-cert", "begin", "--username", "alice", "--authenticator-type", "piv", "--slot", "9a"},
			wantReq: &platformv1.CeremonyClaimCertBeginRequest{
				Username: "alice", AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV, Slot: "9a",
			},
			wantOut: map[string]any{"nonce": "bm9uY2U=", "challenge_id": "chal-1", "expires_at": stamp},
		},
		{
			name: "claim-cert begin fido2",
			args: []string{"claim-cert", "begin", "--username", "bob", "--authenticator-type", "fido2", "--credential-id", "cred-7"},
			wantReq: &platformv1.CeremonyClaimCertBeginRequest{
				Username: "bob", AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2, CredentialId: "cred-7",
			},
			wantOut: map[string]any{"nonce": "bm9uY2U=", "challenge_id": "chal-1", "expires_at": stamp},
		},
		{
			name:    "claim-cert complete",
			args:    []string{"claim-cert", "complete", "--username", "alice", "--nonce", "bm9uY2U=", "--signature", "c2ln"},
			wantReq: &platformv1.CeremonyClaimCertCompleteRequest{Username: "alice", Nonce: "bm9uY2U=", Signature: "c2ln"},
			wantOut: map[string]any{"certificate": "CERT", "chain": "CHAIN"},
		},
		{
			name:    "claim-share begin",
			args:    []string{"claim-share", "begin", "--username", "carol"},
			wantReq: &platformv1.CeremonyClaimShareBeginRequest{Username: "carol"},
			wantOut: map[string]any{"nonce": "c2hhcmU=", "expires_at": stamp},
		},
		{
			name:    "claim-share complete decodes the signature",
			args:    []string{"claim-share", "complete", "--username", "carol", "--nonce", "c2hhcmU=", "--signature", "c2ln"},
			wantReq: &platformv1.CeremonyClaimShareCompleteRequest{Username: "carol", Nonce: "c2hhcmU=", Signature: []byte("sig")},
			wantOut: map[string]any{"share": "U0hBUkU=", "index": float64(2)},
		},
		{
			name: "sign-csr sends the file base64 encoded",
			args: []string{"sign-csr", "--username", "dave", "--so-pin", "1234", "--csr-file", csrPath, "--role", "admin"},
			wantReq: &platformv1.CeremonySignCSRRequest{
				Username: "dave", SoPin: "1234", CsrPem: base64.StdEncoding.EncodeToString(csr),
				Role: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
			},
			wantOut: map[string]any{"certificate": "SIGNED", "chain": "CA"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, flags := startCeremonyServer(t)

			out, err := executeCeremony(t, flags, tt.args...)
			if err != nil {
				t.Fatalf("execute %v: %v", tt.args, err)
			}
			if got := srv.lastRequest(); !proto.Equal(got, tt.wantReq) {
				t.Errorf("server received %v, want %v", got, tt.wantReq)
			}
			var gotOut map[string]any
			if err := json.Unmarshal([]byte(out), &gotOut); err != nil {
				t.Fatalf("output is not JSON: %v\n%s", err, out)
			}
			if !reflect.DeepEqual(gotOut, tt.wantOut) {
				t.Errorf("output = %v, want %v", gotOut, tt.wantOut)
			}
		})
	}
}

// TestRunCommands_ServerFailure checks that a server-side refusal reaches
// the operator as the SDK's typed error, with the server's reason intact,
// and that nothing is printed.
func TestRunCommands_ServerFailure(t *testing.T) {
	csrPath, _ := writeCSR(t)

	tests := []struct {
		name    string
		args    []string
		wantErr any
	}{
		{"status", []string{"status"}, new(*ceremonysvc.ErrStatusFailed)},
		{"claim-cert begin", []string{"claim-cert", "begin", "--username", "a", "--authenticator-type", "software"}, new(*ceremonysvc.ErrClaimCertBeginFailed)},
		{"claim-cert complete", []string{"claim-cert", "complete", "--username", "a", "--nonce", "n", "--signature", "s"}, new(*ceremonysvc.ErrClaimCertCompleteFailed)},
		{"claim-share begin", []string{"claim-share", "begin", "--username", "a"}, new(*ceremonysvc.ErrClaimShareFailed)},
		{"claim-share complete", []string{"claim-share", "complete", "--username", "a", "--nonce", "n", "--signature", "c2ln"}, new(*ceremonysvc.ErrClaimShareFailed)},
		{"sign-csr", []string{"sign-csr", "--username", "a", "--so-pin", "p", "--csr-file", csrPath, "--role", "so"}, new(*ceremonysvc.ErrSignCSRFailed)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, flags := startCeremonyServer(t)
			srv.setFail(status.Error(codes.FailedPrecondition, "ceremony sealed"))

			out, err := executeCeremony(t, flags, tt.args...)
			if err == nil {
				t.Fatal("expected an error from a refusing server")
			}
			if !errors.As(err, tt.wantErr) {
				t.Errorf("error = %T (%v), want %T", err, err, reflect.ValueOf(tt.wantErr).Elem().Interface())
			}
			if !strings.Contains(err.Error(), "ceremony sealed") {
				t.Errorf("error %q lost the server's reason", err)
			}
			if out != "" {
				t.Errorf("nothing should be printed on failure, got %q", out)
			}
		})
	}
}

// TestRunCommands_NoContext checks that once the flags validate, a missing
// CLI context is reported as cli.ErrNoContextSet rather than a dial attempt.
func TestRunCommands_NoContext(t *testing.T) {
	csrPath, _ := writeCSR(t)
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	runs := map[string]func() error{
		"status": func() error { return runStatus(flags) },
		"claim-cert begin": func() error {
			return runClaimCertBegin(flags, &claimCertBeginFlags{username: "a", authenticatorType: "software"})
		},
		"claim-cert complete": func() error {
			return runClaimCertComplete(flags, &claimCertCompleteFlags{username: "a", nonce: "n", signature: "s"})
		},
		"claim-share begin": func() error {
			return runClaimShareBegin(flags, &claimShareBeginFlags{username: "a"})
		},
		"claim-share complete": func() error {
			return runClaimShareComplete(flags, &claimShareCompleteFlags{username: "a", nonce: "n", signature: "c2ln"})
		},
		"sign-csr": func() error {
			return runSignCSR(flags, &signCSRFlags{username: "a", soPIN: "p", csrFile: csrPath, role: "user"})
		},
	}

	for name, run := range runs {
		t.Run(name, func(t *testing.T) {
			var noCtx cli.ErrNoContextSet
			if err := run(); !errors.As(err, &noCtx) {
				t.Errorf("error = %T (%v), want cli.ErrNoContextSet", err, err)
			}
		})
	}
}

// TestErrors_UnwrapToTheirCause checks the wrapping errors keep their cause
// reachable and name it in the message.
func TestErrors_UnwrapToTheirCause(t *testing.T) {
	t.Run("ErrCSRFileRead", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.pem")
		err := runSignCSR(&cli.CommonFlags{}, &signCSRFlags{username: "u", soPIN: "p", csrFile: missing, role: "so"})
		var readErr ErrCSRFileRead
		if !errors.As(err, &readErr) {
			t.Fatalf("error = %T (%v), want ErrCSRFileRead", err, err)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("ErrCSRFileRead must unwrap to os.ErrNotExist, got %v", err)
		}
		if readErr.Path != missing || !strings.Contains(err.Error(), missing) {
			t.Errorf("ErrCSRFileRead must name the path %q, got %q", missing, err)
		}
	})

	t.Run("ErrSignatureDecode", func(t *testing.T) {
		err := runClaimShareComplete(&cli.CommonFlags{}, &claimShareCompleteFlags{username: "u", nonce: "n", signature: "!!!"})
		var decodeErr ErrSignatureDecode
		if !errors.As(err, &decodeErr) {
			t.Fatalf("error = %T (%v), want ErrSignatureDecode", err, err)
		}
		var corrupt base64.CorruptInputError
		if !errors.As(err, &corrupt) {
			t.Errorf("ErrSignatureDecode must unwrap to base64.CorruptInputError, got %v", err)
		}
		if !strings.HasPrefix(err.Error(), "ceremony: --signature is not valid base64: ") {
			t.Errorf("unexpected message %q", err)
		}
	})
}

// TestCanonicalRedirectError_Message checks the redirect tells the operator
// the replacement command to run.
func TestCanonicalRedirectError_Message(t *testing.T) {
	err := &CanonicalRedirectError{Old: "platformctl ceremony init", New: "platformctl init"}
	want := "subcommand 'platformctl ceremony init' has been replaced by 'platformctl init' " +
		"(per docs/08-bootstrap-auth-architecture.md §6). Run: platformctl init"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
