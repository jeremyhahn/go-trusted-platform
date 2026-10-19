// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE-AGPL-3.0 or https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package barrier

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// connectedFlags returns CommonFlags whose context reaches an in-process
// gRPC server on a temporary unix socket, so cli.NewBaseCommand succeeds
// without a daemon. The quicbaas address points at a socket nothing
// listens on; the barrier client itself comes from the factory the test
// installs with SetBarrierClientFactory.
func connectedFlags(t *testing.T) *cli.CommonFlags {
	t.Helper()
	t.Setenv(cli.EnvPlatformQuicBaaSAddr, "")
	t.Setenv(cli.EnvPlatformQuicBaaSTransport, "")

	dir := t.TempDir()
	sock := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	local := &cli.LocalContext{
		SocketPath:   sock,
		QuicBaaSAddr: filepath.Join(dir, "quicbaas.sock"),
	}
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "test", Type: cli.ContextTypeLocal, Local: local}, nil
		},
	}
}

// useFakeBarrierClient routes openBarrierClient to fake for the test.
func useFakeBarrierClient(t *testing.T, fake *fakeBarrierClient) {
	t.Helper()
	t.Cleanup(SetBarrierClientFactory(func(_ *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error) {
		return fake, nil
	}))
}

// runCase drives one barrier verb from flag parsing to the SDK call.
type runCase struct {
	name  string
	run   func(flags *cli.CommonFlags) error
	check func(t *testing.T, fake *fakeBarrierClient)
	// rpcErr arms the fake so the RPC fails, and wantErr is the typed
	// error the verb must wrap it in.
	rpcErr  func(fake *fakeBarrierClient, err error)
	wantErr any
}

func runCases() []runCase {
	return []runCase{
		{
			name: "init",
			run: func(flags *cli.CommonFlags) error {
				return runInit(flags, &initFlags{strategy: "passphrase", secret: "pw", soPin: "so", userPin: "user"})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				req := fake.initReq
				if req == nil || string(req.Secret) != "pw" || req.BarrierStrategy != "passphrase" ||
					req.SOPin != "so" || req.UserPin != "user" {
					t.Errorf("init request = %+v", req)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.initErr = err },
			wantErr: &ErrBarrierInitFailed{},
		},
		{
			name: "init-shamir",
			run: func(flags *cli.CommonFlags) error {
				return runInitShamir(flags, &initShamirFlags{secret: "pw", threshold: 2, total: 3})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				req := fake.initShamirReq
				if req == nil || string(req.Secret) != "pw" || req.Threshold != 2 || req.TotalShares != 3 {
					t.Errorf("init-shamir request = %+v", req)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.initShamirErr = err },
			wantErr: &ErrBarrierInitShamirFailed{},
		},
		{
			name: "status",
			run:  runStatus,
			check: func(t *testing.T, fake *fakeBarrierClient) {
				if fake.statusCalls != 1 {
					t.Errorf("status calls = %d, want 1", fake.statusCalls)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.statusErr = err },
			wantErr: &ErrBarrierStatusFailed{},
		},
		{
			name: "unseal",
			run: func(flags *cli.CommonFlags) error {
				return runUnseal(flags, &unsealFlags{secret: "pw"})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				if fake.unsealReq == nil || string(fake.unsealReq.Secret) != "pw" {
					t.Errorf("unseal request = %+v", fake.unsealReq)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.unsealErr = err },
			wantErr: &ErrBarrierUnsealFailed{},
		},
		{
			name: "unseal-shares",
			run: func(flags *cli.CommonFlags) error {
				return runUnsealShares(strings.NewReader(""), flags, &unsealSharesFlags{shares: []string{"s1", "s2"}})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				req := fake.unsealSharesReq
				if req == nil || strings.Join(req.Shares, ",") != "s1,s2" {
					t.Errorf("unseal-shares request = %+v", req)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.unsealSharesErr = err },
			wantErr: &ErrBarrierUnsealSharesFailed{},
		},
		{
			name: "seal",
			run: func(flags *cli.CommonFlags) error {
				return runSeal(strings.NewReader(""), io.Discard, flags, &sealFlags{assumeYes: true})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				if fake.sealCalls != 1 {
					t.Errorf("seal calls = %d, want 1", fake.sealCalls)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.sealErr = err },
			wantErr: &ErrBarrierSealFailed{},
		},
		{
			name: "rekey",
			run: func(flags *cli.CommonFlags) error {
				return runRekey(flags, &rekeyFlags{soPin: "so", threshold: 2, total: 3})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				req := fake.rekeyReq
				if req == nil || req.SOPin != "so" || req.Threshold != 2 || req.Total != 3 {
					t.Errorf("rekey request = %+v", req)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.rekeyErr = err },
			wantErr: &ErrBarrierRekeyFailed{},
		},
		{
			name: "recovery-generate",
			run: func(flags *cli.CommonFlags) error {
				return runRecoveryGenerate(flags, &recoveryGenerateFlags{threshold: 2, total: 3, soPin: "so"})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				req := fake.recoveryGenReq
				if req == nil || req.SOPin != "so" || req.Threshold != 2 || req.Total != 3 {
					t.Errorf("recovery-generate request = %+v", req)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.recoveryGenErr = err },
			wantErr: &ErrBarrierRecoveryGenerateFailed{},
		},
		{
			name: "recovery-recover",
			run: func(flags *cli.CommonFlags) error {
				return runRecoveryRecover(flags, &recoveryRecoverFlags{shares: []string{"r1", "r2"}})
			},
			check: func(t *testing.T, fake *fakeBarrierClient) {
				req := fake.recoveryRecReq
				if req == nil || strings.Join(req.Keys, ",") != "r1,r2" {
					t.Errorf("recovery-recover request = %+v", req)
				}
			},
			rpcErr:  func(fake *fakeBarrierClient, err error) { fake.recoveryRecoverErr = err },
			wantErr: &ErrBarrierRecoveryRecoverFailed{},
		},
	}
}

// TestRunVerbs_ForwardFlagsToBarrierClient proves every verb, once its
// flags validate and the connection opens, hands the flag values to the
// barrier client unchanged.
func TestRunVerbs_ForwardFlagsToBarrierClient(t *testing.T) {
	for _, tc := range runCases() {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBarrierClient{statusResp: &quicbaassdk.QRDBBarrierStatusResponse{Strategy: "passphrase"}}
			useFakeBarrierClient(t, fake)
			if err := tc.run(connectedFlags(t)); err != nil {
				t.Fatalf("run: %v", err)
			}
			tc.check(t, fake)
		})
	}
}

// TestRunVerbs_WrapRPCFailure proves every verb reports a failed RPC as
// its own typed error with the cause still reachable.
func TestRunVerbs_WrapRPCFailure(t *testing.T) {
	wire := errors.New("wire failure")
	for _, tc := range runCases() {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBarrierClient{}
			tc.rpcErr(fake, wire)
			useFakeBarrierClient(t, fake)
			err := tc.run(connectedFlags(t))
			if !errors.As(err, tc.wantErr) {
				t.Fatalf("err = %T %v, want %T", err, err, tc.wantErr)
			}
			if !errors.Is(err, wire) {
				t.Errorf("cause not reachable through %v", err)
			}
		})
	}
}

// TestRunVerbs_BarrierClientUnavailable proves every verb returns the
// factory's error, without calling the barrier, when no barrier client
// can be opened.
func TestRunVerbs_BarrierClientUnavailable(t *testing.T) {
	unavailable := errors.New("barrier unavailable")
	for _, tc := range runCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(SetBarrierClientFactory(func(_ *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error) {
				return nil, unavailable
			}))
			if err := tc.run(connectedFlags(t)); !errors.Is(err, unavailable) {
				t.Fatalf("err = %v, want %v", err, unavailable)
			}
		})
	}
}

// TestDefaultBarrierClientFactory_QuicBaaSInitFailure proves the
// production factory surfaces the SDK's quicbaas initialisation failure
// (here: a unix quicbaas address with no TLS material) instead of
// returning a nil barrier client.
func TestDefaultBarrierClientFactory_QuicBaaSInitFailure(t *testing.T) {
	base, err := cli.NewBaseCommand(connectedFlags(t))
	if err != nil {
		t.Fatalf("NewBaseCommand: %v", err)
	}
	t.Cleanup(func() {
		if cerr := base.Close(); cerr != nil {
			t.Errorf("Close: %v", cerr)
		}
	})

	bc, err := defaultBarrierClientFactory(base)
	var initErr platform.ErrQuicBaaSInitFailed
	if !errors.As(err, &initErr) {
		t.Fatalf("err = %T %v, want platform.ErrQuicBaaSInitFailed", err, err)
	}
	if initErr.Transport != "unix" {
		t.Errorf("transport = %q, want unix", initErr.Transport)
	}
	if bc != nil {
		t.Errorf("barrier client = %T, want nil on failure", bc)
	}
}

// TestDispatchUnseal_TableAndInvalidFormat covers the table rendering and
// the unknown-format refusal of the unseal verb.
func TestDispatchUnseal_TableAndInvalidFormat(t *testing.T) {
	d, out := newTestDispatcher(cli.OutputFormatTable, &fakeBarrierClient{})
	if err := dispatchUnseal(d, "pw"); err != nil {
		t.Fatalf("table: %v", err)
	}
	if !strings.Contains(out.String(), "Barrier unsealed successfully") {
		t.Errorf("table output = %q", out.String())
	}

	d, _ = newTestDispatcher(cli.OutputFormat("xml"), &fakeBarrierClient{})
	var typed cli.ErrInvalidOutputFormat
	if err := dispatchUnseal(d, "pw"); !errors.As(err, &typed) {
		t.Errorf("err = %T %v, want cli.ErrInvalidOutputFormat", err, err)
	}
}
