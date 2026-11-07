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

package compute

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// fakeComputeServer is an in-process ComputeService. It records the last
// request of each VM call and fails every call when fail is set.
type fakeComputeServer struct {
	platformv1.UnimplementedComputeServiceServer

	fail bool

	createReq  *platformv1.CreateVMRequest
	getReq     *platformv1.GetVMRequest
	listReq    *platformv1.ListVMsRequest
	deleteReq  *platformv1.DeleteVMRequest
	startReq   *platformv1.StartVMRequest
	stopReq    *platformv1.StopVMRequest
	migrateReq *platformv1.MigrateVMRequest

	deleteStatus *platformv1.Status
}

var errFakeCompute = status.Error(codes.Internal, "fake compute failure")

func (s *fakeComputeServer) CreateVM(_ context.Context, in *platformv1.CreateVMRequest) (*platformv1.CreateVMResponse, error) {
	s.createReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.CreateVMResponse{Vm: &platformv1.VM{Id: "vm-new", Config: in.GetConfig()}}, nil
}

func (s *fakeComputeServer) GetVM(_ context.Context, in *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	s.getReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.GetVMResponse{Vm: &platformv1.VM{Id: in.GetId(), Config: &platformv1.VMConfig{Name: "web"}}}, nil
}

func (s *fakeComputeServer) ListVMs(_ context.Context, in *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	s.listReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.ListVMsResponse{Vms: []*platformv1.VM{{Id: "vm-1", Config: &platformv1.VMConfig{Name: "web"}}}}, nil
}

func (s *fakeComputeServer) DeleteVM(_ context.Context, in *platformv1.DeleteVMRequest) (*platformv1.DeleteVMResponse, error) {
	s.deleteReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.DeleteVMResponse{Status: s.deleteStatus}, nil
}

func (s *fakeComputeServer) StartVM(_ context.Context, in *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	s.startReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.StartVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *fakeComputeServer) StopVM(_ context.Context, in *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	s.stopReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.StopVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *fakeComputeServer) MigrateVM(_ context.Context, in *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	s.migrateReq = in
	if s.fail {
		return nil, errFakeCompute
	}
	return &platformv1.MigrateVMResponse{}, nil
}

// fakeEmbeddedHost hosts the fake ComputeService for an embedded context.
type fakeEmbeddedHost struct {
	reg     *embedded.ServiceRegistry
	stopped bool
}

func (h *fakeEmbeddedHost) Services() *embedded.ServiceRegistry { return h.reg }

func (h *fakeEmbeddedHost) Stop(context.Context) error {
	h.stopped = true
	return nil
}

// embeddedFlags returns flags whose context is embedded and served by srv.
func embeddedFlags(srv *fakeComputeServer, format cli.OutputFormat) (*cli.CommonFlags, *fakeEmbeddedHost) {
	host := &fakeEmbeddedHost{reg: &embedded.ServiceRegistry{Compute: srv}}
	flags := &cli.CommonFlags{
		OutputFormat: format,
		NoColor:      true,
		GetContext: func() (*cli.Context, error) {
			return &cli.Context{Name: "embedded-test", Type: cli.ContextTypeEmbedded}, nil
		},
		StartEmbedded: func(context.Context, *cli.Context) (cli.EmbeddedHost, error) {
			return host, nil
		},
	}
	return flags, host
}

var allFormats = []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON, cli.OutputFormatYAML}

func assertOperationFailed(t *testing.T, err error, operation string) {
	t.Helper()
	var opErr ErrVMOperationFailed
	if !errors.As(err, &opErr) {
		t.Fatalf("expected ErrVMOperationFailed, got %T: %v", err, err)
	}
	if opErr.Operation != operation {
		t.Errorf("operation = %q, want %q", opErr.Operation, operation)
	}
}

func assertInvalidOutputFormat(t *testing.T, err error) {
	t.Helper()
	var fmtErr cli.ErrInvalidOutputFormat
	if !errors.As(err, &fmtErr) {
		t.Fatalf("expected ErrInvalidOutputFormat, got %T: %v", err, err)
	}
}

func TestRunCreate_Embedded_SendsParamsInEveryFormat(t *testing.T) {
	for _, format := range allFormats {
		t.Run(string(format), func(t *testing.T) {
			srv := &fakeComputeServer{}
			flags, host := embeddedFlags(srv, format)
			opts := &createOptions{
				name: "web", firmware: "UEFI", bootDevice: "disk",
				cpus: 2, memory: 2048, tpm: true, label: []string{"env=prod"},
			}
			if err := runCreate(flags, opts); err != nil {
				t.Fatalf("runCreate: %v", err)
			}
			cfg := srv.createReq.GetConfig()
			if cfg.GetName() != "web" {
				t.Fatalf("server did not receive the VM name, got %+v", srv.createReq)
			}
			if cfg.GetLabels()["env"] != "prod" {
				t.Errorf("labels = %v, want env=prod", cfg.GetLabels())
			}
			if !cfg.GetTpm().GetEnabled() || cfg.GetCpu().GetCores() != 2 || cfg.GetMemory().GetSizeMb() != 2048 {
				t.Errorf("config = %+v, want tpm, 2 cores and 2048 MB", cfg)
			}
			if cfg.GetFirmware() != platformv1.FirmwareType_FIRMWARE_TYPE_UEFI {
				t.Errorf("firmware = %v, want UEFI", cfg.GetFirmware())
			}
			if !host.stopped {
				t.Error("the embedded host was not stopped when the command closed")
			}
		})
	}
}

func TestRunCreate_Embedded_Errors(t *testing.T) {
	cases := []struct {
		name  string
		opts  createOptions
		fail  bool
		field string
	}{
		{name: "bad label", opts: createOptions{name: "web", firmware: "bios", bootDevice: "disk", label: []string{"novalue"}}, field: "label"},
		{name: "bad boot device", opts: createOptions{name: "web", firmware: "bios", bootDevice: "floppy"}, field: "boot-device"},
		{name: "bad firmware", opts: createOptions{name: "web", firmware: "coreboot", bootDevice: "disk"}, field: "firmware"},
		{name: "server failure", opts: createOptions{name: "web", firmware: "bios", bootDevice: "disk"}, fail: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeComputeServer{fail: tc.fail}
			flags, _ := embeddedFlags(srv, cli.OutputFormatJSON)
			opts := tc.opts
			err := runCreate(flags, &opts)
			if tc.fail {
				assertOperationFailed(t, err, "create")
				return
			}
			var cfgErr ErrInvalidVMConfig
			if !errors.As(err, &cfgErr) || cfgErr.Field != tc.field {
				t.Fatalf("expected ErrInvalidVMConfig on %q, got %T: %v", tc.field, err, err)
			}
			if srv.createReq != nil {
				t.Error("an invalid config must not reach the server")
			}
		})
	}
}

func TestRunCreate_Embedded_InvalidOutputFormat(t *testing.T) {
	flags, _ := embeddedFlags(&fakeComputeServer{}, cli.OutputFormat("xml"))
	err := runCreate(flags, &createOptions{name: "web", firmware: "bios", bootDevice: "disk"})
	assertInvalidOutputFormat(t, err)
}

func TestRunGet_Embedded(t *testing.T) {
	for _, format := range allFormats {
		t.Run(string(format), func(t *testing.T) {
			srv := &fakeComputeServer{}
			flags, _ := embeddedFlags(srv, format)
			if err := runGet(flags, "vm-7"); err != nil {
				t.Fatalf("runGet: %v", err)
			}
			if srv.getReq.GetId() != "vm-7" {
				t.Errorf("server got id %q, want vm-7", srv.getReq.GetId())
			}
		})
	}
}

func TestRunGet_Embedded_Errors(t *testing.T) {
	flags, _ := embeddedFlags(&fakeComputeServer{fail: true}, cli.OutputFormatJSON)
	var nf ErrVMNotFound
	if err := runGet(flags, "vm-7"); !errors.As(err, &nf) || nf.ID != "vm-7" {
		t.Fatalf("expected ErrVMNotFound for vm-7, got %T: %v", err, err)
	}

	flags, _ = embeddedFlags(&fakeComputeServer{}, cli.OutputFormat("xml"))
	assertInvalidOutputFormat(t, runGet(flags, "vm-7"))
}

func TestRunList_Embedded_StateFilter(t *testing.T) {
	cases := []struct {
		name       string
		opts       listOptions
		wantStates []platformv1.VMState
		wantLabels map[string]string
	}{
		{name: "default lists running only", opts: listOptions{pageSize: 10},
			wantStates: []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING}},
		{name: "all lists every state", opts: listOptions{all: true, pageSize: 10}},
		{name: "filters override the default", opts: listOptions{pageSize: 10, filter: []string{"state=stopped", "label=env=prod"}},
			wantStates: []platformv1.VMState{platformv1.VMState_VM_STATE_STOPPED}, wantLabels: map[string]string{"env": "prod"}},
	}
	for _, tc := range cases {
		for _, format := range allFormats {
			t.Run(tc.name+"/"+string(format), func(t *testing.T) {
				srv := &fakeComputeServer{}
				flags, _ := embeddedFlags(srv, format)
				opts := tc.opts
				if err := runList(flags, &opts); err != nil {
					t.Fatalf("runList: %v", err)
				}
				gotStates := srv.listReq.GetStates()
				if len(gotStates) != len(tc.wantStates) {
					t.Fatalf("states = %v, want %v", gotStates, tc.wantStates)
				}
				for i := range gotStates {
					if gotStates[i] != tc.wantStates[i] {
						t.Errorf("states[%d] = %v, want %v", i, gotStates[i], tc.wantStates[i])
					}
				}
				gotLabels := srv.listReq.GetSelector().GetMatchLabels()
				if len(gotLabels) != len(tc.wantLabels) {
					t.Fatalf("labels = %v, want %v", gotLabels, tc.wantLabels)
				}
				for k, v := range tc.wantLabels {
					if gotLabels[k] != v {
						t.Errorf("label %q = %q, want %q", k, gotLabels[k], v)
					}
				}
				if srv.listReq.GetPagination().GetPageSize() != 10 {
					t.Errorf("page size = %d, want 10", srv.listReq.GetPagination().GetPageSize())
				}
			})
		}
	}
}

func TestRunList_Embedded_Errors(t *testing.T) {
	srv := &fakeComputeServer{}
	flags, _ := embeddedFlags(srv, cli.OutputFormatJSON)
	var filterErr ErrInvalidFilter
	if err := runList(flags, &listOptions{filter: []string{"bogus"}}); !errors.As(err, &filterErr) {
		t.Fatalf("expected ErrInvalidFilter, got %T: %v", err, err)
	}
	if srv.listReq != nil {
		t.Error("an invalid filter must not reach the server")
	}

	flags, _ = embeddedFlags(&fakeComputeServer{fail: true}, cli.OutputFormatJSON)
	assertOperationFailed(t, runList(flags, &listOptions{}), "list")

	flags, _ = embeddedFlags(&fakeComputeServer{}, cli.OutputFormat("xml"))
	assertInvalidOutputFormat(t, runList(flags, &listOptions{}))
}

func TestRunDelete_Embedded(t *testing.T) {
	statuses := map[string]*platformv1.Status{
		"success": {Success: true},
		"refused": {Success: false, Message: "in use"},
		"none":    nil,
	}
	for name, st := range statuses {
		for _, format := range allFormats {
			t.Run(name+"/"+string(format), func(t *testing.T) {
				srv := &fakeComputeServer{deleteStatus: st}
				flags, _ := embeddedFlags(srv, format)
				if err := runDelete(flags, "vm-3", &deleteOptions{deleteDisks: true}); err != nil {
					t.Fatalf("runDelete: %v", err)
				}
				if srv.deleteReq.GetId() != "vm-3" || !srv.deleteReq.GetDeleteDisks() {
					t.Errorf("server got %+v, want id vm-3 with disks deleted", srv.deleteReq)
				}
			})
		}
	}
}

func TestRunDelete_Embedded_Errors(t *testing.T) {
	flags, _ := embeddedFlags(&fakeComputeServer{fail: true}, cli.OutputFormatJSON)
	assertOperationFailed(t, runDelete(flags, "vm-3", &deleteOptions{}), "delete")

	flags, _ = embeddedFlags(&fakeComputeServer{deleteStatus: &platformv1.Status{Success: true}}, cli.OutputFormat("xml"))
	assertInvalidOutputFormat(t, runDelete(flags, "vm-3", &deleteOptions{}))
}

func TestRunStartStop_Embedded(t *testing.T) {
	srv := &fakeComputeServer{}
	flags, _ := embeddedFlags(srv, cli.OutputFormatTable)
	if err := runStart(flags, "vm-4"); err != nil {
		t.Fatalf("runStart: %v", err)
	}
	if srv.startReq.GetId() != "vm-4" {
		t.Errorf("start got id %q, want vm-4", srv.startReq.GetId())
	}
	if err := runStop(flags, "vm-4", &stopOptions{force: true, timeout: 30}); err != nil {
		t.Fatalf("runStop: %v", err)
	}
	if srv.stopReq.GetId() != "vm-4" || !srv.stopReq.GetForce() {
		t.Errorf("stop got %+v, want a forced stop of vm-4", srv.stopReq)
	}

	failing := &fakeComputeServer{fail: true}
	flags, _ = embeddedFlags(failing, cli.OutputFormatTable)
	assertOperationFailed(t, runStart(flags, "vm-4"), "start")
	assertOperationFailed(t, runStop(flags, "vm-4", &stopOptions{}), "stop")
}

func TestRunMigrate_Embedded(t *testing.T) {
	for _, live := range []bool{true, false} {
		for _, format := range allFormats {
			t.Run(string(format), func(t *testing.T) {
				srv := &fakeComputeServer{}
				flags, _ := embeddedFlags(srv, format)
				opts := &migrateOptions{destination: "host-b", live: live, bandwidth: 100}
				if err := runMigrate(flags, "vm-5", opts); err != nil {
					t.Fatalf("runMigrate: %v", err)
				}
				req := srv.migrateReq
				if req.GetVmId() != "vm-5" || req.GetDestinationHost() != "host-b" ||
					req.GetLiveMigration() != live || req.GetBandwidthLimitMbps() != 100 {
					t.Errorf("server got %+v", req)
				}
			})
		}
	}
}

func TestRunMigrate_Errors(t *testing.T) {
	var cfgErr ErrInvalidVMConfig
	if err := runMigrate(&cli.CommonFlags{}, "", &migrateOptions{destination: "b"}); !errors.As(err, &cfgErr) || cfgErr.Field != "id" {
		t.Fatalf("expected ErrInvalidVMConfig on id, got %T: %v", err, err)
	}
	if err := runMigrate(&cli.CommonFlags{}, "vm-5", &migrateOptions{}); !errors.As(err, &cfgErr) || cfgErr.Field != "destination" {
		t.Fatalf("expected ErrInvalidVMConfig on destination, got %T: %v", err, err)
	}
	if err := runMigrate(&cli.CommonFlags{}, "vm-5", &migrateOptions{destination: "b"}); !errors.As(err, new(cli.ErrNoContextSet)) {
		t.Fatalf("expected ErrNoContextSet, got %T: %v", err, err)
	}

	flags, _ := embeddedFlags(&fakeComputeServer{fail: true}, cli.OutputFormatJSON)
	assertOperationFailed(t, runMigrate(flags, "vm-5", &migrateOptions{destination: "b"}), "migrate")

	flags, _ = embeddedFlags(&fakeComputeServer{}, cli.OutputFormat("xml"))
	assertInvalidOutputFormat(t, runMigrate(flags, "vm-5", &migrateOptions{destination: "b"}))
}
