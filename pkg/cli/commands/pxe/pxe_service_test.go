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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computepxe "github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// serverClient drives the real daemon PXE gRPC service, backed by the real
// pkg/compute/pxe service and its state table, as a PXEServiceClient.
type serverClient struct {
	platformv1.PXEServiceClient
	srv *daemon.PXEGRPCService
}

func (c *serverClient) GetDevice(ctx context.Context, in *platformv1.GetPXEDeviceRequest, _ ...grpc.CallOption) (*platformv1.GetPXEDeviceResponse, error) {
	return c.srv.GetDevice(ctx, in)
}

func (c *serverClient) UpdateState(ctx context.Context, in *platformv1.UpdatePXEStateRequest, _ ...grpc.CallOption) (*platformv1.UpdatePXEStateResponse, error) {
	return c.srv.UpdateState(ctx, in)
}

func (c *serverClient) Authorize(ctx context.Context, in *platformv1.AuthorizePXEDeviceRequest, _ ...grpc.CallOption) (*platformv1.AuthorizePXEDeviceResponse, error) {
	return c.srv.Authorize(ctx, in)
}

// newRealService returns an initialized PXE service and a device walked
// through the provisioning states up to (and including) last.
func newRealService(t *testing.T, last computepxe.ProvisioningState) (computepxe.Service, string) {
	t.Helper()
	ctx := context.Background()
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	cfg, err := computepxe.NewServiceConfig(plan)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	cfg.BridgeName = "br-test"
	// An unstarted iPXE server: the test drives the state table, never boots.
	svc := computepxe.NewService(computepxe.WithIPXEServer(&ipxe.Server{}))
	if err := svc.Initialize(ctx, cfg); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	dev, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, s := range []computepxe.ProvisioningState{
		computepxe.StateBooting, computepxe.StateInstalling, computepxe.StateInstallComplete,
		computepxe.StateEnrolling, computepxe.StateEnrolled,
	} {
		if err := svc.UpdateDeviceState(ctx, dev.ID, s, string(s)); err != nil {
			t.Fatalf("to %s: %v", s, err)
		}
		if s == last {
			break
		}
	}
	return svc, dev.ID
}

func runReal(t *testing.T, svc computepxe.Service, args ...string) (string, error) {
	t.Helper()
	client := &serverClient{srv: daemon.NewPXEGRPCService(logging.DefaultLogger(), svc)}
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	open := func(*cli.CommonFlags) (platformv1.PXEServiceClient, func() error, error) {
		return client, func() error { return nil }, nil
	}
	cmd := newCommandWith(func() *cli.CommonFlags { return flags }, open)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// An enrolled device is the documented input of authorize: the command
// moves it through authorizing to authorized on the real service.
func TestAuthorize_EnrolledDevice_RealService(t *testing.T) {
	svc, id := newRealService(t, computepxe.StateEnrolled)

	out, err := runReal(t, svc, "authorize", id, "--target-vlan", "20")
	if err != nil {
		t.Fatalf("authorize: %v\n%s", err, out)
	}
	dev, err := svc.GetDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if dev.State != computepxe.StateAuthorized {
		t.Errorf("state = %s, want authorized", dev.State)
	}
	if dev.TargetVLAN != 20 {
		t.Errorf("target VLAN = %d, want 20", dev.TargetVLAN)
	}
	if !strings.Contains(out, "authorized") {
		t.Errorf("output does not show the new state:\n%s", out)
	}
}

// The service's trust checks hold: a device that has not enrolled is
// refused and stays where it was.
func TestAuthorize_NotEnrolledDevice_RealServiceRefuses(t *testing.T) {
	svc, id := newRealService(t, computepxe.StateEnrolling)

	_, err := runReal(t, svc, "authorize", id, "--target-vlan", "20")
	var rpcErr *ErrRPCFailed
	if !errors.As(err, &rpcErr) {
		t.Fatalf("err = %v, want *ErrRPCFailed", err)
	}
	dev, err := svc.GetDevice(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if dev.State != computepxe.StateEnrolling {
		t.Errorf("state = %s, want enrolling (unchanged)", dev.State)
	}
}

func TestList_VLANFilterRange(t *testing.T) {
	for _, v := range []string{"0", "4095", "65536", "65556"} {
		fake := &fakePXEClient{}
		_, err := run(t, fake, "list", "--vlan", v)
		var vErr *ErrInvalidVLANFilter
		if !errors.As(err, &vErr) {
			t.Errorf("--vlan %s: err = %v, want *ErrInvalidVLANFilter", v, err)
		}
		if fake.calls != 0 {
			t.Errorf("--vlan %s: %d RPCs, want none", v, fake.calls)
		}
	}
	for _, v := range []struct {
		arg  string
		want uint32
	}{{"1", 1}, {"4094", 4094}} {
		fake := &fakePXEClient{}
		if _, err := run(t, fake, "list", "--vlan", v.arg); err != nil {
			t.Fatalf("--vlan %s: %v", v.arg, err)
		}
		if got := fake.listReq.GetFilter().GetVlan(); got != v.want {
			t.Errorf("--vlan %s: filter vlan = %d, want %d", v.arg, got, v.want)
		}
	}
	fake := &fakePXEClient{}
	if _, err := run(t, fake, "list"); err != nil {
		t.Fatalf("list without --vlan: %v", err)
	}
	if got := fake.listReq.GetFilter().GetVlan(); got != 0 {
		t.Errorf("list without --vlan: filter vlan = %d, want 0 (no filter)", got)
	}
}
