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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakePXEClient records the requests a command sends and answers with
// canned replies. Methods a test does not set panic through the nil
// embedded interface, which flags an unexpected RPC.
type fakePXEClient struct {
	platformv1.PXEServiceClient

	listReq       *platformv1.ListPXEDevicesRequest
	listResp      *platformv1.ListPXEDevicesResponse
	getReq        *platformv1.GetPXEDeviceRequest
	authorizeReq  *platformv1.AuthorizePXEDeviceRequest
	quarantineReq *platformv1.QuarantinePXEDeviceRequest
	retryReq      *platformv1.RetryPXEDeviceRequest
	eventsReq     *platformv1.GetPXEEventsRequest
	eventsResp    *platformv1.GetPXEEventsResponse
	err           error
	calls         int
}

func (f *fakePXEClient) ListDevices(_ context.Context, in *platformv1.ListPXEDevicesRequest, _ ...grpc.CallOption) (*platformv1.ListPXEDevicesResponse, error) {
	f.calls++
	f.listReq = in
	return f.listResp, f.err
}

func (f *fakePXEClient) GetDevice(_ context.Context, in *platformv1.GetPXEDeviceRequest, _ ...grpc.CallOption) (*platformv1.GetPXEDeviceResponse, error) {
	f.calls++
	f.getReq = in
	return &platformv1.GetPXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{Id: in.GetDeviceId()}}, f.err
}

func (f *fakePXEClient) Authorize(_ context.Context, in *platformv1.AuthorizePXEDeviceRequest, _ ...grpc.CallOption) (*platformv1.AuthorizePXEDeviceResponse, error) {
	f.calls++
	f.authorizeReq = in
	return &platformv1.AuthorizePXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{
		Id: in.GetDeviceId(), State: platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED,
	}}, f.err
}

func (f *fakePXEClient) Quarantine(_ context.Context, in *platformv1.QuarantinePXEDeviceRequest, _ ...grpc.CallOption) (*platformv1.QuarantinePXEDeviceResponse, error) {
	f.calls++
	f.quarantineReq = in
	return &platformv1.QuarantinePXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{Id: in.GetDeviceId()}}, f.err
}

func (f *fakePXEClient) Retry(_ context.Context, in *platformv1.RetryPXEDeviceRequest, _ ...grpc.CallOption) (*platformv1.RetryPXEDeviceResponse, error) {
	f.calls++
	f.retryReq = in
	return &platformv1.RetryPXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{Id: in.GetDeviceId()}}, f.err
}

func (f *fakePXEClient) GetEvents(_ context.Context, in *platformv1.GetPXEEventsRequest, _ ...grpc.CallOption) (*platformv1.GetPXEEventsResponse, error) {
	f.calls++
	f.eventsReq = in
	return f.eventsResp, f.err
}

// run executes the pxe group with args against fake and returns its output.
func run(t *testing.T, fake *fakePXEClient, args ...string) (string, error) {
	t.Helper()
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	open := func(*cli.CommonFlags) (platformv1.PXEServiceClient, func() error, error) {
		return fake, func() error { return nil }, nil
	}
	cmd := newCommandWith(func() *cli.CommonFlags { return flags }, open)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestAuthorize_SendsDeviceID(t *testing.T) {
	fake := &fakePXEClient{}
	out, err := run(t, fake, "authorize", "dev-1", "--target-vlan", "20")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if fake.authorizeReq == nil {
		t.Fatal("Authorize was not called")
	}
	if got := fake.authorizeReq.GetDeviceId(); got != "dev-1" {
		t.Errorf("device_id = %q, want dev-1", got)
	}
	if got := fake.authorizeReq.GetTargetVlan(); got != 20 {
		t.Errorf("target_vlan = %d, want 20", got)
	}
	if !strings.Contains(out, "authorized") {
		t.Errorf("output does not show the new state:\n%s", out)
	}
}

func TestAuthorize_RequiresDeviceID(t *testing.T) {
	fake := &fakePXEClient{}
	_, err := run(t, fake, "authorize", "")
	var want *ErrDeviceIDRequired
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want *ErrDeviceIDRequired", err)
	}
	if fake.calls != 0 {
		t.Errorf("RPC called %d times, want 0", fake.calls)
	}
}

func TestQuarantine_RequiresReason(t *testing.T) {
	fake := &fakePXEClient{}
	_, err := run(t, fake, "quarantine", "dev-1")
	var want *ErrReasonRequired
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want *ErrReasonRequired", err)
	}
	if fake.calls != 0 {
		t.Errorf("RPC called %d times, want 0", fake.calls)
	}

	_, err = run(t, fake, "quarantine", "dev-1", "--reason", "bad measurement")
	if err != nil {
		t.Fatalf("quarantine with reason: %v", err)
	}
	if got := fake.quarantineReq.GetReason(); got != "bad measurement" {
		t.Errorf("reason = %q, want %q", got, "bad measurement")
	}
	if got := fake.quarantineReq.GetDeviceId(); got != "dev-1" {
		t.Errorf("device_id = %q, want dev-1", got)
	}
}

func TestList_Table(t *testing.T) {
	fake := &fakePXEClient{listResp: &platformv1.ListPXEDevicesResponse{
		Devices: []*platformv1.PXEDeviceInfo{
			{Id: "dev-1", MacAddress: "52:54:00:00:00:01", State: platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED, CurrentVlan: 10},
			{Id: "dev-2", MacAddress: "52:54:00:00:00:02", State: platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE, CurrentVlan: 30, RetryCount: 2},
		},
		TotalCount: 2,
	}}
	out, err := run(t, fake, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, want := range []string{"ID", "MAC", "STATE", "VLAN", "RETRIES",
		"dev-1", "52:54:00:00:00:01", "discovered",
		"dev-2", "install-complete"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
}

func TestList_StateFilter(t *testing.T) {
	fake := &fakePXEClient{listResp: &platformv1.ListPXEDevicesResponse{}}
	if _, err := run(t, fake, "list", "--state", "quarantined", "--limit", "5"); err != nil {
		t.Fatalf("list: %v", err)
	}
	filter := fake.listReq.GetFilter()
	if filter.GetState() != platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED {
		t.Errorf("state = %v, want QUARANTINED", filter.GetState())
	}
	if filter.GetLimit() != 5 {
		t.Errorf("limit = %d, want 5", filter.GetLimit())
	}

	_, err := run(t, &fakePXEClient{}, "list", "--state", "sleeping")
	var want *ErrInvalidState
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want *ErrInvalidState", err)
	}
}

func TestGetRetryEvents_SendDeviceID(t *testing.T) {
	fake := &fakePXEClient{eventsResp: &platformv1.GetPXEEventsResponse{
		Events: []*platformv1.ProvisioningEvent{{
			Id: "ev-1", DeviceId: "dev-1",
			EventType: platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_RETRY,
			FromState: platformv1.ProvisioningState_PROVISIONING_STATE_FAILED,
			ToState:   platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
		}},
	}}
	if _, err := run(t, fake, "get", "dev-1"); err != nil {
		t.Fatalf("get: %v", err)
	}
	if fake.getReq.GetDeviceId() != "dev-1" {
		t.Errorf("get device_id = %q", fake.getReq.GetDeviceId())
	}
	if _, err := run(t, fake, "retry", "dev-1"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if fake.retryReq.GetDeviceId() != "dev-1" {
		t.Errorf("retry device_id = %q", fake.retryReq.GetDeviceId())
	}
	out, err := run(t, fake, "events", "dev-1")
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	if fake.eventsReq.GetDeviceId() != "dev-1" {
		t.Errorf("events device_id = %q", fake.eventsReq.GetDeviceId())
	}
	for _, want := range []string{"ev-1", "retry", "failed", "discovered"} {
		if !strings.Contains(out, want) {
			t.Errorf("events table lacks %q:\n%s", want, out)
		}
	}
}

func TestRPCError_IsWrapped(t *testing.T) {
	cause := errors.New("unavailable")
	_, err := run(t, &fakePXEClient{err: cause}, "retry", "dev-1")
	var want *ErrRPCFailed
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want *ErrRPCFailed", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("err does not wrap its cause: %v", err)
	}
}
