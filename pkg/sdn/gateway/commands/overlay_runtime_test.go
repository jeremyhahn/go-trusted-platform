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

package commands

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdaemon "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// fakeOverlayIPAMClient serves one fabric pool and counts the listings.
type fakeOverlayIPAMClient struct {
	allocations []*platformv1.IPAllocation
	err         error
	listings    int
	zones       []string
}

func (f *fakeOverlayIPAMClient) ListIPAMPools(_ context.Context, zone string) ([]*platformv1.IPAMPool, error) {
	f.listings++
	f.zones = append(f.zones, zone)
	if f.err != nil {
		return nil, f.err
	}
	return []*platformv1.IPAMPool{{Id: "fabric-pool", Zone: zone}}, nil
}

func (f *fakeOverlayIPAMClient) ListAllocations(_ context.Context, poolID string) ([]*platformv1.IPAllocation, error) {
	return f.allocations, nil
}

func fabricAllocation(ip, deviceID string) *platformv1.IPAllocation {
	return &platformv1.IPAllocation{Ip: ip, PoolId: "fabric-pool", DeviceId: deviceID}
}

// steppingClock returns a clock that advances one second per reading, so
// every miss happens after the listing before it started.
func steppingClock() func() time.Time {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		at = at.Add(time.Second)
		return at
	}
}

func TestOverlayRuntimeIPAM_IndexServesHitsWithoutListing(t *testing.T) {
	client := &fakeOverlayIPAMClient{allocations: []*platformv1.IPAllocation{
		fabricAllocation("10.0.0.1", "7"),
		fabricAllocation("10.0.0.2", "8"),
	}}
	r := &overlayRuntimeIPAM{client: client, now: steppingClock()}
	ctx := context.Background()

	for _, addr := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.1"} {
		allocation, err := r.GetAllocation(ctx, netip.MustParseAddr(addr))
		if err != nil {
			t.Fatalf("GetAllocation(%s): %v", addr, err)
		}
		if allocation.IP.String() != addr || allocation.Zone != "fabric" {
			t.Fatalf("GetAllocation(%s) = %+v", addr, allocation)
		}
	}
	if client.listings != 1 {
		t.Fatalf("listings = %d, want 1: indexed addresses must not list the allocations", client.listings)
	}
	if len(client.zones) != 1 || client.zones[0] != "fabric" {
		t.Fatalf("listed zones = %v, want [fabric]", client.zones)
	}
}

func TestOverlayRuntimeIPAM_MissListsAgain(t *testing.T) {
	client := &fakeOverlayIPAMClient{allocations: []*platformv1.IPAllocation{fabricAllocation("10.0.0.1", "7")}}
	r := &overlayRuntimeIPAM{client: client, now: steppingClock()}
	ctx := context.Background()
	if _, err := r.GetAllocation(ctx, netip.MustParseAddr("10.0.0.1")); err != nil {
		t.Fatalf("GetAllocation: %v", err)
	}

	client.allocations = append(client.allocations, fabricAllocation("10.0.0.2", "8"))
	allocation, err := r.GetAllocation(ctx, netip.MustParseAddr("10.0.0.2"))
	if err != nil {
		t.Fatalf("GetAllocation of a new reservation: %v", err)
	}
	if allocation.DeviceID != "8" {
		t.Fatalf("DeviceID = %q, want 8", allocation.DeviceID)
	}

	_, err = r.GetAllocation(ctx, netip.MustParseAddr("10.0.0.9"))
	if !errors.Is(err, ipam.ErrAllocationNotFound) {
		t.Fatalf("GetAllocation of an unreserved address = %v, want ipam.ErrAllocationNotFound", err)
	}
	if client.listings != 3 {
		t.Fatalf("listings = %d, want 3", client.listings)
	}
}

func TestOverlayRuntimeIPAM_MissReusesListingStartedAfterIt(t *testing.T) {
	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	client := &fakeOverlayIPAMClient{}
	r := &overlayRuntimeIPAM{client: client, now: func() time.Time { return at }}
	ctx := context.Background()
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	_, err := r.GetAllocation(ctx, netip.MustParseAddr("10.0.0.9"))
	if !errors.Is(err, ipam.ErrAllocationNotFound) {
		t.Fatalf("GetAllocation = %v, want ipam.ErrAllocationNotFound", err)
	}
	if client.listings != 1 {
		t.Fatalf("listings = %d, want 1: a listing that started at the miss already answers it", client.listings)
	}
}

func TestOverlayRuntimeIPAM_OutageIsNotANotFound(t *testing.T) {
	client := &fakeOverlayIPAMClient{allocations: []*platformv1.IPAllocation{fabricAllocation("10.0.0.1", "7")}}
	r := &overlayRuntimeIPAM{client: client, now: steppingClock()}
	ctx := context.Background()
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	outage := status.Error(codes.Unavailable, "platformd down")
	client.err = outage
	_, err := r.GetAllocation(ctx, netip.MustParseAddr("10.0.0.2"))
	if !errors.Is(err, outage) {
		t.Fatalf("GetAllocation during an outage = %v, want the platformd error", err)
	}
	if errors.Is(err, ipam.ErrAllocationNotFound) || errors.Is(err, gateway.ErrOverlayRecordNotFound) {
		t.Fatalf("an outage must not read as a missing allocation: %v", err)
	}
	if err := r.Refresh(ctx); !errors.Is(err, outage) {
		t.Fatalf("Refresh during an outage = %v, want the platformd error", err)
	}
	if _, err := r.GetAllocation(ctx, netip.MustParseAddr("10.0.0.1")); err != nil {
		t.Fatalf("an indexed address must still resolve during an outage: %v", err)
	}
}

func TestOverlayRuntimeIPAM_RejectsMalformedAllocation(t *testing.T) {
	client := &fakeOverlayIPAMClient{allocations: []*platformv1.IPAllocation{fabricAllocation("not-an-ip", "7")}}
	r := &overlayRuntimeIPAM{client: client, now: steppingClock()}

	_, err := r.GetAllocation(context.Background(), netip.MustParseAddr("10.0.0.1"))
	if err == nil || errors.Is(err, ipam.ErrAllocationNotFound) {
		t.Fatalf("GetAllocation over a malformed allocation = %v, want a parse error", err)
	}
}

func TestOverlayRuntimeIPAM_GetAllocationsByDeviceListsFresh(t *testing.T) {
	client := &fakeOverlayIPAMClient{allocations: []*platformv1.IPAllocation{fabricAllocation("10.0.0.1", "7")}}
	r := &overlayRuntimeIPAM{client: client, now: steppingClock()}
	ctx := context.Background()
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	client.allocations = append(client.allocations, fabricAllocation("10.0.0.2", "7"), fabricAllocation("10.0.0.3", "8"))
	allocations, err := r.GetAllocationsByDevice(ctx, "7")
	if err != nil {
		t.Fatalf("GetAllocationsByDevice: %v", err)
	}
	if len(allocations) != 2 {
		t.Fatalf("GetAllocationsByDevice = %d allocations, want 2 from a fresh listing", len(allocations))
	}
}

func TestOverlayRuntimeIPAM_GetAllocationsByDeviceOutageKeepsLastListing(t *testing.T) {
	client := &fakeOverlayIPAMClient{allocations: []*platformv1.IPAllocation{
		fabricAllocation("10.0.0.1", "7"),
		fabricAllocation("10.0.0.3", "8"),
	}}
	r := &overlayRuntimeIPAM{client: client, now: steppingClock()}
	ctx := context.Background()
	if err := r.Refresh(ctx); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	outage := status.Error(codes.Unavailable, "platformd down")
	client.err = outage
	allocations, err := r.GetAllocationsByDevice(ctx, "7")
	if !errors.Is(err, outage) {
		t.Fatalf("GetAllocationsByDevice during an outage = %v, want the platformd error", err)
	}
	if len(allocations) != 1 || allocations[0].IP != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("GetAllocationsByDevice during an outage = %+v, want the last known 10.0.0.1", allocations)
	}
}

// fakeOverlayDeviceClient serves one device or one error.
type fakeOverlayDeviceClient struct {
	device *platformv1.Device
	err    error
}

func (f *fakeOverlayDeviceClient) Get(_ context.Context, _ uint64) (*platformv1.Device, error) {
	return f.device, f.err
}

func TestOverlayRuntimeDevices_GetMapsTheRecord(t *testing.T) {
	r := &overlayRuntimeDevices{client: &fakeOverlayDeviceClient{device: &platformv1.Device{
		Id:       42,
		Serial:   "SN-42",
		Hostname: "node-42",
		Model:    "x10",
	}}}

	device, err := r.Get(context.Background(), 42)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if device.ID != 42 || device.Serial != "SN-42" || device.Hostname != "node-42" || device.Model != "x10" {
		t.Fatalf("Get = %+v", device)
	}
}

func TestOverlayRuntimeDevices_GetSeparatesNotFoundFromOutage(t *testing.T) {
	missing := &overlayRuntimeDevices{client: &fakeOverlayDeviceClient{err: status.Error(codes.NotFound, "no device")}}
	if _, err := missing.Get(context.Background(), 42); !errors.Is(err, gateway.ErrOverlayRecordNotFound) {
		t.Fatalf("Get of a missing device = %v, want gateway.ErrOverlayRecordNotFound", err)
	}

	down := &overlayRuntimeDevices{client: &fakeOverlayDeviceClient{err: status.Error(codes.Unavailable, "down")}}
	_, err := down.Get(context.Background(), 42)
	if err == nil || errors.Is(err, gateway.ErrOverlayRecordNotFound) {
		t.Fatalf("Get during an outage = %v, want a non-not-found error", err)
	}
}

// fakeOverlayReportClient serves one attestation report or one error.
type fakeOverlayReportClient struct {
	report *platformv1.DeviceAttestationReport
	err    error
}

func (f *fakeOverlayReportClient) GetDeviceReport(_ context.Context, _ string) (*platformv1.DeviceAttestationReport, error) {
	return f.report, f.err
}

func TestOverlayRuntimeVerdicts_UsesTheAttestationTime(t *testing.T) {
	attestedAt := time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC)
	r := &overlayRuntimeVerdicts{client: &fakeOverlayReportClient{report: &platformv1.DeviceAttestationReport{
		Serial:              "SN-42",
		Verified:            true,
		Fresh:               true,
		PcrBaselineCaptured: true,
		PcrBaselineSource:   "signed",
		AttestedAt:          timestamppb.New(attestedAt),
		CollectedAt:         timestamppb.New(attestedAt.Add(time.Hour)),
	}}}

	recorded, err := r.LatestDeviceVerdict(context.Background(), 42)
	if err != nil {
		t.Fatalf("LatestDeviceVerdict: %v", err)
	}
	if !recorded.RecordedAt.Equal(attestedAt) {
		t.Fatalf("RecordedAt = %v, want the attestation time %v", recorded.RecordedAt, attestedAt)
	}
	if !recorded.Verdict.Passed || recorded.Verdict.DeviceID != 42 || recorded.Verdict.Serial != "SN-42" {
		t.Fatalf("Verdict = %+v", recorded.Verdict)
	}
}

func TestOverlayRuntimeVerdicts_NeverBackfillsTheAttestationTime(t *testing.T) {
	collectedAt := time.Date(2026, 10, 9, 11, 0, 0, 0, time.UTC)
	r := &overlayRuntimeVerdicts{client: &fakeOverlayReportClient{report: &platformv1.DeviceAttestationReport{
		Verified:    true,
		Fresh:       true,
		CollectedAt: timestamppb.New(collectedAt),
		AsOf:        timestamppb.New(collectedAt),
	}}}

	recorded, err := r.LatestDeviceVerdict(context.Background(), 42)
	if err != nil {
		t.Fatalf("LatestDeviceVerdict: %v", err)
	}
	if !recorded.RecordedAt.IsZero() {
		t.Fatalf("RecordedAt = %v, want zero: a report with no attestation time must not look fresh", recorded.RecordedAt)
	}
}

func TestOverlayRuntimeVerdicts_SeparatesNotFoundFromOutage(t *testing.T) {
	missing := &overlayRuntimeVerdicts{client: &fakeOverlayReportClient{err: status.Error(codes.NotFound, "no report")}}
	if _, err := missing.LatestDeviceVerdict(context.Background(), 42); !errors.Is(err, gateway.ErrOverlayRecordNotFound) {
		t.Fatalf("LatestDeviceVerdict without a report = %v, want gateway.ErrOverlayRecordNotFound", err)
	}

	down := &overlayRuntimeVerdicts{client: &fakeOverlayReportClient{err: status.Error(codes.Unavailable, "down")}}
	_, err := down.LatestDeviceVerdict(context.Background(), 42)
	if err == nil || errors.Is(err, gateway.ErrOverlayRecordNotFound) {
		t.Fatalf("LatestDeviceVerdict during an outage = %v, want a non-not-found error", err)
	}
}

func TestOverlayRuntimeVerdicts_UnfreshReportDoesNotPass(t *testing.T) {
	r := &overlayRuntimeVerdicts{client: &fakeOverlayReportClient{report: &platformv1.DeviceAttestationReport{
		Verified:   true,
		Fresh:      false,
		AttestedAt: timestamppb.Now(),
	}}}

	recorded, err := r.LatestDeviceVerdict(context.Background(), 42)
	if err != nil {
		t.Fatalf("LatestDeviceVerdict: %v", err)
	}
	if recorded.Verdict.Passed {
		t.Fatal("a verified report the platform marks stale must not pass")
	}
}

// fakeOverlayEventClient opens one stream of fixed events, ending in err.
type fakeOverlayEventClient struct {
	events  []*platformv1.Event
	end     error
	openErr error
	request *platformv1.StreamEventsRequest
}

func (f *fakeOverlayEventClient) StreamEvents(_ context.Context, req *platformv1.StreamEventsRequest) (sdkdaemon.EventStream, error) {
	f.request = req
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &fakeEventStream{events: f.events, end: f.end}, nil
}

type fakeEventStream struct {
	events []*platformv1.Event
	end    error
}

func (s *fakeEventStream) Recv() (*platformv1.Event, error) {
	if len(s.events) == 0 {
		return nil, s.end
	}
	event := s.events[0]
	s.events = s.events[1:]
	return event, nil
}

func (s *fakeEventStream) CloseSend() error { return nil }

func verdictEvent(v verdict.DeviceVerdict) *platformv1.Event {
	return &platformv1.Event{Source: verdict.EventSource, Metadata: verdict.EventMetadata(v)}
}

func TestOverlayRuntimeVerdictStream_DeliversOnlyDeviceVerdicts(t *testing.T) {
	failed := verdict.DeviceVerdict{DeviceID: 42, Reason: "no attestation certificate enrolled"}
	passed := verdict.DeviceVerdict{DeviceID: 43, Passed: true}
	unreadable := verdictEvent(failed)
	unreadable.Metadata["device_id"] = "forty-two"
	client := &fakeOverlayEventClient{
		events: []*platformv1.Event{
			{Source: "sdn.addressing", Metadata: verdict.EventMetadata(failed)},
			verdictEvent(failed),
			unreadable,
			verdictEvent(passed),
		},
		end: io.EOF,
	}
	s := &overlayRuntimeVerdictStream{client: client, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	var got []verdict.DeviceVerdict
	err := s.Follow(context.Background(), func(_ context.Context, v verdict.DeviceVerdict) {
		got = append(got, v)
	})

	if !errors.Is(err, io.EOF) {
		t.Fatalf("Follow = %v, want the stream's end", err)
	}
	if len(got) != 2 || got[0] != failed || got[1] != passed {
		t.Fatalf("delivered %+v, want only the two readable device verdicts", got)
	}
	if len(client.request.GetSources()) != 1 || client.request.GetSources()[0] != verdict.EventSource {
		t.Fatalf("the subscription must ask for device verdicts only: %+v", client.request)
	}
}

func TestOverlayRuntimeVerdictStream_ReportsAStreamThatCannotOpen(t *testing.T) {
	down := status.Error(codes.Unavailable, "down")
	s := &overlayRuntimeVerdictStream{client: &fakeOverlayEventClient{openErr: down}, logger: slog.Default()}

	err := s.Follow(context.Background(), func(context.Context, verdict.DeviceVerdict) {
		t.Fatal("nothing may be delivered")
	})

	if !errors.Is(err, down) {
		t.Fatalf("Follow = %v, want the open error", err)
	}
}
