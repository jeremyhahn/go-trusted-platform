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
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdaemon "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// overlayIPAMClient is the part of the platform gateway SDK client the fabric
// allocation index reads.
type overlayIPAMClient interface {
	ListIPAMPools(ctx context.Context, zone string) ([]*platformv1.IPAMPool, error)
	ListAllocations(ctx context.Context, poolID string) ([]*platformv1.IPAllocation, error)
}

// overlayIPAMIndex is one listing of the fabric allocations, keyed by address.
// listedAt is when the listing started, so the index answers for every lookup
// made before then.
type overlayIPAMIndex struct {
	byIP     map[netip.Addr]*ipam.Allocation
	listedAt time.Time
}

// overlayRuntimeIPAM serves gateway.OverlayIPAMReader from an index of the
// platform's fabric allocations. EVPN delivers routes one at a time, so a
// route for an indexed address must not cost a platformd call. An address
// missing from the index lists the allocations again, unless a listing that
// started after the miss already answers it, so a burst of misses costs one
// listing. The admission sweep refreshes the index, which bounds how long a
// released allocation stays in it.
type overlayRuntimeIPAM struct {
	client overlayIPAMClient
	now    func() time.Time

	index atomic.Pointer[overlayIPAMIndex]
	// listing serialises listings, so concurrent misses share one.
	listing sync.Mutex
}

// GetAllocation returns the fabric allocation of addr, or
// ipam.ErrAllocationNotFound when platformd holds none.
func (r *overlayRuntimeIPAM) GetAllocation(ctx context.Context, addr netip.Addr) (*ipam.Allocation, error) {
	missedAt := r.now()
	if index := r.index.Load(); index != nil {
		if allocation, ok := index.byIP[addr]; ok {
			return allocation, nil
		}
	}
	index, err := r.listSince(ctx, missedAt)
	if err != nil {
		return nil, err
	}
	if allocation, ok := index.byIP[addr]; ok {
		return allocation, nil
	}
	return nil, ipam.ErrAllocationNotFound
}

// GetAllocationsByDevice returns the device's fabric allocations from a fresh
// listing. While platformd cannot be read it returns the allocations of the
// last listing along with the error, so a revocation still withdraws every
// VTEP the gateway knew the device by.
func (r *overlayRuntimeIPAM) GetAllocationsByDevice(ctx context.Context, deviceID string) ([]*ipam.Allocation, error) {
	index, err := r.listSince(ctx, r.now())
	if err != nil {
		index = r.index.Load()
	}
	if index == nil {
		return nil, err
	}
	var out []*ipam.Allocation
	for _, allocation := range index.byIP {
		if allocation.DeviceID == deviceID {
			out = append(out, allocation)
		}
	}
	return out, err
}

// Refresh implements gateway.OverlayIPAMRefresher by listing the allocations.
// A failed listing keeps the previous index.
func (r *overlayRuntimeIPAM) Refresh(ctx context.Context) error {
	_, err := r.listSince(ctx, r.now())
	return err
}

// listSince returns an index whose listing started no earlier than since,
// listing the allocations when there is none yet.
func (r *overlayRuntimeIPAM) listSince(ctx context.Context, since time.Time) (*overlayIPAMIndex, error) {
	r.listing.Lock()
	defer r.listing.Unlock()
	if index := r.index.Load(); index != nil && !index.listedAt.Before(since) {
		return index, nil
	}
	listedAt := r.now()
	byIP, err := r.listFabric(ctx)
	if err != nil {
		return nil, err
	}
	index := &overlayIPAMIndex{byIP: byIP, listedAt: listedAt}
	r.index.Store(index)
	return index, nil
}

// listFabric reads every allocation of every fabric pool.
func (r *overlayRuntimeIPAM) listFabric(ctx context.Context) (map[netip.Addr]*ipam.Allocation, error) {
	pools, err := r.client.ListIPAMPools(ctx, string(zone.ZoneFabric))
	if err != nil {
		return nil, err
	}
	byIP := make(map[netip.Addr]*ipam.Allocation)
	for _, pool := range pools {
		allocations, err := r.client.ListAllocations(ctx, pool.GetId())
		if err != nil {
			return nil, err
		}
		for _, allocation := range allocations {
			converted, err := overlayIPAMAllocationFromProto(allocation, pool.GetZone())
			if err != nil {
				return nil, err
			}
			if converted != nil {
				byIP[converted.IP] = converted
			}
		}
	}
	return byIP, nil
}

// overlayDeviceClient is the part of the platform device SDK client overlay
// admission reads.
type overlayDeviceClient interface {
	Get(ctx context.Context, id uint64) (*platformv1.Device, error)
}

// overlayRuntimeDevices serves gateway.OverlayDeviceGetter from platformd.
type overlayRuntimeDevices struct {
	client overlayDeviceClient
}

// Get returns the platform record of device id. A device platformd does not
// hold is reported as gateway.ErrOverlayRecordNotFound.
func (r *overlayRuntimeDevices) Get(ctx context.Context, id uint64) (*deviceentities.Device, error) {
	device, err := r.client.Get(ctx, id)
	if err != nil {
		return nil, overlayPlatformError("device "+strconv.FormatUint(id, 10), err)
	}
	if device == nil {
		return nil, nil
	}
	return &deviceentities.Device{
		ID:            device.GetId(),
		AttestPub:     device.GetAttestPub(),
		AttestCert:    device.GetAttestCert(),
		EKCert:        device.GetEkCert(),
		EventLog:      device.GetEventLog(),
		HashAlgoId:    device.GetHashAlgoId(),
		Hostname:      device.GetHostname(),
		Model:         device.GetModel(),
		Serial:        device.GetSerial(),
		SigningPub:    device.GetSigningPub(),
		SwitchName:    device.GetSwitchName(),
		SwitchPort:    device.GetSwitchPort(),
		NetworkPortID: device.GetNetworkPortId(),
		CreatedAt:     protoTime(device.GetCreatedAt()),
		UpdatedAt:     protoTime(device.GetUpdatedAt()),
	}, nil
}

// overlayReportClient is the part of the platform attestation SDK client
// overlay admission reads.
type overlayReportClient interface {
	GetDeviceReport(ctx context.Context, deviceID string) (*platformv1.DeviceAttestationReport, error)
}

// overlayRuntimeVerdicts serves gateway.OverlayVerdictReader from the
// platform's attestation report of a device.
type overlayRuntimeVerdicts struct {
	client overlayReportClient
}

// LatestDeviceVerdict returns the device's latest verdict, stamped with the
// time the device was attested. A report with no attestation time keeps a
// zero RecordedAt, which the admitter refuses: when the report was collected
// or served says nothing about how fresh the quote is. A device platformd has
// no report for is reported as gateway.ErrOverlayRecordNotFound.
func (r *overlayRuntimeVerdicts) LatestDeviceVerdict(ctx context.Context, deviceID uint64) (*deviceverdict.RecordedDeviceVerdict, error) {
	id := strconv.FormatUint(deviceID, 10)
	report, err := r.client.GetDeviceReport(ctx, id)
	if err != nil {
		return nil, overlayPlatformError("attestation report for device "+id, err)
	}
	return &deviceverdict.RecordedDeviceVerdict{
		Verdict: deviceverdict.DeviceVerdict{
			DeviceID:         deviceID,
			Serial:           report.GetSerial(),
			Passed:           report.GetVerified() && report.GetFresh(),
			Cryptographic:    report.GetCryptographicFailure(),
			Reason:           report.GetMessage(),
			BaselineCaptured: report.GetPcrBaselineCaptured(),
			BaselineSource:   report.GetPcrBaselineSource(),
		},
		EventID:    "device-report-" + id,
		RecordedAt: protoTime(report.GetAttestedAt()),
	}, nil
}

// overlayEventClient is the part of the platform daemon SDK client the verdict
// stream reads.
type overlayEventClient interface {
	StreamEvents(ctx context.Context, req *platformv1.StreamEventsRequest) (sdkdaemon.EventStream, error)
}

// overlayRuntimeVerdictStream serves gateway.OverlayVerdictStream from
// platformd's event stream.
type overlayRuntimeVerdictStream struct {
	client overlayEventClient
	logger *slog.Logger
}

// Follow streams platformd's events and hands each device verdict to deliver
// until ctx ends or the stream breaks. platformd sends every event to every
// subscriber, so Follow keeps only those from verdict.EventSource; a verdict
// event it cannot read is logged and skipped.
func (s *overlayRuntimeVerdictStream) Follow(ctx context.Context, deliver func(context.Context, verdict.DeviceVerdict)) error {
	// Cancelling the stream's context is what releases it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, err := s.client.StreamEvents(ctx, &platformv1.StreamEventsRequest{
		Types:   []platformv1.EventType{platformv1.EventType_EVENT_TYPE_ATTESTATION_VERIFIED},
		Sources: []string{verdict.EventSource},
	})
	if err != nil {
		return err
	}
	for {
		event, err := events.Recv()
		if err != nil {
			return err
		}
		if event.GetSource() != verdict.EventSource {
			continue
		}
		v, err := verdict.FromEventMetadata(event.GetMetadata())
		if err != nil {
			s.logger.Warn("overlay: skipping an unreadable device verdict event",
				slog.String("event_id", event.GetId()), slog.Any("error", err))
			continue
		}
		deliver(ctx, v)
	}
}

// overlayPlatformError marks a platformd NotFound as a missing record, so the
// admitter denies; every other error stays an outage.
func overlayPlatformError(record string, err error) error {
	if status.Code(err) == codes.NotFound {
		return &ErrOverlayPlatformRecordMissing{Record: record, Cause: err}
	}
	return err
}

func overlayIPAMAllocationFromProto(allocation *platformv1.IPAllocation, zoneName string) (*ipam.Allocation, error) {
	if allocation == nil {
		return nil, nil
	}
	addr, err := netip.ParseAddr(allocation.GetIp())
	if err != nil {
		return nil, err
	}
	converted := &ipam.Allocation{
		ID:          allocation.GetIp(),
		PoolID:      allocation.GetPoolId(),
		Zone:        zoneName,
		IP:          addr,
		DeviceID:    allocation.GetDeviceId(),
		Hostname:    allocation.GetHostname(),
		AllocatedAt: protoTime(allocation.GetAllocatedAt()),
		ExpiresAt:   protoTime(allocation.GetExpiresAt()),
		Status:      ipam.AllocationStatusActive,
	}
	return converted, nil
}

func protoTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
