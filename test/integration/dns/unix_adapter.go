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

//go:build integration

package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// unixDialTimeout is the timeout for establishing Unix socket connection.
const unixDialTimeout = 10 * time.Second

// UnixAdapter implements the DNSCommands interface using gRPC over Unix socket
// to communicate with platformd.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	dns        pb.DNSServiceClient
}

// NewUnixAdapter creates a new UnixAdapter instance.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (s *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the gRPC connection over Unix socket.
func (s *UnixAdapter) Setup(ctx context.Context) error {
	s.socketPath = os.Getenv(EnvPlatformdSocket)
	if s.socketPath == "" {
		s.socketPath = DefaultPlatformdSocket
	}

	conn, err := grpc.DialContext(ctx, "unix://"+s.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrUnixConnectionFailed{Path: s.socketPath, Err: err}
	}

	s.conn = conn
	s.dns = pb.NewDNSServiceClient(conn)

	// Verify connectivity with a list zones call
	_, err = s.dns.ListZones(ctx, &pb.ListZonesRequest{})
	if err != nil {
		s.conn.Close()
		return ErrUnixBackendUnavailable{Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (s *UnixAdapter) Teardown() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// =============================================================================
// Zone Management Operations
// =============================================================================

// CreateZone creates a new DNS zone via Unix socket.
func (s *UnixAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	req := &pb.CreateZoneRequest{
		Name:        opts.Name,
		Ttl:         opts.TTL,
		Description: opts.Description,
		Internal:    opts.Internal,
	}

	if opts.SOA != nil {
		req.Soa = &pb.SOARecord{
			Name:       opts.Name,
			Mname:      opts.SOA.MName,
			Rname:      opts.SOA.RName,
			Serial:     opts.SOA.Serial,
			Refresh:    opts.SOA.Refresh,
			Retry:      opts.SOA.Retry,
			Expire:     opts.SOA.Expire,
			MinimumTtl: opts.SOA.MinimumTTL,
			Ttl:        opts.TTL,
		}
	}

	resp, err := s.dns.CreateZone(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateZone", Err: err}
	}
	if resp.Zone == nil {
		return nil, ErrGRPCMissingInResponse{Method: "CreateZone", Field: "zone"}
	}

	return &CreateZoneResult{
		Name:      resp.Zone.Name,
		ID:        fmt.Sprintf("%d", resp.Zone.Id),
		TTL:       resp.Zone.Ttl,
		Internal:  resp.Zone.Internal,
		CreatedAt: time.Now(),
	}, nil
}

// GetZone retrieves a DNS zone by name via Unix socket.
func (s *UnixAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	req := &pb.GetZoneRequest{
		Name: zoneName,
	}

	resp, err := s.dns.GetZone(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetZone", Err: err}
	}
	if resp.Zone == nil {
		return nil, ErrGRPCMissingInResponse{Method: "GetZone", Field: "zone"}
	}

	result := &GetZoneResult{
		Name:        resp.Zone.Name,
		ID:          fmt.Sprintf("%d", resp.Zone.Id),
		TTL:         resp.Zone.Ttl,
		Description: resp.Zone.Description,
		Internal:    resp.Zone.Internal,
		RecordCount: countRecords(resp.Zone.Records),
	}

	if resp.Zone.Records != nil && resp.Zone.Records.Soa != nil {
		result.SOA = &SOARecordInfo{
			Name:       resp.Zone.Records.Soa.Name,
			MName:      resp.Zone.Records.Soa.Mname,
			RName:      resp.Zone.Records.Soa.Rname,
			Serial:     resp.Zone.Records.Soa.Serial,
			Refresh:    resp.Zone.Records.Soa.Refresh,
			Retry:      resp.Zone.Records.Soa.Retry,
			Expire:     resp.Zone.Records.Soa.Expire,
			MinimumTTL: resp.Zone.Records.Soa.MinimumTtl,
			TTL:        resp.Zone.Records.Soa.Ttl,
		}
	}

	return result, nil
}

// UpdateZone updates a DNS zone via Unix socket.
func (s *UnixAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	req := &pb.UpdateZoneRequest{
		Name:        zoneName,
		Ttl:         opts.TTL,
		Description: opts.Description,
	}

	resp, err := s.dns.UpdateZone(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateZone", Err: err}
	}
	if resp.Zone == nil {
		return nil, ErrGRPCMissingInResponse{Method: "UpdateZone", Field: "zone"}
	}

	return &UpdateZoneResult{
		Name:      resp.Zone.Name,
		TTL:       resp.Zone.Ttl,
		UpdatedAt: time.Now(),
	}, nil
}

// DeleteZone deletes a DNS zone via Unix socket.
func (s *UnixAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	req := &pb.DeleteZoneRequest{
		Name: zoneName,
	}

	resp, err := s.dns.DeleteZone(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteZone", Err: err}
	}

	return &DeleteZoneResult{
		Name:    zoneName,
		Deleted: resp.Status != nil && resp.Status.Success,
	}, nil
}

// ListZones lists DNS zones with pagination via Unix socket.
func (s *UnixAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	req := &pb.ListZonesRequest{}

	if opts.Internal != nil {
		if *opts.Internal {
			req.InternalOnly = true
		} else {
			req.PublicOnly = true
		}
	}

	if opts.Limit > 0 {
		req.Pagination = &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := s.dns.ListZones(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListZones", Err: err}
	}

	zones := make([]ZoneSummary, 0, len(resp.Zones))
	for _, z := range resp.Zones {
		zones = append(zones, ZoneSummary{
			Name:        z.Name,
			ID:          fmt.Sprintf("%d", z.Id),
			TTL:         z.Ttl,
			Internal:    z.Internal,
			RecordCount: countRecords(z.Records),
		})
	}

	result := &ListZonesResult{
		Zones: zones,
	}

	if resp.Pagination != nil {
		result.TotalCount = int32(resp.Pagination.TotalItems)
		result.HasMore = resp.Pagination.Page < resp.Pagination.TotalPages
	}

	return result, nil
}

// =============================================================================
// Record Management Operations
// =============================================================================

// AddRecord adds a DNS record to a zone via Unix socket.
func (s *UnixAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	req := &pb.AddRecordRequest{
		ZoneName: opts.ZoneName,
		Record:   buildProtoRecordMessage(opts),
	}

	resp, err := s.dns.AddRecord(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AddRecord", Err: err}
	}

	_ = resp // Response contains updated zone

	return &AddRecordResult{
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		CreatedAt:  time.Now(),
	}, nil
}

// GetRecord retrieves a DNS record via Unix socket.
func (s *UnixAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	zoneName := extractZoneName(name)

	req := &pb.ListRecordsRequest{
		ZoneName: zoneName,
		Type:     recordTypeStringToProto(recordType),
	}

	resp, err := s.dns.ListRecords(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListRecords", Err: err}
	}

	for _, rec := range resp.Records {
		recName, recValue, recTTL, priority, weight, port := extractRecordInfo(rec)
		if recName == name {
			return &GetRecordResult{
				Name:       recName,
				RecordType: recordType,
				Value:      recValue,
				TTL:        recTTL,
				Priority:   priority,
				Weight:     weight,
				Port:       port,
			}, nil
		}
	}

	return nil, ErrRecordNotFound{Name: name, Type: recordType}
}

// UpdateRecord updates a DNS record via Unix socket.
func (s *UnixAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	addOpts := AddRecordOptions{
		ZoneName:   opts.ZoneName,
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		Priority:   opts.Priority,
		Weight:     opts.Weight,
		Port:       opts.Port,
	}

	req := &pb.UpdateRecordRequest{
		ZoneName:  opts.ZoneName,
		OldRecord: buildProtoRecordMessage(addOpts),
		NewRecord: buildProtoRecordMessage(addOpts),
	}

	resp, err := s.dns.UpdateRecord(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateRecord", Err: err}
	}

	_ = resp // Response contains updated zone

	return &UpdateRecordResult{
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		UpdatedAt:  time.Now(),
	}, nil
}

// DeleteRecord deletes a DNS record via Unix socket.
func (s *UnixAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	zoneName := extractZoneName(name)

	req := &pb.DeleteRecordRequest{
		ZoneName: zoneName,
		Type:     recordTypeStringToProto(recordType),
		Name:     name,
	}

	resp, err := s.dns.DeleteRecord(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteRecord", Err: err}
	}

	return &DeleteRecordResult{
		Name:       name,
		RecordType: recordType,
		Deleted:    resp.Status != nil && resp.Status.Success,
	}, nil
}

// ListRecords lists DNS records in a zone via Unix socket.
func (s *UnixAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	req := &pb.ListRecordsRequest{
		ZoneName: zoneName,
	}

	if opts.RecordType != "" {
		req.Type = recordTypeStringToProto(opts.RecordType)
	}

	if opts.Limit > 0 {
		req.Pagination = &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
		}
	}

	resp, err := s.dns.ListRecords(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListRecords", Err: err}
	}

	records := make([]RecordSummary, 0, len(resp.Records))
	for _, r := range resp.Records {
		name, value, ttl, priority, _, _ := extractRecordInfo(r)
		records = append(records, RecordSummary{
			Name:       name,
			RecordType: recordTypeProtoToString(r.Type),
			Value:      value,
			TTL:        ttl,
			Priority:   priority,
		})
	}

	result := &ListRecordsResult{
		Records:    records,
		TotalCount: int32(len(records)),
	}
	if resp.Pagination != nil {
		result.TotalCount = int32(resp.Pagination.TotalItems)
		result.HasMore = resp.Pagination.Page < resp.Pagination.TotalPages
	}
	return result, nil
}

// =============================================================================
// Resolution Operations
// =============================================================================

// Resolve performs DNS resolution via Unix socket.
func (s *UnixAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	req := &pb.ResolveRequest{
		Fqdn: name,
		Type: recordTypeStringToProto(recordType),
	}

	resp, err := s.dns.Resolve(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "Resolve", Err: err}
	}

	values := make([]string, 0, len(resp.Records))
	var ttl uint32
	for _, r := range resp.Records {
		_, value, recordTTL, _, _, _ := extractRecordInfo(r)
		values = append(values, value)
		if ttl == 0 {
			ttl = recordTTL
		}
	}

	if len(values) == 0 {
		return nil, ErrRecordNotFound{Name: name, Type: recordType}
	}

	return &ResolveResult{
		Name:       name,
		RecordType: recordType,
		Values:     values,
		TTL:        ttl,
		Timestamp:  time.Now(),
	}, nil
}

// =============================================================================
// TLSA/DANE Operations
// =============================================================================

// AddTLSARecord adds a TLSA record for DANE via Unix socket.
func (s *UnixAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	req := &pb.AddRecordRequest{
		ZoneName: opts.ZoneName,
		Record: &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_TLSA,
			Record: &pb.Record_Tlsa{
				Tlsa: &pb.TLSARecord{
					Name:         opts.Name,
					Usage:        uint32(opts.Usage),
					Selector:     uint32(opts.Selector),
					MatchingType: uint32(opts.MatchingType),
					Data:         opts.Data,
					Ttl:          opts.TTL,
				},
			},
		},
	}

	resp, err := s.dns.AddRecord(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AddTLSARecord", Err: err}
	}

	_ = resp // Response contains updated zone

	return &AddTLSARecordResult{
		Name:         opts.Name,
		Usage:        opts.Usage,
		Selector:     opts.Selector,
		MatchingType: opts.MatchingType,
		Data:         opts.Data,
		TTL:          opts.TTL,
		CreatedAt:    time.Now(),
	}, nil
}

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates the Unix socket connection failed.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixBackendUnavailable indicates the backend is not responding.
type ErrUnixBackendUnavailable struct {
	Err error
}

func (e ErrUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("Unix backend unavailable: %v", e.Err)
}

func (e ErrUnixBackendUnavailable) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// Ensure UnixAdapter implements DNSCommands interface.
var _ DNSCommands = (*UnixAdapter)(nil)
