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
	"os"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements DNSCommands using gRPC calls to platformd.
// This adapter makes gRPC calls to the platformd server for testing
// the gRPC transport layer consistency with other protocol adapters.
type GRPCAdapter struct {
	conn *grpc.ClientConn
	dns  pb.DNSServiceClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformGRPC
	}

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.dns = pb.NewDNSServiceClient(conn)

	// Verify connectivity by listing zones (will return empty if no zones exist)
	_, err = g.dns.ListZones(ctx, &pb.ListZonesRequest{})
	if err != nil {
		conn.Close()
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Zone Management Operations
// =============================================================================

// CreateZone creates a new DNS zone via gRPC.
func (g *GRPCAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
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

	resp, err := g.dns.CreateZone(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateZone", Err: err}
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

// GetZone retrieves a DNS zone by name via gRPC.
func (g *GRPCAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	req := &pb.GetZoneRequest{
		Name: zoneName,
	}

	resp, err := g.dns.GetZone(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetZone", Err: err}
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

// UpdateZone updates a DNS zone via gRPC.
func (g *GRPCAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	req := &pb.UpdateZoneRequest{
		Name:        zoneName,
		Ttl:         opts.TTL,
		Description: opts.Description,
	}

	resp, err := g.dns.UpdateZone(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateZone", Err: err}
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

// DeleteZone deletes a DNS zone via gRPC.
func (g *GRPCAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	req := &pb.DeleteZoneRequest{
		Name: zoneName,
	}

	resp, err := g.dns.DeleteZone(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteZone", Err: err}
	}

	return &DeleteZoneResult{
		Name:    zoneName,
		Deleted: resp.Status != nil && resp.Status.Success,
	}, nil
}

// ListZones lists DNS zones with pagination via gRPC.
func (g *GRPCAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
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

	resp, err := g.dns.ListZones(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListZones", Err: err}
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

// AddRecord adds a DNS record to a zone via gRPC.
func (g *GRPCAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	req := &pb.AddRecordRequest{
		ZoneName: opts.ZoneName,
		Record:   buildProtoRecordMessage(opts),
	}

	resp, err := g.dns.AddRecord(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AddRecord", Err: err}
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

// GetRecord retrieves a DNS record via gRPC.
// Note: The gRPC API doesn't have a dedicated GetRecord - we use ListRecords and filter.
func (g *GRPCAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	// Extract zone name from record name (e.g., "www.example.com." -> "example.com.")
	zoneName := extractZoneName(name)

	req := &pb.ListRecordsRequest{
		ZoneName: zoneName,
		Type:     recordTypeStringToProto(recordType),
	}

	resp, err := g.dns.ListRecords(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListRecords", Err: err}
	}

	// Find the matching record
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

// UpdateRecord updates a DNS record via gRPC.
func (g *GRPCAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
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

	resp, err := g.dns.UpdateRecord(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateRecord", Err: err}
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

// DeleteRecord deletes a DNS record via gRPC.
func (g *GRPCAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	zoneName := extractZoneName(name)

	req := &pb.DeleteRecordRequest{
		ZoneName: zoneName,
		Type:     recordTypeStringToProto(recordType),
		Name:     name,
	}

	resp, err := g.dns.DeleteRecord(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteRecord", Err: err}
	}

	return &DeleteRecordResult{
		Name:       name,
		RecordType: recordType,
		Deleted:    resp.Status != nil && resp.Status.Success,
	}, nil
}

// ListRecords lists DNS records in a zone via gRPC.
func (g *GRPCAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	req := &pb.ListRecordsRequest{
		ZoneName: zoneName,
	}

	if opts.RecordType != "" {
		req.Type = recordTypeStringToProto(opts.RecordType)
	}

	resp, err := g.dns.ListRecords(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListRecords", Err: err}
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

	return &ListRecordsResult{
		Records:    records,
		TotalCount: int32(len(records)),
	}, nil
}

// =============================================================================
// Resolution Operations
// =============================================================================

// Resolve performs DNS resolution via gRPC.
func (g *GRPCAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	req := &pb.ResolveRequest{
		Fqdn: name,
		Type: recordTypeStringToProto(recordType),
	}

	resp, err := g.dns.Resolve(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "Resolve", Err: err}
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

// AddTLSARecord adds a TLSA record for DANE via gRPC.
func (g *GRPCAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
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

	resp, err := g.dns.AddRecord(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AddTLSARecord", Err: err}
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
// Helper Functions
// =============================================================================

// countRecords counts the total number of records in a RecordSet.
func countRecords(rs *pb.RecordSet) int {
	if rs == nil {
		return 0
	}
	count := 0
	if rs.Soa != nil {
		count++
	}
	count += len(rs.ARecords)
	count += len(rs.AaaaRecords)
	count += len(rs.CnameRecords)
	count += len(rs.MxRecords)
	count += len(rs.NsRecords)
	count += len(rs.TxtRecords)
	count += len(rs.SrvRecords)
	count += len(rs.CaaRecords)
	count += len(rs.TlsaRecords)
	count += len(rs.DnskeyRecords)
	count += len(rs.DsRecords)
	return count
}

// extractZoneName extracts the zone name from a fully qualified record name.
func extractZoneName(name string) string {
	// Simple extraction: remove first label
	// e.g., "www.example.com." -> "example.com."
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i+1 < len(name) {
				return name[i+1:]
			}
			return name
		}
	}
	return name
}

// recordTypeStringToProto converts a string record type to proto enum.
func recordTypeStringToProto(t string) pb.RecordType {
	switch t {
	case "A":
		return pb.RecordType_RECORD_TYPE_A
	case "AAAA":
		return pb.RecordType_RECORD_TYPE_AAAA
	case "CNAME":
		return pb.RecordType_RECORD_TYPE_CNAME
	case "MX":
		return pb.RecordType_RECORD_TYPE_MX
	case "NS":
		return pb.RecordType_RECORD_TYPE_NS
	case "TXT":
		return pb.RecordType_RECORD_TYPE_TXT
	case "SRV":
		return pb.RecordType_RECORD_TYPE_SRV
	case "SOA":
		return pb.RecordType_RECORD_TYPE_SOA
	case "CAA":
		return pb.RecordType_RECORD_TYPE_CAA
	case "TLSA":
		return pb.RecordType_RECORD_TYPE_TLSA
	default:
		return pb.RecordType_RECORD_TYPE_UNSPECIFIED
	}
}

// recordTypeProtoToString converts a proto record type to string.
func recordTypeProtoToString(t pb.RecordType) string {
	switch t {
	case pb.RecordType_RECORD_TYPE_A:
		return "A"
	case pb.RecordType_RECORD_TYPE_AAAA:
		return "AAAA"
	case pb.RecordType_RECORD_TYPE_CNAME:
		return "CNAME"
	case pb.RecordType_RECORD_TYPE_MX:
		return "MX"
	case pb.RecordType_RECORD_TYPE_NS:
		return "NS"
	case pb.RecordType_RECORD_TYPE_TXT:
		return "TXT"
	case pb.RecordType_RECORD_TYPE_SRV:
		return "SRV"
	case pb.RecordType_RECORD_TYPE_SOA:
		return "SOA"
	case pb.RecordType_RECORD_TYPE_CAA:
		return "CAA"
	case pb.RecordType_RECORD_TYPE_TLSA:
		return "TLSA"
	default:
		return ""
	}
}

// buildProtoRecordMessage builds a complete proto Record message from AddRecordOptions.
func buildProtoRecordMessage(opts AddRecordOptions) *pb.Record {
	switch opts.RecordType {
	case "A":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_A,
			Record: &pb.Record_A{
				A: &pb.ARecord{
					Name:  opts.Name,
					Value: opts.Value,
					Ttl:   opts.TTL,
				},
			},
		}
	case "AAAA":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_AAAA,
			Record: &pb.Record_Aaaa{
				Aaaa: &pb.AAAARecord{
					Name:  opts.Name,
					Value: opts.Value,
					Ttl:   opts.TTL,
				},
			},
		}
	case "CNAME":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_CNAME,
			Record: &pb.Record_Cname{
				Cname: &pb.CNAMERecord{
					Name:  opts.Name,
					Value: opts.Value,
					Ttl:   opts.TTL,
				},
			},
		}
	case "MX":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_MX,
			Record: &pb.Record_Mx{
				Mx: &pb.MXRecord{
					Name:     opts.Name,
					Value:    opts.Value,
					Priority: uint32(opts.Priority),
					Ttl:      opts.TTL,
				},
			},
		}
	case "NS":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_NS,
			Record: &pb.Record_Ns{
				Ns: &pb.NSRecord{
					Name:  opts.Name,
					Value: opts.Value,
					Ttl:   opts.TTL,
				},
			},
		}
	case "TXT":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_TXT,
			Record: &pb.Record_Txt{
				Txt: &pb.TXTRecord{
					Name:  opts.Name,
					Value: opts.Value,
					Ttl:   opts.TTL,
				},
			},
		}
	case "SRV":
		return &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_SRV,
			Record: &pb.Record_Srv{
				Srv: &pb.SRVRecord{
					Name:     opts.Name,
					Target:   opts.Value,
					Port:     uint32(opts.Port),
					Priority: uint32(opts.Priority),
					Weight:   uint32(opts.Weight),
					Ttl:      opts.TTL,
				},
			},
		}
	default:
		return nil
	}
}

// extractRecordInfo extracts common record information from a proto Record.
func extractRecordInfo(r *pb.Record) (name, value string, ttl uint32, priority, weight, port uint16) {
	switch rec := r.Record.(type) {
	case *pb.Record_A:
		return rec.A.Name, rec.A.Value, rec.A.Ttl, 0, 0, 0
	case *pb.Record_Aaaa:
		return rec.Aaaa.Name, rec.Aaaa.Value, rec.Aaaa.Ttl, 0, 0, 0
	case *pb.Record_Cname:
		return rec.Cname.Name, rec.Cname.Value, rec.Cname.Ttl, 0, 0, 0
	case *pb.Record_Mx:
		return rec.Mx.Name, rec.Mx.Value, rec.Mx.Ttl, uint16(rec.Mx.Priority), 0, 0
	case *pb.Record_Ns:
		return rec.Ns.Name, rec.Ns.Value, rec.Ns.Ttl, 0, 0, 0
	case *pb.Record_Txt:
		return rec.Txt.Name, rec.Txt.Value, rec.Txt.Ttl, 0, 0, 0
	case *pb.Record_Srv:
		return rec.Srv.Name, rec.Srv.Target, rec.Srv.Ttl, uint16(rec.Srv.Priority), uint16(rec.Srv.Weight), uint16(rec.Srv.Port)
	case *pb.Record_Caa:
		return rec.Caa.Name, rec.Caa.Value, rec.Caa.Ttl, 0, 0, 0
	case *pb.Record_Tlsa:
		return rec.Tlsa.Name, rec.Tlsa.Data, rec.Tlsa.Ttl, 0, 0, 0
	default:
		return "", "", 0, 0, 0, 0
	}
}

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCMissingInResponse indicates a successful gRPC reply (over TCP or
// the Unix socket) without a field the call always returns.
type ErrGRPCMissingInResponse struct {
	Method string
	Field  string
}

func (e ErrGRPCMissingInResponse) Error() string {
	return "gRPC " + e.Method + " response carries no " + e.Field
}

// ErrRecordNotFound indicates a record was not found.
type ErrRecordNotFound struct {
	Name string
	Type string
}

func (e ErrRecordNotFound) Error() string {
	return fmt.Sprintf("record not found: %s (type %s)", e.Name, e.Type)
}

// Ensure GRPCAdapter implements DNSCommands interface.
var _ DNSCommands = (*GRPCAdapter)(nil)
