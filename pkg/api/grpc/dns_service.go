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

package grpc

import (
	"context"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DNS gRPC service error types.

// ErrNilDNSService is returned when the DNS service is nil.
type ErrNilDNSService struct{}

func (e ErrNilDNSService) Error() string {
	return "dns service is nil"
}

// ErrMissingZoneName is returned when a zone name is required but not provided.
type ErrMissingZoneName struct{}

func (e ErrMissingZoneName) Error() string {
	return "zone name is required"
}

// ErrMissingRecordName is returned when a record name is required but not provided.
type ErrMissingRecordName struct{}

func (e ErrMissingRecordName) Error() string {
	return "record name is required"
}

// ErrMissingRecordType is returned when a record type is required but not provided.
type ErrMissingRecordType struct{}

func (e ErrMissingRecordType) Error() string {
	return "record type is required"
}

// ErrMissingRecord is returned when a record is required but not provided.
type ErrMissingRecord struct{}

func (e ErrMissingRecord) Error() string {
	return "record is required"
}

// ErrMissingFQDN is returned when an FQDN is required but not provided.
type ErrMissingFQDN struct{}

func (e ErrMissingFQDN) Error() string {
	return "fqdn is required"
}

// ErrMissingIP is returned when an IP address is required but not provided.
type ErrMissingIP struct{}

func (e ErrMissingIP) Error() string {
	return "ip address is required"
}

// ErrInvalidRecordType is returned when an invalid record type is provided.
type ErrInvalidRecordType struct {
	Type string
}

func (e ErrInvalidRecordType) Error() string {
	return "invalid record type: " + e.Type
}

// ErrDNSOperationFailed is returned when a DNS operation fails.
type ErrDNSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDNSOperationFailed) Error() string {
	if e.Cause != nil {
		return "dns operation " + e.Operation + " failed: " + e.Cause.Error()
	}
	return "dns operation " + e.Operation + " failed"
}

// dnsSuccessStatus creates a success status response.
func dnsSuccessStatus(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

// DNSGRPCService implements the gRPC DNSService server interface.
// It wraps the dns.DNSService interface to provide gRPC access to DNS operations.
type DNSGRPCService struct {
	platformv1.UnimplementedDNSServiceServer
	logger  *logging.Logger
	service dns.DNSService
}

// NewDNSGRPCService creates a new DNSGRPCService instance.
func NewDNSGRPCService(
	logger *logging.Logger,
	service dns.DNSService,
) *DNSGRPCService {
	return &DNSGRPCService{
		logger:  logger,
		service: service,
	}
}

// CreateZone creates a new DNS zone.
func (s *DNSGRPCService) CreateZone(
	ctx context.Context,
	req *platformv1.CreateZoneRequest,
) (*platformv1.CreateZoneResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	// Create the zone
	if err := s.service.CreateZone(ctx, req.GetName()); err != nil {
		return nil, s.mapError("CreateZone", err)
	}

	// Retrieve the created zone to get full details
	zone, err := s.service.Zone(ctx, req.GetName())
	if err != nil {
		return nil, s.mapError("CreateZone", err)
	}

	// Update zone properties if provided
	if req.GetTtl() > 0 || req.GetDescription() != "" {
		zone.TTL = req.GetTtl()
		zone.Description = req.GetDescription()
		zone.Internal = req.GetInternal()

		// Set SOA record if provided
		if req.GetSoa() != nil {
			zone.RecordSet.SOARecord = protoSOAToEntity(req.GetSoa())
		}

		// Add NS records if provided
		for _, ns := range req.GetNsRecords() {
			zone.AddNSRecord(&entities.NSRecord{
				Name:  ns.GetName(),
				Value: ns.GetValue(),
				TTL:   ns.GetTtl(),
			})
		}

		if err := s.service.Save(ctx, zone); err != nil {
			return nil, s.mapError("CreateZone", err)
		}
	}

	return &platformv1.CreateZoneResponse{
		Status: dnsSuccessStatus("zone created successfully"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// GetZone retrieves a DNS zone by name.
func (s *DNSGRPCService) GetZone(
	ctx context.Context,
	req *platformv1.GetZoneRequest,
) (*platformv1.GetZoneResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	zone, err := s.service.Zone(ctx, req.GetName())
	if err != nil {
		return nil, s.mapError("GetZone", err)
	}

	return &platformv1.GetZoneResponse{
		Zone: entityZoneToProto(zone),
	}, nil
}

// UpdateZone updates an existing DNS zone.
func (s *DNSGRPCService) UpdateZone(
	ctx context.Context,
	req *platformv1.UpdateZoneRequest,
) (*platformv1.UpdateZoneResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	zone, err := s.service.Zone(ctx, req.GetName())
	if err != nil {
		return nil, s.mapError("UpdateZone", err)
	}

	// Update zone properties
	if req.GetTtl() > 0 {
		zone.TTL = req.GetTtl()
	}
	if req.GetDescription() != "" {
		zone.Description = req.GetDescription()
	}

	if err := s.service.Save(ctx, zone); err != nil {
		return nil, s.mapError("UpdateZone", err)
	}

	return &platformv1.UpdateZoneResponse{
		Status: dnsSuccessStatus("zone updated successfully"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// DeleteZone deletes a DNS zone.
func (s *DNSGRPCService) DeleteZone(
	ctx context.Context,
	req *platformv1.DeleteZoneRequest,
) (*platformv1.DeleteZoneResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	if err := s.service.DeleteZone(ctx, req.GetName()); err != nil {
		return nil, s.mapError("DeleteZone", err)
	}

	return &platformv1.DeleteZoneResponse{
		Status: dnsSuccessStatus("zone deleted successfully"),
	}, nil
}

// ListZones returns a list of DNS zones.
func (s *DNSGRPCService) ListZones(
	ctx context.Context,
	req *platformv1.ListZonesRequest,
) (*platformv1.ListZonesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	zones, err := s.service.ListZones(ctx)
	if err != nil {
		return nil, s.mapError("ListZones", err)
	}

	// Filter zones based on request flags
	filteredZones := make([]*platformv1.Zone, 0, len(zones))
	for _, zone := range zones {
		// Apply internal/public filtering
		if req.GetInternalOnly() && !zone.Internal {
			continue
		}
		if req.GetPublicOnly() && zone.Internal {
			continue
		}
		filteredZones = append(filteredZones, entityZoneToProto(zone))
	}

	// Apply pagination if requested
	pagination := req.GetPagination()
	if pagination != nil && pagination.GetPageSize() > 0 {
		page := int(pagination.GetPage())
		pageSize := int(pagination.GetPageSize())

		if page < 1 {
			page = 1
		}

		start := (page - 1) * pageSize
		if start > len(filteredZones) {
			start = len(filteredZones)
		}

		end := start + pageSize
		if end > len(filteredZones) {
			end = len(filteredZones)
		}

		total := len(filteredZones)
		totalPages := (total + pageSize - 1) / pageSize
		filteredZones = filteredZones[start:end]

		return &platformv1.ListZonesResponse{
			Zones: filteredZones,
			Pagination: &platformv1.PaginationResponse{
				Page:       uint32(page),
				PageSize:   uint32(pageSize),
				TotalPages: uint32(totalPages),
				TotalItems: uint64(total),
			},
		}, nil
	}

	return &platformv1.ListZonesResponse{
		Zones: filteredZones,
	}, nil
}

// AddRecord adds a DNS record to a zone.
func (s *DNSGRPCService) AddRecord(
	ctx context.Context,
	req *platformv1.AddRecordRequest,
) (*platformv1.AddRecordResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	if req.GetRecord() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRecord{}.Error())
	}

	recordType, name, value, ttl, err := extractRecordInfo(req.GetRecord())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.service.AddRecord(ctx, name, recordType, value, int(ttl)); err != nil {
		return nil, s.mapError("AddRecord", err)
	}

	// Retrieve updated zone
	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		return nil, s.mapError("AddRecord", err)
	}

	return &platformv1.AddRecordResponse{
		Status: dnsSuccessStatus("record added successfully"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// DeleteRecord deletes a DNS record from a zone.
func (s *DNSGRPCService) DeleteRecord(
	ctx context.Context,
	req *platformv1.DeleteRecordRequest,
) (*platformv1.DeleteRecordResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRecordName{}.Error())
	}

	if req.GetType() == platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRecordType{}.Error())
	}

	recordType := protoRecordTypeToString(req.GetType())
	if err := s.service.DeleteRecord(ctx, req.GetName(), recordType); err != nil {
		return nil, s.mapError("DeleteRecord", err)
	}

	// Retrieve updated zone
	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		return nil, s.mapError("DeleteRecord", err)
	}

	return &platformv1.DeleteRecordResponse{
		Status: dnsSuccessStatus("record deleted successfully"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// UpdateRecord updates a DNS record in a zone.
func (s *DNSGRPCService) UpdateRecord(
	ctx context.Context,
	req *platformv1.UpdateRecordRequest,
) (*platformv1.UpdateRecordResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	if req.GetOldRecord() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRecord{}.Error())
	}

	if req.GetNewRecord() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRecord{}.Error())
	}

	// Delete old record
	oldType, oldName, _, _, err := extractRecordInfo(req.GetOldRecord())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.service.DeleteRecord(ctx, oldName, oldType); err != nil {
		s.logger.Debug("delete during update failed (may not exist)", "error", err)
	}

	// Add new record
	newType, newName, newValue, newTTL, err := extractRecordInfo(req.GetNewRecord())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.service.AddRecord(ctx, newName, newType, newValue, int(newTTL)); err != nil {
		return nil, s.mapError("UpdateRecord", err)
	}

	// Retrieve updated zone
	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		return nil, s.mapError("UpdateRecord", err)
	}

	return &platformv1.UpdateRecordResponse{
		Status: dnsSuccessStatus("record updated successfully"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// ListRecords lists DNS records in a zone.
func (s *DNSGRPCService) ListRecords(
	ctx context.Context,
	req *platformv1.ListRecordsRequest,
) (*platformv1.ListRecordsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	records, err := s.service.ListRecords(ctx, req.GetZoneName())
	if err != nil {
		return nil, s.mapError("ListRecords", err)
	}

	protoRecords := make([]*platformv1.Record, 0, len(records))
	requestedType := req.GetType()

	for _, rec := range records {
		protoRecord := entityRecordToProto(rec)
		if protoRecord != nil {
			// Filter by type if specified
			if requestedType != platformv1.RecordType_RECORD_TYPE_UNSPECIFIED &&
				protoRecord.GetType() != requestedType {
				continue
			}
			protoRecords = append(protoRecords, protoRecord)
		}
	}

	return &platformv1.ListRecordsResponse{
		Records: protoRecords,
	}, nil
}

// SignZone signs a DNS zone with DNSSEC.
func (s *DNSGRPCService) SignZone(
	ctx context.Context,
	req *platformv1.SignZoneRequest,
) (*platformv1.SignZoneResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		return nil, s.mapError("SignZone", err)
	}

	if err := s.service.SignZone(zone); err != nil {
		return nil, s.mapError("SignZone", err)
	}

	// Save the signed zone
	if err := s.service.Save(ctx, zone); err != nil {
		return nil, s.mapError("SignZone", err)
	}

	return &platformv1.SignZoneResponse{
		Status: dnsSuccessStatus("zone signed successfully"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// GetDNSSECStatus retrieves the DNSSEC status for a zone.
func (s *DNSGRPCService) GetDNSSECStatus(
	ctx context.Context,
	req *platformv1.GetDNSSECStatusRequest,
) (*platformv1.GetDNSSECStatusResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingZoneName{}.Error())
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		return nil, s.mapError("GetDNSSECStatus", err)
	}

	enabled := s.service.IsDNSSECEnabled()
	zoneSigned := len(zone.RecordSet.RRSIGRecords) > 0

	// Convert DNSKEY records
	dnskeyRecords := make([]*platformv1.DNSKEYRecord, 0, len(zone.RecordSet.DNSKEYRecords))
	for _, key := range zone.RecordSet.DNSKEYRecords {
		dnskeyRecords = append(dnskeyRecords, entityDNSKEYToProto(key))
	}

	// Convert DS records
	dsRecords := make([]*platformv1.DSRecord, 0, len(zone.RecordSet.DSRecords))
	for _, ds := range zone.RecordSet.DSRecords {
		dsRecords = append(dsRecords, entityDSToProto(ds))
	}

	return &platformv1.GetDNSSECStatusResponse{
		Status: &platformv1.DNSSECStatus{
			Enabled:    enabled,
			ZoneSigned: zoneSigned,
			Keys:       dnskeyRecords,
			DsRecords:  dsRecords,
		},
	}, nil
}

// Resolve resolves a DNS query.
func (s *DNSGRPCService) Resolve(
	ctx context.Context,
	req *platformv1.ResolveRequest,
) (*platformv1.ResolveResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetFqdn() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingFQDN{}.Error())
	}

	recordType := "A"
	if req.GetType() != platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		recordType = protoRecordTypeToString(req.GetType())
	}

	values, err := s.service.Resolve(ctx, req.GetFqdn(), recordType)
	if err != nil {
		return nil, s.mapError("Resolve", err)
	}

	// Convert resolved values to Record messages
	records := make([]*platformv1.Record, 0, len(values))
	for _, value := range values {
		record := &platformv1.Record{
			Type: req.GetType(),
		}
		switch req.GetType() {
		case platformv1.RecordType_RECORD_TYPE_A, platformv1.RecordType_RECORD_TYPE_UNSPECIFIED:
			record.Record = &platformv1.Record_A{
				A: &platformv1.ARecord{
					Name:  req.GetFqdn(),
					Value: value,
				},
			}
		case platformv1.RecordType_RECORD_TYPE_AAAA:
			record.Record = &platformv1.Record_Aaaa{
				Aaaa: &platformv1.AAAARecord{
					Name:  req.GetFqdn(),
					Value: value,
				},
			}
		case platformv1.RecordType_RECORD_TYPE_TXT:
			record.Record = &platformv1.Record_Txt{
				Txt: &platformv1.TXTRecord{
					Name:  req.GetFqdn(),
					Value: value,
				},
			}
		case platformv1.RecordType_RECORD_TYPE_CNAME:
			record.Record = &platformv1.Record_Cname{
				Cname: &platformv1.CNAMERecord{
					Name:  req.GetFqdn(),
					Value: value,
				},
			}
		default:
			// For other types, use A record as fallback
			record.Record = &platformv1.Record_A{
				A: &platformv1.ARecord{
					Name:  req.GetFqdn(),
					Value: value,
				},
			}
		}
		records = append(records, record)
	}

	// Check if we are authoritative for this zone
	authoritative := false
	// Extract zone from FQDN and check if we have it
	parts := strings.Split(req.GetFqdn(), ".")
	if len(parts) >= 2 {
		zoneName := strings.Join(parts[len(parts)-2:], ".") + "."
		if _, err := s.service.Zone(ctx, zoneName); err == nil {
			authoritative = true
		}
	}

	return &platformv1.ResolveResponse{
		Records:       records,
		Authoritative: authoritative,
	}, nil
}

// Register registers a new DNS record based on FQDN and IP.
func (s *DNSGRPCService) Register(
	ctx context.Context,
	req *platformv1.RegisterRequest,
) (*platformv1.RegisterResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDNSService{}.Error())
	}

	if req.GetFqdn() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingFQDN{}.Error())
	}

	if req.GetIp() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingIP{}.Error())
	}

	zone, err := s.service.Register(ctx, req.GetFqdn(), req.GetIp())
	if err != nil {
		return nil, s.mapError("Register", err)
	}

	return &platformv1.RegisterResponse{
		Status: dnsSuccessStatus("registration successful"),
		Zone:   entityZoneToProto(zone),
	}, nil
}

// Helper functions

// protoSOAToEntity converts a proto SOARecord to an entity SOARecord.
func protoSOAToEntity(soa *platformv1.SOARecord) entities.SOARecord {
	if soa == nil {
		return entities.SOARecord{}
	}
	return entities.SOARecord{
		Name:       soa.GetName(),
		MName:      soa.GetMname(),
		RName:      soa.GetRname(),
		Serial:     soa.GetSerial(),
		Refresh:    soa.GetRefresh(),
		Retry:      soa.GetRetry(),
		Expire:     soa.GetExpire(),
		MinimumTTL: soa.GetMinimumTtl(),
		TTL:        soa.GetTtl(),
	}
}

// entityZoneToProto converts an entity Zone to a proto Zone.
func entityZoneToProto(zone *entities.Zone) *platformv1.Zone {
	if zone == nil {
		return nil
	}

	protoZone := &platformv1.Zone{
		Id:          zone.ID,
		Name:        zone.Name,
		Ttl:         zone.TTL,
		Description: zone.Description,
		Internal:    zone.Internal,
		Records:     entityRecordSetToProto(&zone.RecordSet),
	}

	return protoZone
}

// entityRecordSetToProto converts an entity RecordSet to a proto RecordSet.
func entityRecordSetToProto(rs *entities.RecordSet) *platformv1.RecordSet {
	if rs == nil {
		return nil
	}

	protoRS := &platformv1.RecordSet{}

	// SOA
	if rs.SOARecord.Name != "" {
		protoRS.Soa = &platformv1.SOARecord{
			Name:       rs.SOARecord.Name,
			Mname:      rs.SOARecord.MName,
			Rname:      rs.SOARecord.RName,
			Serial:     rs.SOARecord.Serial,
			Refresh:    rs.SOARecord.Refresh,
			Retry:      rs.SOARecord.Retry,
			Expire:     rs.SOARecord.Expire,
			MinimumTtl: rs.SOARecord.MinimumTTL,
			Ttl:        rs.SOARecord.TTL,
		}
	}

	// A records
	for _, rec := range rs.ARecords {
		protoRS.ARecords = append(protoRS.ARecords, &platformv1.ARecord{
			Name:  rec.Name,
			Value: rec.Value,
			Ttl:   rec.TTL,
		})
	}

	// AAAA records
	for _, rec := range rs.AAAARecords {
		protoRS.AaaaRecords = append(protoRS.AaaaRecords, &platformv1.AAAARecord{
			Name:  rec.Name,
			Value: rec.Value,
			Ttl:   rec.TTL,
		})
	}

	// CNAME records
	for _, rec := range rs.CNAMERecords {
		protoRS.CnameRecords = append(protoRS.CnameRecords, &platformv1.CNAMERecord{
			Name:  rec.Name,
			Value: rec.Value,
			Ttl:   rec.TTL,
		})
	}

	// MX records
	for _, rec := range rs.MXRecords {
		protoRS.MxRecords = append(protoRS.MxRecords, &platformv1.MXRecord{
			Name:     rec.Name,
			Value:    rec.Value,
			Priority: uint32(rec.Priority),
			Ttl:      rec.TTL,
		})
	}

	// NS records
	for _, rec := range rs.NSRecords {
		protoRS.NsRecords = append(protoRS.NsRecords, &platformv1.NSRecord{
			Name:  rec.Name,
			Value: rec.Value,
			Ttl:   rec.TTL,
		})
	}

	// TXT records
	for _, rec := range rs.TXTRecords {
		protoRS.TxtRecords = append(protoRS.TxtRecords, &platformv1.TXTRecord{
			Name:  rec.Name,
			Value: rec.Value,
			Ttl:   rec.TTL,
		})
	}

	// SRV records
	for _, rec := range rs.SRVRecords {
		protoRS.SrvRecords = append(protoRS.SrvRecords, &platformv1.SRVRecord{
			Name:     rec.Name,
			Target:   rec.Target,
			Port:     uint32(rec.Port),
			Priority: uint32(rec.Priority),
			Weight:   uint32(rec.Weight),
			Ttl:      rec.TTL,
		})
	}

	// CAA records
	for _, rec := range rs.CAARecords {
		protoRS.CaaRecords = append(protoRS.CaaRecords, &platformv1.CAARecord{
			Name:  rec.Name,
			Flags: uint32(rec.Flags),
			Tag:   rec.Tag,
			Value: rec.Value,
			Ttl:   rec.TTL,
		})
	}

	// TLSA records
	for _, rec := range rs.TLSARecords {
		protoRS.TlsaRecords = append(protoRS.TlsaRecords, &platformv1.TLSARecord{
			Name:         rec.Name,
			Usage:        uint32(rec.Usage),
			Selector:     uint32(rec.Selector),
			MatchingType: uint32(rec.MatchingType),
			Data:         rec.Data,
			Ttl:          rec.TTL,
		})
	}

	// DNSKEY records
	for _, rec := range rs.DNSKEYRecords {
		protoRS.DnskeyRecords = append(protoRS.DnskeyRecords, entityDNSKEYToProto(rec))
	}

	// DS records
	for _, rec := range rs.DSRecords {
		protoRS.DsRecords = append(protoRS.DsRecords, entityDSToProto(rec))
	}

	// RRSIG records
	for _, rec := range rs.RRSIGRecords {
		protoRS.RrsigRecords = append(protoRS.RrsigRecords, &platformv1.RRSIGRecord{
			TypeCovered: rec.TypeCovered,
			Algorithm:   uint32(rec.Algorithm),
			Labels:      uint32(rec.Labels),
			OriginalTtl: rec.OriginalTTL,
			Expiration:  rec.Expiration,
			Inception:   rec.Inception,
			KeyTag:      uint32(rec.KeyTag),
			SignerName:  rec.SignerName,
			Signature:   rec.Signature,
		})
	}

	// NSEC records
	for _, rec := range rs.NSECRecords {
		typeBitmap := make([]uint32, len(rec.TypeBitMap))
		for i, v := range rec.TypeBitMap {
			typeBitmap[i] = uint32(v)
		}
		protoRS.NsecRecords = append(protoRS.NsecRecords, &platformv1.NSECRecord{
			Name:       rec.Name,
			NextDomain: rec.NextDomain,
			TypeBitmap: typeBitmap,
			Ttl:        rec.TTL,
		})
	}

	// NSEC3 records
	for _, rec := range rs.NSEC3Records {
		typeBitmap := make([]uint32, len(rec.TypeBitMap))
		for i, v := range rec.TypeBitMap {
			typeBitmap[i] = uint32(v)
		}
		protoRS.Nsec3Records = append(protoRS.Nsec3Records, &platformv1.NSEC3Record{
			Name:       rec.Name,
			Algorithm:  uint32(rec.Algorithm),
			Flags:      uint32(rec.Flags),
			Iterations: uint32(rec.Iterations),
			Salt:       rec.Salt,
			NextHashed: rec.NextHashed,
			TypeBitmap: typeBitmap,
			Ttl:        rec.TTL,
		})
	}

	// NSEC3PARAM records
	for _, rec := range rs.NSEC3PARAMRecords {
		protoRS.Nsec3ParamRecords = append(protoRS.Nsec3ParamRecords, &platformv1.NSEC3PARAMRecord{
			Name:       rec.Name,
			Algorithm:  uint32(rec.Algorithm),
			Flags:      uint32(rec.Flags),
			Iterations: uint32(rec.Iterations),
			Salt:       rec.Salt,
			Ttl:        rec.TTL,
		})
	}

	return protoRS
}

// entityDNSKEYToProto converts an entity DNSKEYRecord to a proto DNSKEYRecord.
func entityDNSKEYToProto(rec *entities.DNSKEYRecord) *platformv1.DNSKEYRecord {
	if rec == nil {
		return nil
	}
	return &platformv1.DNSKEYRecord{
		Name:      rec.Name,
		Flags:     uint32(rec.Flags),
		Protocol:  uint32(rec.Protocol),
		Algorithm: uint32(rec.Algorithm),
		Key:       rec.Key,
		Ttl:       rec.TTL,
	}
}

// entityDSToProto converts an entity DSRecord to a proto DSRecord.
func entityDSToProto(rec *entities.DSRecord) *platformv1.DSRecord {
	if rec == nil {
		return nil
	}
	return &platformv1.DSRecord{
		Name:       rec.Name,
		KeyTag:     uint32(rec.KeyTag),
		Algorithm:  uint32(rec.Algorithm),
		DigestType: uint32(rec.DigestType),
		Digest:     rec.Digest,
		Ttl:        rec.TTL,
	}
}

// entityRecordToProto converts an entity record interface to a proto Record.
func entityRecordToProto(record interface{}) *platformv1.Record {
	if record == nil {
		return nil
	}

	switch r := record.(type) {
	case *entities.ARecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{
					Name:  r.Name,
					Value: r.Value,
					Ttl:   r.TTL,
				},
			},
		}
	case *entities.AAAARecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_AAAA,
			Record: &platformv1.Record_Aaaa{
				Aaaa: &platformv1.AAAARecord{
					Name:  r.Name,
					Value: r.Value,
					Ttl:   r.TTL,
				},
			},
		}
	case *entities.CNAMERecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_CNAME,
			Record: &platformv1.Record_Cname{
				Cname: &platformv1.CNAMERecord{
					Name:  r.Name,
					Value: r.Value,
					Ttl:   r.TTL,
				},
			},
		}
	case *entities.MXRecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_MX,
			Record: &platformv1.Record_Mx{
				Mx: &platformv1.MXRecord{
					Name:     r.Name,
					Value:    r.Value,
					Priority: uint32(r.Priority),
					Ttl:      r.TTL,
				},
			},
		}
	case *entities.NSRecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_NS,
			Record: &platformv1.Record_Ns{
				Ns: &platformv1.NSRecord{
					Name:  r.Name,
					Value: r.Value,
					Ttl:   r.TTL,
				},
			},
		}
	case *entities.TXTRecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_TXT,
			Record: &platformv1.Record_Txt{
				Txt: &platformv1.TXTRecord{
					Name:  r.Name,
					Value: r.Value,
					Ttl:   r.TTL,
				},
			},
		}
	case *entities.SRVRecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_SRV,
			Record: &platformv1.Record_Srv{
				Srv: &platformv1.SRVRecord{
					Name:     r.Name,
					Target:   r.Target,
					Port:     uint32(r.Port),
					Priority: uint32(r.Priority),
					Weight:   uint32(r.Weight),
					Ttl:      r.TTL,
				},
			},
		}
	case *entities.CAARecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_CAA,
			Record: &platformv1.Record_Caa{
				Caa: &platformv1.CAARecord{
					Name:  r.Name,
					Flags: uint32(r.Flags),
					Tag:   r.Tag,
					Value: r.Value,
					Ttl:   r.TTL,
				},
			},
		}
	case *entities.TLSARecord:
		return &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_TLSA,
			Record: &platformv1.Record_Tlsa{
				Tlsa: &platformv1.TLSARecord{
					Name:         r.Name,
					Usage:        uint32(r.Usage),
					Selector:     uint32(r.Selector),
					MatchingType: uint32(r.MatchingType),
					Data:         r.Data,
					Ttl:          r.TTL,
				},
			},
		}
	default:
		return nil
	}
}

// protoRecordTypeToString converts a proto RecordType to a string.
func protoRecordTypeToString(rt platformv1.RecordType) string {
	switch rt {
	case platformv1.RecordType_RECORD_TYPE_A:
		return "A"
	case platformv1.RecordType_RECORD_TYPE_AAAA:
		return "AAAA"
	case platformv1.RecordType_RECORD_TYPE_CNAME:
		return "CNAME"
	case platformv1.RecordType_RECORD_TYPE_MX:
		return "MX"
	case platformv1.RecordType_RECORD_TYPE_NS:
		return "NS"
	case platformv1.RecordType_RECORD_TYPE_TXT:
		return "TXT"
	case platformv1.RecordType_RECORD_TYPE_SRV:
		return "SRV"
	case platformv1.RecordType_RECORD_TYPE_SOA:
		return "SOA"
	case platformv1.RecordType_RECORD_TYPE_CAA:
		return "CAA"
	case platformv1.RecordType_RECORD_TYPE_TLSA:
		return "TLSA"
	case platformv1.RecordType_RECORD_TYPE_DNSKEY:
		return "DNSKEY"
	case platformv1.RecordType_RECORD_TYPE_DS:
		return "DS"
	case platformv1.RecordType_RECORD_TYPE_RRSIG:
		return "RRSIG"
	case platformv1.RecordType_RECORD_TYPE_NSEC:
		return "NSEC"
	case platformv1.RecordType_RECORD_TYPE_NSEC3:
		return "NSEC3"
	case platformv1.RecordType_RECORD_TYPE_NSEC3PARAM:
		return "NSEC3PARAM"
	default:
		return "A"
	}
}

// extractRecordInfo extracts record information from a proto Record.
func extractRecordInfo(record *platformv1.Record) (recordType, name, value string, ttl uint32, err error) {
	if record == nil {
		return "", "", "", 0, ErrMissingRecord{}
	}

	switch r := record.GetRecord().(type) {
	case *platformv1.Record_A:
		if r.A == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "A", r.A.GetName(), r.A.GetValue(), r.A.GetTtl(), nil
	case *platformv1.Record_Aaaa:
		if r.Aaaa == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "AAAA", r.Aaaa.GetName(), r.Aaaa.GetValue(), r.Aaaa.GetTtl(), nil
	case *platformv1.Record_Cname:
		if r.Cname == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "CNAME", r.Cname.GetName(), r.Cname.GetValue(), r.Cname.GetTtl(), nil
	case *platformv1.Record_Mx:
		if r.Mx == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "MX", r.Mx.GetName(), r.Mx.GetValue(), r.Mx.GetTtl(), nil
	case *platformv1.Record_Ns:
		if r.Ns == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "NS", r.Ns.GetName(), r.Ns.GetValue(), r.Ns.GetTtl(), nil
	case *platformv1.Record_Txt:
		if r.Txt == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "TXT", r.Txt.GetName(), r.Txt.GetValue(), r.Txt.GetTtl(), nil
	case *platformv1.Record_Srv:
		if r.Srv == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "SRV", r.Srv.GetName(), r.Srv.GetTarget(), r.Srv.GetTtl(), nil
	case *platformv1.Record_Caa:
		if r.Caa == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "CAA", r.Caa.GetName(), r.Caa.GetValue(), r.Caa.GetTtl(), nil
	case *platformv1.Record_Tlsa:
		if r.Tlsa == nil {
			return "", "", "", 0, ErrMissingRecord{}
		}
		return "TLSA", r.Tlsa.GetName(), r.Tlsa.GetData(), r.Tlsa.GetTtl(), nil
	default:
		return "", "", "", 0, ErrInvalidRecordType{Type: "unknown"}
	}
}

// mapError maps DNS errors to appropriate gRPC status codes.
func (s *DNSGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "dns operation failed", "operation", operation)

	// Check for specific DNS error types
	errMsg := err.Error()
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "does not exist") {
		return status.Errorf(codes.NotFound, "dns operation %s: %s", operation, errMsg)
	}
	if strings.Contains(errMsg, "already exists") || strings.Contains(errMsg, "duplicate") {
		return status.Errorf(codes.AlreadyExists, "dns operation %s: %s", operation, errMsg)
	}
	if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "validation") {
		return status.Errorf(codes.InvalidArgument, "dns operation %s: %s", operation, errMsg)
	}

	// Default to internal error
	return status.Errorf(codes.Internal, "dns operation %s failed: %s", operation, errMsg)
}

// dnsTimestamp returns the current UTC timestamp.
func dnsTimestamp() int64 {
	return time.Now().UTC().Unix()
}

// Ensure DNSGRPCService implements the DNSServiceServer interface.
var _ platformv1.DNSServiceServer = (*DNSGRPCService)(nil)
