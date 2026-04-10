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

package daemon

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// DNSServiceServer implements the gRPC DNSService interface.
// It delegates all operations to the dns.DNSService service layer.
type DNSServiceServer struct {
	platformv1.UnimplementedDNSServiceServer
	service dns.DNSService
	logger  *slog.Logger
}

// NewDNSServiceServer creates a new DNSServiceServer.
func NewDNSServiceServer(service dns.DNSService, logger *slog.Logger) *DNSServiceServer {
	return &DNSServiceServer{
		service: service,
		logger:  logger,
	}
}

// CreateZone creates a new DNS zone.
func (s *DNSServiceServer) CreateZone(ctx context.Context, req *platformv1.CreateZoneRequest) (*platformv1.CreateZoneResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	// Build SOA record
	var soaRecord entities.SOARecord
	if req.GetSoa() != nil {
		soaRecord = entities.SOARecord{
			Name:       req.GetSoa().GetName(),
			MName:      req.GetSoa().GetMname(),
			RName:      req.GetSoa().GetRname(),
			Serial:     req.GetSoa().GetSerial(),
			Refresh:    req.GetSoa().GetRefresh(),
			Retry:      req.GetSoa().GetRetry(),
			Expire:     req.GetSoa().GetExpire(),
			MinimumTTL: req.GetSoa().GetMinimumTtl(),
			TTL:        req.GetSoa().GetTtl(),
		}
	}

	// Build NS records
	var nsRecords []*entities.NSRecord
	for _, ns := range req.GetNsRecords() {
		nsRecords = append(nsRecords, &entities.NSRecord{
			Name:  ns.GetName(),
			Value: ns.GetValue(),
			TTL:   ns.GetTtl(),
		})
	}

	zone := &entities.Zone{
		Name:        req.GetName(),
		TTL:         req.GetTtl(),
		Description: req.GetDescription(),
		Internal:    req.GetInternal(),
		RecordSet: entities.RecordSet{
			SOARecord: soaRecord,
			NSRecords: nsRecords,
		},
	}

	if err := s.service.Save(ctx, zone); err != nil {
		s.logger.Error("failed to create zone", slog.String("zone", req.GetName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.CreateZoneResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "zone created successfully",
		},
		Zone: s.zoneToProto(zone),
	}, nil
}

// GetZone retrieves a DNS zone by name.
func (s *DNSServiceServer) GetZone(ctx context.Context, req *platformv1.GetZoneRequest) (*platformv1.GetZoneResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetName())
	if err != nil {
		s.logger.Error("failed to get zone", slog.String("zone", req.GetName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &platformv1.GetZoneResponse{
		Zone: s.zoneToProto(zone),
	}, nil
}

// UpdateZone updates an existing DNS zone.
func (s *DNSServiceServer) UpdateZone(ctx context.Context, req *platformv1.UpdateZoneRequest) (*platformv1.UpdateZoneResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetName())
	if err != nil {
		s.logger.Error("failed to get zone for update", slog.String("zone", req.GetName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	if req.GetTtl() > 0 {
		zone.TTL = req.GetTtl()
	}
	if req.GetDescription() != "" {
		zone.Description = req.GetDescription()
	}

	if err := s.service.Save(ctx, zone); err != nil {
		s.logger.Error("failed to update zone", slog.String("zone", req.GetName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.UpdateZoneResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "zone updated successfully",
		},
		Zone: s.zoneToProto(zone),
	}, nil
}

// DeleteZone deletes a DNS zone.
func (s *DNSServiceServer) DeleteZone(ctx context.Context, req *platformv1.DeleteZoneRequest) (*platformv1.DeleteZoneResponse, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetName())
	if err != nil {
		s.logger.Error("failed to get zone for delete", slog.String("zone", req.GetName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	if err := s.service.Delete(ctx, zone); err != nil {
		s.logger.Error("failed to delete zone", slog.String("zone", req.GetName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.DeleteZoneResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "zone deleted successfully",
		},
	}, nil
}

// ListZones lists all DNS zones.
func (s *DNSServiceServer) ListZones(ctx context.Context, req *platformv1.ListZonesRequest) (*platformv1.ListZonesResponse, error) {
	zones, err := s.service.ListZones(ctx)
	if err != nil {
		s.logger.Error("failed to list zones", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	var protoZones []*platformv1.Zone
	for _, zone := range zones {
		// Filter by internal/public if requested
		if req.GetInternalOnly() && !zone.Internal {
			continue
		}
		if req.GetPublicOnly() && zone.Internal {
			continue
		}
		protoZones = append(protoZones, s.zoneToProto(zone))
	}

	return &platformv1.ListZonesResponse{
		Zones: protoZones,
	}, nil
}

// AddRecord adds a record to a zone.
func (s *DNSServiceServer) AddRecord(ctx context.Context, req *platformv1.AddRecordRequest) (*platformv1.AddRecordResponse, error) {
	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}
	if req.GetRecord() == nil {
		return nil, status.Error(codes.InvalidArgument, "record is required")
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		s.logger.Error("failed to get zone for add record", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	// Add the record based on type
	if err := s.addRecordToZone(zone, req.GetRecord()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.service.Save(ctx, zone); err != nil {
		s.logger.Error("failed to save zone after add record", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.AddRecordResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "record added successfully",
		},
		Zone: s.zoneToProto(zone),
	}, nil
}

// DeleteRecord deletes a record from a zone.
func (s *DNSServiceServer) DeleteRecord(ctx context.Context, req *platformv1.DeleteRecordRequest) (*platformv1.DeleteRecordResponse, error) {
	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "record name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		s.logger.Error("failed to get zone for delete record", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	// Delete record based on type
	s.deleteRecordFromZone(zone, req.GetType(), req.GetName())

	if err := s.service.Save(ctx, zone); err != nil {
		s.logger.Error("failed to save zone after delete record", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.DeleteRecordResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "record deleted successfully",
		},
		Zone: s.zoneToProto(zone),
	}, nil
}

// UpdateRecord updates a record in a zone.
func (s *DNSServiceServer) UpdateRecord(ctx context.Context, req *platformv1.UpdateRecordRequest) (*platformv1.UpdateRecordResponse, error) {
	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}
	if req.GetOldRecord() == nil || req.GetNewRecord() == nil {
		return nil, status.Error(codes.InvalidArgument, "old and new records are required")
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		s.logger.Error("failed to get zone for update record", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	// Delete old record
	s.deleteRecordFromZone(zone, req.GetOldRecord().GetType(), s.getRecordName(req.GetOldRecord()))

	// Add new record
	if err := s.addRecordToZone(zone, req.GetNewRecord()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.service.Save(ctx, zone); err != nil {
		s.logger.Error("failed to save zone after update record", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.UpdateRecordResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "record updated successfully",
		},
		Zone: s.zoneToProto(zone),
	}, nil
}

// ListRecords lists records in a zone.
func (s *DNSServiceServer) ListRecords(ctx context.Context, req *platformv1.ListRecordsRequest) (*platformv1.ListRecordsResponse, error) {
	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		s.logger.Error("failed to get zone for list records", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	records := s.extractRecords(zone, req.GetType())

	return &platformv1.ListRecordsResponse{
		Records: records,
	}, nil
}

// SignZone signs a zone with DNSSEC.
func (s *DNSServiceServer) SignZone(ctx context.Context, req *platformv1.SignZoneRequest) (*platformv1.SignZoneResponse, error) {
	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		s.logger.Error("failed to get zone for signing", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	if err := s.service.SignZone(zone); err != nil {
		s.logger.Error("failed to sign zone", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := s.service.Save(ctx, zone); err != nil {
		s.logger.Error("failed to save signed zone", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.SignZoneResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "zone signed successfully",
		},
		Zone: s.zoneToProto(zone),
	}, nil
}

// GetDNSSECStatus returns the DNSSEC status for a zone.
func (s *DNSServiceServer) GetDNSSECStatus(ctx context.Context, req *platformv1.GetDNSSECStatusRequest) (*platformv1.GetDNSSECStatusResponse, error) {
	if req.GetZoneName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}

	zone, err := s.service.Zone(ctx, req.GetZoneName())
	if err != nil {
		s.logger.Error("failed to get zone for DNSSEC status", slog.String("zone", req.GetZoneName()), slog.String("error", err.Error()))
		return nil, status.Error(codes.NotFound, err.Error())
	}

	dnssecStatus := &platformv1.DNSSECStatus{
		Enabled:    s.service.IsDNSSECEnabled(),
		ZoneSigned: len(zone.RecordSet.DNSKEYRecords) > 0,
	}

	// Add DNSKEY records
	for _, key := range zone.RecordSet.DNSKEYRecords {
		dnssecStatus.Keys = append(dnssecStatus.Keys, &platformv1.DNSKEYRecord{
			Name:      key.Name,
			Flags:     uint32(key.Flags),
			Protocol:  uint32(key.Protocol),
			Algorithm: uint32(key.Algorithm),
			Key:       key.Key,
			Ttl:       key.TTL,
		})
	}

	// Add DS records
	for _, ds := range zone.RecordSet.DSRecords {
		dnssecStatus.DsRecords = append(dnssecStatus.DsRecords, &platformv1.DSRecord{
			Name:       ds.Name,
			KeyTag:     uint32(ds.KeyTag),
			Algorithm:  uint32(ds.Algorithm),
			DigestType: uint32(ds.DigestType),
			Digest:     ds.Digest,
			Ttl:        ds.TTL,
		})
	}

	return &platformv1.GetDNSSECStatusResponse{
		Status: dnssecStatus,
	}, nil
}

// Resolve resolves a DNS query.
func (s *DNSServiceServer) Resolve(ctx context.Context, req *platformv1.ResolveRequest) (*platformv1.ResolveResponse, error) {
	if req.GetFqdn() == "" {
		return nil, status.Error(codes.InvalidArgument, "fqdn is required")
	}

	// For now, we only support resolving from zones we manage
	// This could be extended to use the DNS resolver
	zone, err := s.service.Zone(ctx, req.GetFqdn())
	if err != nil {
		// Zone not found, return empty response
		return &platformv1.ResolveResponse{
			Records:       nil,
			Authoritative: false,
		}, nil
	}

	records := s.extractRecords(zone, req.GetType())

	return &platformv1.ResolveResponse{
		Records:       records,
		Authoritative: true,
	}, nil
}

// Register registers a new DNS record or zone.
func (s *DNSServiceServer) Register(ctx context.Context, req *platformv1.RegisterRequest) (*platformv1.RegisterResponse, error) {
	if req.GetFqdn() == "" {
		return nil, status.Error(codes.InvalidArgument, "fqdn is required")
	}
	if req.GetIp() == "" {
		return nil, status.Error(codes.InvalidArgument, "ip is required")
	}

	zone, err := s.service.Register(ctx, req.GetFqdn(), req.GetIp())
	if err != nil {
		s.logger.Error("failed to register", slog.String("fqdn", req.GetFqdn()), slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, err.Error())
	}

	var protoZone *platformv1.Zone
	if zone != nil {
		protoZone = s.zoneToProto(zone)
	}

	return &platformv1.RegisterResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "registration successful",
		},
		Zone: protoZone,
	}, nil
}

// Helper functions

func (s *DNSServiceServer) zoneToProto(zone *entities.Zone) *platformv1.Zone {
	if zone == nil {
		return nil
	}

	protoZone := &platformv1.Zone{
		Id:          zone.ID,
		Name:        zone.Name,
		Ttl:         zone.TTL,
		Description: zone.Description,
		Internal:    zone.Internal,
		Records:     s.recordSetToProto(&zone.RecordSet),
	}

	return protoZone
}

func (s *DNSServiceServer) recordSetToProto(rs *entities.RecordSet) *platformv1.RecordSet {
	if rs == nil {
		return nil
	}

	protoRS := &platformv1.RecordSet{
		Soa: &platformv1.SOARecord{
			Name:       rs.SOARecord.Name,
			Mname:      rs.SOARecord.MName,
			Rname:      rs.SOARecord.RName,
			Serial:     rs.SOARecord.Serial,
			Refresh:    rs.SOARecord.Refresh,
			Retry:      rs.SOARecord.Retry,
			Expire:     rs.SOARecord.Expire,
			MinimumTtl: rs.SOARecord.MinimumTTL,
			Ttl:        rs.SOARecord.TTL,
		},
	}

	for _, r := range rs.ARecords {
		protoRS.ARecords = append(protoRS.ARecords, &platformv1.ARecord{
			Name:  r.Name,
			Value: r.Value,
			Ttl:   r.TTL,
		})
	}

	for _, r := range rs.AAAARecords {
		protoRS.AaaaRecords = append(protoRS.AaaaRecords, &platformv1.AAAARecord{
			Name:  r.Name,
			Value: r.Value,
			Ttl:   r.TTL,
		})
	}

	for _, r := range rs.CNAMERecords {
		protoRS.CnameRecords = append(protoRS.CnameRecords, &platformv1.CNAMERecord{
			Name:  r.Name,
			Value: r.Value,
			Ttl:   r.TTL,
		})
	}

	for _, r := range rs.MXRecords {
		protoRS.MxRecords = append(protoRS.MxRecords, &platformv1.MXRecord{
			Name:     r.Name,
			Value:    r.Value,
			Priority: uint32(r.Priority),
			Ttl:      r.TTL,
		})
	}

	for _, r := range rs.NSRecords {
		protoRS.NsRecords = append(protoRS.NsRecords, &platformv1.NSRecord{
			Name:  r.Name,
			Value: r.Value,
			Ttl:   r.TTL,
		})
	}

	for _, r := range rs.TXTRecords {
		protoRS.TxtRecords = append(protoRS.TxtRecords, &platformv1.TXTRecord{
			Name:  r.Name,
			Value: r.Value,
			Ttl:   r.TTL,
		})
	}

	for _, r := range rs.SRVRecords {
		protoRS.SrvRecords = append(protoRS.SrvRecords, &platformv1.SRVRecord{
			Name:     r.Name,
			Target:   r.Target,
			Port:     uint32(r.Port),
			Priority: uint32(r.Priority),
			Weight:   uint32(r.Weight),
			Ttl:      r.TTL,
		})
	}

	for _, r := range rs.CAARecords {
		protoRS.CaaRecords = append(protoRS.CaaRecords, &platformv1.CAARecord{
			Name:  r.Name,
			Flags: uint32(r.Flags),
			Tag:   r.Tag,
			Value: r.Value,
			Ttl:   r.TTL,
		})
	}

	for _, r := range rs.TLSARecords {
		protoRS.TlsaRecords = append(protoRS.TlsaRecords, &platformv1.TLSARecord{
			Name:         r.Name,
			Usage:        uint32(r.Usage),
			Selector:     uint32(r.Selector),
			MatchingType: uint32(r.MatchingType),
			Data:         r.Data,
			Ttl:          r.TTL,
		})
	}

	for _, r := range rs.DNSKEYRecords {
		protoRS.DnskeyRecords = append(protoRS.DnskeyRecords, &platformv1.DNSKEYRecord{
			Name:      r.Name,
			Flags:     uint32(r.Flags),
			Protocol:  uint32(r.Protocol),
			Algorithm: uint32(r.Algorithm),
			Key:       r.Key,
			Ttl:       r.TTL,
		})
	}

	for _, r := range rs.DSRecords {
		protoRS.DsRecords = append(protoRS.DsRecords, &platformv1.DSRecord{
			Name:       r.Name,
			KeyTag:     uint32(r.KeyTag),
			Algorithm:  uint32(r.Algorithm),
			DigestType: uint32(r.DigestType),
			Digest:     r.Digest,
			Ttl:        r.TTL,
		})
	}

	for _, r := range rs.RRSIGRecords {
		protoRS.RrsigRecords = append(protoRS.RrsigRecords, &platformv1.RRSIGRecord{
			TypeCovered: r.TypeCovered,
			Algorithm:   uint32(r.Algorithm),
			Labels:      uint32(r.Labels),
			OriginalTtl: r.OriginalTTL,
			Expiration:  r.Expiration,
			Inception:   r.Inception,
			KeyTag:      uint32(r.KeyTag),
			SignerName:  r.SignerName,
			Signature:   r.Signature,
		})
	}

	return protoRS
}

func (s *DNSServiceServer) addRecordToZone(zone *entities.Zone, record *platformv1.Record) error {
	switch record.GetType() {
	case platformv1.RecordType_RECORD_TYPE_A:
		if a := record.GetA(); a != nil {
			zone.AddARecord(&entities.ARecord{
				Name:  a.GetName(),
				Value: a.GetValue(),
				TTL:   a.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_AAAA:
		if aaaa := record.GetAaaa(); aaaa != nil {
			zone.AddAAAARecord(&entities.AAAARecord{
				Name:  aaaa.GetName(),
				Value: aaaa.GetValue(),
				TTL:   aaaa.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_CNAME:
		if cname := record.GetCname(); cname != nil {
			zone.AddCNAMERecord(&entities.CNAMERecord{
				Name:  cname.GetName(),
				Value: cname.GetValue(),
				TTL:   cname.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_MX:
		if mx := record.GetMx(); mx != nil {
			zone.AddMXRecord(&entities.MXRecord{
				Name:     mx.GetName(),
				Value:    mx.GetValue(),
				Priority: uint16(mx.GetPriority()),
				TTL:      mx.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_NS:
		if ns := record.GetNs(); ns != nil {
			zone.AddNSRecord(&entities.NSRecord{
				Name:  ns.GetName(),
				Value: ns.GetValue(),
				TTL:   ns.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_TXT:
		if txt := record.GetTxt(); txt != nil {
			zone.AddTXTRecord(&entities.TXTRecord{
				Name:  txt.GetName(),
				Value: txt.GetValue(),
				TTL:   txt.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_SRV:
		if srv := record.GetSrv(); srv != nil {
			zone.AddSRVRecord(&entities.SRVRecord{
				Name:     srv.GetName(),
				Target:   srv.GetTarget(),
				Port:     uint16(srv.GetPort()),
				Priority: uint16(srv.GetPriority()),
				Weight:   uint16(srv.GetWeight()),
				TTL:      srv.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_CAA:
		if caa := record.GetCaa(); caa != nil {
			zone.AddCAARecord(&entities.CAARecord{
				Name:  caa.GetName(),
				Flags: uint8(caa.GetFlags()),
				Tag:   caa.GetTag(),
				Value: caa.GetValue(),
				TTL:   caa.GetTtl(),
			})
		}
	case platformv1.RecordType_RECORD_TYPE_TLSA:
		if tlsa := record.GetTlsa(); tlsa != nil {
			zone.AddTLSARecord(&entities.TLSARecord{
				Name:         tlsa.GetName(),
				Usage:        uint8(tlsa.GetUsage()),
				Selector:     uint8(tlsa.GetSelector()),
				MatchingType: uint8(tlsa.GetMatchingType()),
				Data:         tlsa.GetData(),
				TTL:          tlsa.GetTtl(),
			})
		}
	default:
		return ErrUnsupportedRecordType{}
	}
	return nil
}

func (s *DNSServiceServer) deleteRecordFromZone(zone *entities.Zone, recordType platformv1.RecordType, name string) {
	switch recordType {
	case platformv1.RecordType_RECORD_TYPE_A:
		zone.RemoveARecord(name)
	case platformv1.RecordType_RECORD_TYPE_AAAA:
		zone.RemoveAAAARecord(name)
	case platformv1.RecordType_RECORD_TYPE_CNAME:
		zone.RemoveCNAMERecord(name)
	case platformv1.RecordType_RECORD_TYPE_MX:
		zone.RemoveMXRecord(name)
	case platformv1.RecordType_RECORD_TYPE_NS:
		zone.RemoveNSRecord(name)
	case platformv1.RecordType_RECORD_TYPE_TXT:
		zone.RemoveTXTRecord(name)
	case platformv1.RecordType_RECORD_TYPE_SRV:
		zone.RemoveSRVRecord(name)
	case platformv1.RecordType_RECORD_TYPE_CAA:
		zone.RemoveCAARecord(name)
	case platformv1.RecordType_RECORD_TYPE_TLSA:
		zone.RemoveTLSARecord(name)
	}
}

func (s *DNSServiceServer) getRecordName(record *platformv1.Record) string {
	switch record.GetType() {
	case platformv1.RecordType_RECORD_TYPE_A:
		if a := record.GetA(); a != nil {
			return a.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_AAAA:
		if aaaa := record.GetAaaa(); aaaa != nil {
			return aaaa.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_CNAME:
		if cname := record.GetCname(); cname != nil {
			return cname.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_MX:
		if mx := record.GetMx(); mx != nil {
			return mx.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_NS:
		if ns := record.GetNs(); ns != nil {
			return ns.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_TXT:
		if txt := record.GetTxt(); txt != nil {
			return txt.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_SRV:
		if srv := record.GetSrv(); srv != nil {
			return srv.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_CAA:
		if caa := record.GetCaa(); caa != nil {
			return caa.GetName()
		}
	case platformv1.RecordType_RECORD_TYPE_TLSA:
		if tlsa := record.GetTlsa(); tlsa != nil {
			return tlsa.GetName()
		}
	}
	return ""
}

func (s *DNSServiceServer) extractRecords(zone *entities.Zone, recordType platformv1.RecordType) []*platformv1.Record {
	var records []*platformv1.Record

	// If unspecified, return all record types
	if recordType == platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		for _, r := range zone.RecordSet.ARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.AAAARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.CNAMERecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.MXRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: r.Name, Value: r.Value, Priority: uint32(r.Priority), Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.NSRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.TXTRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.SRVRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: r.Name, Target: r.Target, Port: uint32(r.Port), Priority: uint32(r.Priority), Weight: uint32(r.Weight), Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.CAARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: r.Name, Flags: uint32(r.Flags), Tag: r.Tag, Value: r.Value, Ttl: r.TTL}},
			})
		}
		for _, r := range zone.RecordSet.TLSARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: r.Name, Usage: uint32(r.Usage), Selector: uint32(r.Selector), MatchingType: uint32(r.MatchingType), Data: r.Data, Ttl: r.TTL}},
			})
		}
		return records
	}

	// Filter by specific type
	switch recordType {
	case platformv1.RecordType_RECORD_TYPE_A:
		for _, r := range zone.RecordSet.ARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_AAAA:
		for _, r := range zone.RecordSet.AAAARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_CNAME:
		for _, r := range zone.RecordSet.CNAMERecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_MX:
		for _, r := range zone.RecordSet.MXRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: r.Name, Value: r.Value, Priority: uint32(r.Priority), Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_NS:
		for _, r := range zone.RecordSet.NSRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_TXT:
		for _, r := range zone.RecordSet.TXTRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: r.Name, Value: r.Value, Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_SRV:
		for _, r := range zone.RecordSet.SRVRecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: r.Name, Target: r.Target, Port: uint32(r.Port), Priority: uint32(r.Priority), Weight: uint32(r.Weight), Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_CAA:
		for _, r := range zone.RecordSet.CAARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: r.Name, Flags: uint32(r.Flags), Tag: r.Tag, Value: r.Value, Ttl: r.TTL}},
			})
		}
	case platformv1.RecordType_RECORD_TYPE_TLSA:
		for _, r := range zone.RecordSet.TLSARecords {
			records = append(records, &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: r.Name, Usage: uint32(r.Usage), Selector: uint32(r.Selector), MatchingType: uint32(r.MatchingType), Data: r.Data, Ttl: r.TTL}},
			})
		}
	}

	return records
}
