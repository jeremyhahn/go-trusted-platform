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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// DNS QUIC wire contract (SDK-mapped operations)
// =============================================================================
//
// The canonical QUIC wire contract for the SDK-mapped DNS operations is the
// platform.v1 protobuf request/response messages themselves. The SDK QUIC
// transport adapter (sdk/go/transport/quic) hands the generated platform.v1
// request struct straight to the wire — the msgpack payload codec keys on
// exact Go field names — so the daemon MUST decode the payload into the SAME
// platform.v1 message the SDK sent (or a field-name-identical mirror) and
// encode the platform.v1 response the SDK expects. Decoding into a flat local
// struct whose Go field names differ from the pb Go field names silently
// drops every field.
//
// Each of the seven SDK-mapped operations below delegates to the shared
// *DNSServiceServer (the same business path the gRPC transport uses), so the
// typed dns error -> gRPC status mapping is reused by construction; this file
// only translates the resulting gRPC codes to QUIC status bytes.
//
// ONEOF HANDLING. The platform.v1 Record message carries a protobuf oneof
// (the interface-typed `Record` field). The msgpack codec PANICS decoding an
// interface-typed field, so any message that transports a Record cannot be
// decoded into the raw pb struct. Those messages use FLAT MIRROR structs whose
// field names match the pb wire byte-for-byte:
//
//   - AddRecord REQUEST carries a Record -> dnsAddRecordRequestWire decodes it.
//   - ListRecords / Resolve RESPONSES carry []Record -> the daemon encodes the
//     mirror response (dnsListRecordsResponseWire / dnsResolveResponseWire) so
//     the SDK can decode it without hitting the oneof panic (see the symmetric
//     decoders in sdk/go/transport/quic/dns.go).
//
// The empirically-verified wire shape of a Record is:
//
//	{"Type": <enum int>, "Record": {"<Wrapper>": {<fields>}}}
//
// where <Wrapper> is the Go field name of the generated oneof wrapper (A,
// Aaaa, Cname, Mx, Ns, Txt, Srv, Caa, Tlsa). The mirror mirrors that nesting:
// dnsRecordWire.Record is a *dnsRecordOneofWire whose one non-nil pointer
// selects the arm.

// rebuildDNSGRPC rebuilds the shared *DNSServiceServer the SDK-mapped DNS QUIC
// handlers delegate to. The QUIC handler stores the DNS service under the
// narrow local DNSService interface; the gRPC service needs the full
// dns.DNSService surface (Save/Delete/Register/SignZone/...). The concrete
// platform DNS service (*dns.Service) implements the full interface, so the
// assertion succeeds in production. When it does not (e.g. a partial test
// double), dnsGRPC stays nil and the delegated handlers report the service as
// unavailable.
func (h *QUICServiceHandler) rebuildDNSGRPC() {
	if full := fullDNSService(h.dnsService); full != nil {
		h.dnsGRPC = NewDNSServiceServer(full, h.logger.Slog())
	} else {
		h.dnsGRPC = nil
	}
}

// fullDNSService returns the full dns.DNSService behind the narrow DNSService
// the daemon config carries, or nil when svc is nil or does not implement it.
// The gRPC/Unix servicer and the QUIC delegate both resolve the backend
// through it, so every transport reaches the same instance.
func fullDNSService(svc DNSService) dns.DNSService {
	full, ok := svc.(dns.DNSService)
	if !ok {
		return nil
	}
	return full
}

// =============================================================================
// Error mapping
// =============================================================================

// dnsGRPCCodeToQUICStatus maps the gRPC status codes produced by the shared
// DNSServiceServer to QUIC status bytes.
var dnsGRPCCodeToQUICStatus = map[codes.Code]byte{
	codes.InvalidArgument:    quicwire.StatusInvalidArgument,
	codes.Unauthenticated:    quicwire.StatusUnauthorized,
	codes.PermissionDenied:   quicwire.StatusPermissionDenied,
	codes.NotFound:           quicwire.StatusNotFound,
	codes.AlreadyExists:      quicwire.StatusAlreadyExists,
	codes.FailedPrecondition: quicwire.StatusInvalidRequest,
	codes.Unavailable:        quicwire.StatusUnavailable,
	codes.Internal:           quicwire.StatusInternalError,
}

// dnsErrorToQUICResponse converts a gRPC status error from the shared
// DNSServiceServer into a QUIC error response, preserving the status-code
// semantics established by the gRPC service. Unknown codes map to
// StatusInternalError.
func (h *QUICServiceHandler) dnsErrorToQUICResponse(op string, err error) *quicwire.Response {
	quicStatus := quicwire.StatusInternalError
	if mapped, ok := dnsGRPCCodeToQUICStatus[status.Code(err)]; ok {
		quicStatus = mapped
	}
	return h.errorResponse(quicStatus, ErrQUICOperationFailed{Op: op, Cause: err})
}

// encodeDNSResponse encodes v (a platform.v1 pb response or a DNS mirror wire
// struct) as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeDNSResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Mirror wire types for the Record oneof
// =============================================================================

// dnsSimpleRecordWire mirrors the {name, value, ttl} record messages
// (ARecord, AAAARecord, CNAMERecord, NSRecord, TXTRecord). The Go field names
// match the pb messages exactly, which IS the msgpack wire contract.
type dnsSimpleRecordWire struct {
	Name  string `codec:"Name"`
	Value string `codec:"Value"`
	Ttl   uint32 `codec:"Ttl"`
}

// dnsMXRecordWire mirrors platformv1.MXRecord.
type dnsMXRecordWire struct {
	Name     string `codec:"Name"`
	Value    string `codec:"Value"`
	Priority uint32 `codec:"Priority"`
	Ttl      uint32 `codec:"Ttl"`
}

// dnsSRVRecordWire mirrors platformv1.SRVRecord.
type dnsSRVRecordWire struct {
	Name     string `codec:"Name"`
	Target   string `codec:"Target"`
	Port     uint32 `codec:"Port"`
	Priority uint32 `codec:"Priority"`
	Weight   uint32 `codec:"Weight"`
	Ttl      uint32 `codec:"Ttl"`
}

// dnsCAARecordWire mirrors platformv1.CAARecord.
type dnsCAARecordWire struct {
	Name  string `codec:"Name"`
	Flags uint32 `codec:"Flags"`
	Tag   string `codec:"Tag"`
	Value string `codec:"Value"`
	Ttl   uint32 `codec:"Ttl"`
}

// dnsTLSARecordWire mirrors platformv1.TLSARecord.
type dnsTLSARecordWire struct {
	Name         string `codec:"Name"`
	Usage        uint32 `codec:"Usage"`
	Selector     uint32 `codec:"Selector"`
	MatchingType uint32 `codec:"MatchingType"`
	Data         string `codec:"Data"`
	Ttl          uint32 `codec:"Ttl"`
}

// dnsRecordOneofWire mirrors the generated Record oneof wrapper set. Exactly
// one pointer is non-nil; its Go field name (A, Aaaa, ...) matches the wrapper
// field name the codec emits for the pb oneof interface value.
type dnsRecordOneofWire struct {
	A     *dnsSimpleRecordWire `codec:"A"`
	Aaaa  *dnsSimpleRecordWire `codec:"Aaaa"`
	Cname *dnsSimpleRecordWire `codec:"Cname"`
	Mx    *dnsMXRecordWire     `codec:"Mx"`
	Ns    *dnsSimpleRecordWire `codec:"Ns"`
	Txt   *dnsSimpleRecordWire `codec:"Txt"`
	Srv   *dnsSRVRecordWire    `codec:"Srv"`
	Caa   *dnsCAARecordWire    `codec:"Caa"`
	Tlsa  *dnsTLSARecordWire   `codec:"Tlsa"`
}

// dnsRecordWire mirrors platformv1.Record. Type carries the RecordType enum
// value; Record nests the oneof arm exactly as the codec serializes the pb
// interface field (a map keyed by the wrapper Go field name).
type dnsRecordWire struct {
	Type   int32               `codec:"Type"`
	Record *dnsRecordOneofWire `codec:"Record"`
}

// toProto rebuilds a platformv1.Record from the mirror. It is the inverse of
// recordToWire and never panics: it constructs the concrete oneof wrapper for
// whichever arm pointer is non-nil.
func (w *dnsRecordWire) toProto() *platformv1.Record {
	if w == nil {
		return nil
	}
	rec := &platformv1.Record{Type: platformv1.RecordType(w.Type)}
	o := w.Record
	if o == nil {
		return rec
	}
	switch {
	case o.A != nil:
		rec.Record = &platformv1.Record_A{A: &platformv1.ARecord{Name: o.A.Name, Value: o.A.Value, Ttl: o.A.Ttl}}
	case o.Aaaa != nil:
		rec.Record = &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: o.Aaaa.Name, Value: o.Aaaa.Value, Ttl: o.Aaaa.Ttl}}
	case o.Cname != nil:
		rec.Record = &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: o.Cname.Name, Value: o.Cname.Value, Ttl: o.Cname.Ttl}}
	case o.Mx != nil:
		rec.Record = &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: o.Mx.Name, Value: o.Mx.Value, Priority: o.Mx.Priority, Ttl: o.Mx.Ttl}}
	case o.Ns != nil:
		rec.Record = &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: o.Ns.Name, Value: o.Ns.Value, Ttl: o.Ns.Ttl}}
	case o.Txt != nil:
		rec.Record = &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: o.Txt.Name, Value: o.Txt.Value, Ttl: o.Txt.Ttl}}
	case o.Srv != nil:
		rec.Record = &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: o.Srv.Name, Target: o.Srv.Target, Port: o.Srv.Port, Priority: o.Srv.Priority, Weight: o.Srv.Weight, Ttl: o.Srv.Ttl}}
	case o.Caa != nil:
		rec.Record = &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: o.Caa.Name, Flags: o.Caa.Flags, Tag: o.Caa.Tag, Value: o.Caa.Value, Ttl: o.Caa.Ttl}}
	case o.Tlsa != nil:
		rec.Record = &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: o.Tlsa.Name, Usage: o.Tlsa.Usage, Selector: o.Tlsa.Selector, MatchingType: o.Tlsa.MatchingType, Data: o.Tlsa.Data, Ttl: o.Tlsa.Ttl}}
	}
	return rec
}

// recordToWire flattens a platformv1.Record onto the mirror for encoding. It
// is the inverse of dnsRecordWire.toProto.
func recordToWire(r *platformv1.Record) *dnsRecordWire {
	if r == nil {
		return nil
	}
	w := &dnsRecordWire{Type: int32(r.GetType())}
	switch rec := r.GetRecord().(type) {
	case *platformv1.Record_A:
		w.Record = &dnsRecordOneofWire{A: &dnsSimpleRecordWire{Name: rec.A.GetName(), Value: rec.A.GetValue(), Ttl: rec.A.GetTtl()}}
	case *platformv1.Record_Aaaa:
		w.Record = &dnsRecordOneofWire{Aaaa: &dnsSimpleRecordWire{Name: rec.Aaaa.GetName(), Value: rec.Aaaa.GetValue(), Ttl: rec.Aaaa.GetTtl()}}
	case *platformv1.Record_Cname:
		w.Record = &dnsRecordOneofWire{Cname: &dnsSimpleRecordWire{Name: rec.Cname.GetName(), Value: rec.Cname.GetValue(), Ttl: rec.Cname.GetTtl()}}
	case *platformv1.Record_Mx:
		w.Record = &dnsRecordOneofWire{Mx: &dnsMXRecordWire{Name: rec.Mx.GetName(), Value: rec.Mx.GetValue(), Priority: rec.Mx.GetPriority(), Ttl: rec.Mx.GetTtl()}}
	case *platformv1.Record_Ns:
		w.Record = &dnsRecordOneofWire{Ns: &dnsSimpleRecordWire{Name: rec.Ns.GetName(), Value: rec.Ns.GetValue(), Ttl: rec.Ns.GetTtl()}}
	case *platformv1.Record_Txt:
		w.Record = &dnsRecordOneofWire{Txt: &dnsSimpleRecordWire{Name: rec.Txt.GetName(), Value: rec.Txt.GetValue(), Ttl: rec.Txt.GetTtl()}}
	case *platformv1.Record_Srv:
		w.Record = &dnsRecordOneofWire{Srv: &dnsSRVRecordWire{Name: rec.Srv.GetName(), Target: rec.Srv.GetTarget(), Port: rec.Srv.GetPort(), Priority: rec.Srv.GetPriority(), Weight: rec.Srv.GetWeight(), Ttl: rec.Srv.GetTtl()}}
	case *platformv1.Record_Caa:
		w.Record = &dnsRecordOneofWire{Caa: &dnsCAARecordWire{Name: rec.Caa.GetName(), Flags: rec.Caa.GetFlags(), Tag: rec.Caa.GetTag(), Value: rec.Caa.GetValue(), Ttl: rec.Caa.GetTtl()}}
	case *platformv1.Record_Tlsa:
		w.Record = &dnsRecordOneofWire{Tlsa: &dnsTLSARecordWire{Name: rec.Tlsa.GetName(), Usage: rec.Tlsa.GetUsage(), Selector: rec.Tlsa.GetSelector(), MatchingType: rec.Tlsa.GetMatchingType(), Data: rec.Tlsa.GetData(), Ttl: rec.Tlsa.GetTtl()}}
	}
	return w
}

// =============================================================================
// Mirror request / response messages that transport a Record
// =============================================================================

// dnsAddRecordRequestWire mirrors platformv1.AddRecordRequest. ZoneName and
// Record match the pb Go field names; Record is a mirror because AddRecord
// carries the oneof-bearing Record message.
type dnsAddRecordRequestWire struct {
	ZoneName string         `codec:"ZoneName"`
	Record   *dnsRecordWire `codec:"Record"`
}

// dnsListRecordsResponseWire mirrors platformv1.ListRecordsResponse. Records
// carries the flattened Record mirrors so the response round-trips through the
// codec without hitting the oneof panic.
type dnsListRecordsResponseWire struct {
	Records []*dnsRecordWire `codec:"Records"`
}

// dnsResolveResponseWire mirrors platformv1.ResolveResponse.
type dnsResolveResponseWire struct {
	Records       []*dnsRecordWire `codec:"Records"`
	Authoritative bool             `codec:"Authoritative"`
}

// dnsListRecordsResponseFromProto flattens a pb ListRecordsResponse onto the
// mirror.
func dnsListRecordsResponseFromProto(pb *platformv1.ListRecordsResponse) *dnsListRecordsResponseWire {
	out := &dnsListRecordsResponseWire{}
	for _, r := range pb.GetRecords() {
		out.Records = append(out.Records, recordToWire(r))
	}
	return out
}

// dnsResolveResponseFromProto flattens a pb ResolveResponse onto the mirror.
func dnsResolveResponseFromProto(pb *platformv1.ResolveResponse) *dnsResolveResponseWire {
	out := &dnsResolveResponseWire{Authoritative: pb.GetAuthoritative()}
	for _, r := range pb.GetRecords() {
		out.Records = append(out.Records, recordToWire(r))
	}
	return out
}

// =============================================================================
// Delegated handlers (SDK-mapped operations)
// =============================================================================

// handleDNSAddRecord decodes the mirror AddRecord request (the pb Record oneof
// cannot decode directly), delegates to the shared DNSServiceServer, and
// encodes the pb response (AddRecordResponse carries a Zone with no oneof, so
// it round-trips as raw pb).
func (h *QUICServiceHandler) handleDNSAddRecord(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var wire dnsAddRecordRequestWire
	if err := quicwire.DecodePayload(req.Payload, &wire); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if wire.ZoneName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "zone_name"})
	}
	if wire.Record == nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "record"})
	}

	pbResp, err := h.dnsGRPC.AddRecord(ctx, &platformv1.AddRecordRequest{
		ZoneName: wire.ZoneName,
		Record:   wire.Record.toProto(),
	})
	if err != nil {
		h.logger.Error(err, "failed to add DNS record", "zone", wire.ZoneName)
		return h.dnsErrorToQUICResponse("DNSAddRecord", err)
	}
	return h.encodeDNSResponse(pbResp)
}

// handleDNSDeleteRecord decodes the pb DeleteRecordRequest (no oneof — codec
// safe), delegates, and encodes the pb response.
func (h *QUICServiceHandler) handleDNSDeleteRecord(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var delReq platformv1.DeleteRecordRequest
	if err := quicwire.DecodePayload(req.Payload, &delReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if delReq.GetZoneName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "zone_name"})
	}
	if delReq.GetName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbResp, err := h.dnsGRPC.DeleteRecord(ctx, &delReq)
	if err != nil {
		h.logger.Error(err, "failed to delete DNS record", "zone", delReq.GetZoneName(), "name", delReq.GetName())
		return h.dnsErrorToQUICResponse("DNSDeleteRecord", err)
	}
	return h.encodeDNSResponse(pbResp)
}

// handleDNSListRecords decodes the pb ListRecordsRequest (no oneof),
// delegates, and encodes the FLATTENED mirror response because the pb
// ListRecordsResponse carries oneof-bearing Records that would panic the SDK
// decoder.
func (h *QUICServiceHandler) handleDNSListRecords(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var listReq platformv1.ListRecordsRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}
	if listReq.GetZoneName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "zone_name"})
	}

	pbResp, err := h.dnsGRPC.ListRecords(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list DNS records", "zone", listReq.GetZoneName())
		return h.dnsErrorToQUICResponse("DNSListRecords", err)
	}
	return h.encodeDNSResponse(dnsListRecordsResponseFromProto(pbResp))
}

// handleDNSAddZone decodes the pb CreateZoneRequest (no oneof), delegates, and
// encodes the pb response.
func (h *QUICServiceHandler) handleDNSAddZone(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var createReq platformv1.CreateZoneRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if createReq.GetName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbResp, err := h.dnsGRPC.CreateZone(ctx, &createReq)
	if err != nil {
		h.logger.Error(err, "failed to create DNS zone", "zone", createReq.GetName())
		return h.dnsErrorToQUICResponse("DNSAddZone", err)
	}
	return h.encodeDNSResponse(pbResp)
}

// handleDNSDeleteZone decodes the pb DeleteZoneRequest (no oneof), delegates,
// and encodes the pb response.
func (h *QUICServiceHandler) handleDNSDeleteZone(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var delReq platformv1.DeleteZoneRequest
	if err := quicwire.DecodePayload(req.Payload, &delReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if delReq.GetName() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbResp, err := h.dnsGRPC.DeleteZone(ctx, &delReq)
	if err != nil {
		h.logger.Error(err, "failed to delete DNS zone", "zone", delReq.GetName())
		return h.dnsErrorToQUICResponse("DNSDeleteZone", err)
	}
	return h.encodeDNSResponse(pbResp)
}

// handleDNSListZones decodes the pb ListZonesRequest (no oneof), delegates,
// and encodes the pb response. ListZonesResponse carries Zones whose nested
// RecordSet uses explicit typed slices (no oneof), so it round-trips as raw
// pb.
func (h *QUICServiceHandler) handleDNSListZones(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var listReq platformv1.ListZonesRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	pbResp, err := h.dnsGRPC.ListZones(ctx, &listReq)
	if err != nil {
		h.logger.Error(err, "failed to list DNS zones")
		return h.dnsErrorToQUICResponse("DNSListZones", err)
	}
	return h.encodeDNSResponse(pbResp)
}

// handleDNSResolve decodes the pb ResolveRequest (no oneof), delegates, and
// encodes the FLATTENED mirror response because ResolveResponse carries
// oneof-bearing Records.
func (h *QUICServiceHandler) handleDNSResolve(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.dnsGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDNSServiceNotAvailable{})
	}

	var resolveReq platformv1.ResolveRequest
	if err := quicwire.DecodePayload(req.Payload, &resolveReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if resolveReq.GetFqdn() == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "fqdn"})
	}

	pbResp, err := h.dnsGRPC.Resolve(ctx, &resolveReq)
	if err != nil {
		h.logger.Error(err, "failed to resolve DNS", "fqdn", resolveReq.GetFqdn())
		return h.dnsErrorToQUICResponse("DNSResolve", err)
	}
	return h.encodeDNSResponse(dnsResolveResponseFromProto(pbResp))
}
