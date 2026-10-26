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

package dns

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordTypePrefix is the prefix every RecordType enum name carries. A path
// or query type may be the bare mnemonic ("A") or the enum name.
const recordTypePrefix = "RECORD_TYPE_"

// DNSHandlers serves /api/v1/dns. Each handler decodes a JSON body into the
// matching protobuf request, merges in path variables and query parameters,
// calls the DNSServiceServer gRPC serves, and writes the protojson response
// in the standard envelope.
type DNSHandlers struct {
	logger     *logging.Logger
	server     platformv1.DNSServiceServer
	respWriter response.HttpWriter
}

// NewDNSHandlers wires the supplied gRPC server into the REST handlers.
func NewDNSHandlers(
	logger *logging.Logger,
	server platformv1.DNSServiceServer,
	respWriter response.HttpWriter,
) *DNSHandlers {
	return &DNSHandlers{
		logger:     logger,
		server:     server,
		respWriter: respWriter,
	}
}

func (h *DNSHandlers) ensureAvailable(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "dns"})
		return false
	}
	return true
}

// decode checks the server is wired and decodes the body into req. It
// writes the error response and returns false when either step fails.
func (h *DNSHandlers) decode(w http.ResponseWriter, r *http.Request, req proto.Message) bool {
	if !h.ensureAvailable(w, r) {
		return false
	}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return false
	}
	return true
}

// parseRecordType maps a mnemonic ("A", "aaaa") or an enum name
// ("RECORD_TYPE_A") to its RecordType. An empty value is unspecified.
func parseRecordType(value string) (platformv1.RecordType, error) {
	if value == "" {
		return platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, nil
	}
	name := strings.ToUpper(value)
	if !strings.HasPrefix(name, recordTypePrefix) {
		name = recordTypePrefix + name
	}
	parsed, ok := platformv1.RecordType_value[name]
	if !ok || parsed == int32(platformv1.RecordType_RECORD_TYPE_UNSPECIFIED) {
		return platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, &ErrInvalidRecordType{Type: value}
	}
	return platformv1.RecordType(parsed), nil
}

// queryRecordType reads the type query parameter, keeping current when the
// query does not set one.
func queryRecordType(r *http.Request, current platformv1.RecordType) (platformv1.RecordType, error) {
	value := r.URL.Query().Get("type")
	if value == "" {
		return current, nil
	}
	return parseRecordType(value)
}

// queryPagination replaces the body's page and page size with the page and
// page_size query parameters when either is given; sort_by and ascending stay
// as the body set them.
func queryPagination(r *http.Request, current *platformv1.PaginationRequest) (*platformv1.PaginationRequest, error) {
	query := r.URL.Query()
	if query.Get("page") == "" && query.Get("page_size") == "" {
		return current, nil
	}
	page, err := protorest.QueryUint32(r, "page")
	if err != nil {
		return nil, err
	}
	size, err := protorest.QueryUint32(r, "page_size")
	if err != nil {
		return nil, err
	}
	if current == nil {
		current = &platformv1.PaginationRequest{}
	}
	current.Page, current.PageSize = page, size
	return current, nil
}

// CreateZone handles POST /api/v1/dns/zones.
func (h *DNSHandlers) CreateZone(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.CreateZoneRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.server.CreateZone(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ListZones handles GET /api/v1/dns/zones. The internal and public query
// parameters set internal_only and public_only; page and page_size page.
func (h *DNSHandlers) ListZones(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListZonesRequest{}
	if !h.decode(w, r, req) {
		return
	}
	if r.URL.Query().Get("internal") != "" {
		internalOnly, err := protorest.QueryBool(r, "internal")
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		req.InternalOnly = internalOnly
	}
	if r.URL.Query().Get("public") != "" {
		publicOnly, err := protorest.QueryBool(r, "public")
		if err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
		req.PublicOnly = publicOnly
	}
	pagination, err := queryPagination(r, req.Pagination)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Pagination = pagination
	resp, err := h.server.ListZones(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetZone handles GET /api/v1/dns/zones/{zone}.
func (h *DNSHandlers) GetZone(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.GetZoneRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.Name = mux.Vars(r)["zone"]
	resp, err := h.server.GetZone(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// UpdateZone handles PUT /api/v1/dns/zones/{zone}.
func (h *DNSHandlers) UpdateZone(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.UpdateZoneRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.Name = mux.Vars(r)["zone"]
	resp, err := h.server.UpdateZone(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteZone handles DELETE /api/v1/dns/zones/{zone}.
func (h *DNSHandlers) DeleteZone(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.DeleteZoneRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.Name = mux.Vars(r)["zone"]
	resp, err := h.server.DeleteZone(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// AddRecord handles POST /api/v1/dns/zones/{zone}/records.
func (h *DNSHandlers) AddRecord(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.AddRecordRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.ZoneName = mux.Vars(r)["zone"]
	resp, err := h.server.AddRecord(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// UpdateRecord handles PUT /api/v1/dns/zones/{zone}/records.
func (h *DNSHandlers) UpdateRecord(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.UpdateRecordRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.ZoneName = mux.Vars(r)["zone"]
	resp, err := h.server.UpdateRecord(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// ListRecords handles GET /api/v1/dns/zones/{zone}/records. The type query
// parameter filters; page and page_size page.
func (h *DNSHandlers) ListRecords(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ListRecordsRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.ZoneName = mux.Vars(r)["zone"]
	recordType, err := queryRecordType(r, req.Type)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Type = recordType
	pagination, err := queryPagination(r, req.Pagination)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Pagination = pagination
	resp, err := h.server.ListRecords(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetRecord handles GET /api/v1/dns/zones/{zone}/records/{type}/{name}. It
// answers the first Record of that type and name, through ListRecords, and
// 404 when the zone holds none.
func (h *DNSHandlers) GetRecord(w http.ResponseWriter, r *http.Request) {
	if !h.ensureAvailable(w, r) {
		return
	}
	vars := mux.Vars(r)
	recordType, err := parseRecordType(vars["type"])
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.ListRecords(r.Context(), &platformv1.ListRecordsRequest{
		ZoneName: vars["zone"],
		Type:     recordType,
	})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	for _, record := range resp.GetRecords() {
		if recordName(record) == vars["name"] {
			protorest.WriteSuccess(w, r, h.respWriter, record)
			return
		}
	}
	h.respWriter.Error404(w, r, &ErrRecordNotFound{Type: vars["type"], Name: vars["name"]})
}

// DeleteRecord handles DELETE /api/v1/dns/zones/{zone}/records/{type}/{name}.
func (h *DNSHandlers) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.DeleteRecordRequest{}
	if !h.decode(w, r, req) {
		return
	}
	vars := mux.Vars(r)
	recordType, err := parseRecordType(vars["type"])
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.ZoneName, req.Type, req.Name = vars["zone"], recordType, vars["name"]
	resp, err := h.server.DeleteRecord(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Resolve handles GET /api/v1/dns/resolve?fqdn={fqdn}&type={type}. A name
// with no managed zone is not an error: the answer is empty and not
// authoritative.
func (h *DNSHandlers) Resolve(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.ResolveRequest{}
	if !h.decode(w, r, req) {
		return
	}
	if fqdn := r.URL.Query().Get("fqdn"); fqdn != "" {
		req.Fqdn = fqdn
	}
	recordType, err := queryRecordType(r, req.Type)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.Type = recordType
	resp, err := h.server.Resolve(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// SignZone handles POST /api/v1/dns/zones/{zone}/sign.
func (h *DNSHandlers) SignZone(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.SignZoneRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.ZoneName = mux.Vars(r)["zone"]
	resp, err := h.server.SignZone(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetDNSSECStatus handles GET /api/v1/dns/zones/{zone}/dnssec.
func (h *DNSHandlers) GetDNSSECStatus(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.GetDNSSECStatusRequest{}
	if !h.decode(w, r, req) {
		return
	}
	req.ZoneName = mux.Vars(r)["zone"]
	resp, err := h.server.GetDNSSECStatus(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// Register handles POST /api/v1/dns/register.
func (h *DNSHandlers) Register(w http.ResponseWriter, r *http.Request) {
	req := &platformv1.RegisterRequest{}
	if !h.decode(w, r, req) {
		return
	}
	resp, err := h.server.Register(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// recordName is the owner name of whichever record the oneof holds, or ""
// when it holds none.
func recordName(record *platformv1.Record) string {
	message := record.ProtoReflect()
	field := message.WhichOneof(message.Descriptor().Oneofs().ByName("record"))
	if field == nil {
		return ""
	}
	named, ok := message.Get(field).Message().Interface().(interface{ GetName() string })
	if !ok {
		return ""
	}
	return named.GetName()
}
