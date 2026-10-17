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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface over the daemon REST
// listener, whose DNS routes live under /api/v1/dns
// (pkg/webservice/v1/rest/dns/router.go).

//go:build integration

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// restDNSPrefix is where the daemon REST listener mounts the DNS routes.
const restDNSPrefix = "/api/v1/dns"

// restRequestTimeout bounds one REST round trip.
const restRequestTimeout = 30 * time.Second

// ErrRESTConnectionFailed is returned when the REST endpoint cannot be reached.
type ErrRESTConnectionFailed struct {
	URL string
	Err error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("REST connection to %s failed: %v", e.URL, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error { return e.Err }

// ErrRESTRequestFailed is returned when a request cannot be built or a
// response cannot be read or decoded.
type ErrRESTRequestFailed struct {
	Op  string
	Err error
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("REST %s failed: %v", e.Op, e.Err)
}

func (e ErrRESTRequestFailed) Unwrap() error { return e.Err }

// ErrRESTAPIError is returned when the server answers with a 4xx or 5xx status.
type ErrRESTAPIError struct {
	StatusCode int
	Message    string
}

func (e ErrRESTAPIError) Error() string {
	return fmt.Sprintf("REST API error (%d): %s", e.StatusCode, e.Message)
}

// RESTAdapter implements DNSCommands against the daemon REST listener,
// authenticating with the runner's mTLS client certificate.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter returns an adapter for PLATFORM_API_ENDPOINT. The runner
// exports the endpoint with its scheme; a bare host:port gets https://,
// because platformd serves REST over TLS only.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv(EnvPlatformAPIEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformAPIEndpoint
	}
	return &RESTAdapter{baseURL: restBaseURL(endpoint) + restDNSPrefix}
}

// restBaseURL keeps an explicit scheme and gives a bare host:port https://.
func restBaseURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return strings.TrimSuffix(endpoint, "/")
	}
	return "https://" + endpoint
}

// Name returns the adapter name.
func (r *RESTAdapter) Name() string { return "REST" }

// Setup builds the mTLS client from the runner's client certificate and key.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	r.httpClient = helpers.NewHTTPClient(restRequestTimeout)
	return nil
}

// Teardown releases idle connections.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// restEnvelope is the daemon's response envelope (sdk/go/wire/restwire).
type restEnvelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// do sends one request and decodes the envelope payload into out.
func (r *RESTAdapter) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	reqURL := r.baseURL + path
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return ErrRESTRequestFailed{Op: "encode " + method + " " + path, Err: err}
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return ErrRESTRequestFailed{Op: "build " + method + " " + path, Err: err}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ErrRESTConnectionFailed{URL: reqURL, Err: err}
	}
	raw, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return ErrRESTRequestFailed{Op: "read " + method + " " + path, Err: readErr}
	}
	if closeErr != nil {
		return ErrRESTRequestFailed{Op: "close " + method + " " + path, Err: closeErr}
	}

	var env restEnvelope
	decodeErr := json.Unmarshal(raw, &env)
	if resp.StatusCode >= http.StatusBadRequest {
		message := strings.TrimSpace(string(raw))
		if decodeErr == nil && env.Error != "" {
			message = env.Error
		}
		return ErrRESTAPIError{StatusCode: resp.StatusCode, Message: message}
	}
	if decodeErr != nil {
		return ErrRESTRequestFailed{Op: "decode " + method + " " + path, Err: decodeErr}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(env.Payload, out); err != nil {
		return ErrRESTRequestFailed{Op: "decode payload of " + method + " " + path, Err: err}
	}
	return nil
}

func zonePath(zoneName string) string {
	return "/zones/" + url.PathEscape(zoneName)
}

func recordPath(zoneName, recordType, name string) string {
	return zonePath(zoneName) + "/records/" + url.PathEscape(recordType) + "/" + url.PathEscape(name)
}

// pageQuery adds limit and offset; the cursor is the offset the previous
// page returned.
func pageQuery(query url.Values, limit int32, cursor string) (int, error) {
	offset := 0
	if cursor != "" {
		parsed, err := strconv.Atoi(cursor)
		if err != nil {
			return 0, ErrRESTRequestFailed{Op: "parse cursor " + cursor, Err: err}
		}
		offset = parsed
		query.Set("offset", cursor)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(int(limit)))
	}
	return offset, nil
}

// parseRESTTime parses the server's RFC 3339 timestamps; an absent one is
// the zero time.
func parseRESTTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, ErrRESTRequestFailed{Op: "parse time " + value, Err: err}
	}
	return parsed, nil
}

// Wire types (pkg/webservice/v1/rest/dns/types.go).

type restSOA struct {
	Name       string `json:"name"`
	MName      string `json:"mname"`
	RName      string `json:"rname"`
	Serial     uint32 `json:"serial,omitempty"`
	Refresh    uint32 `json:"refresh,omitempty"`
	Retry      uint32 `json:"retry,omitempty"`
	Expire     uint32 `json:"expire,omitempty"`
	MinimumTTL uint32 `json:"minimum_ttl,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
}

type restCreateZoneRequest struct {
	Name        string   `json:"name"`
	TTL         uint32   `json:"ttl,omitempty"`
	Description string   `json:"description,omitempty"`
	Internal    bool     `json:"internal"`
	SOA         *restSOA `json:"soa,omitempty"`
}

type restUpdateZoneRequest struct {
	TTL         uint32 `json:"ttl,omitempty"`
	Description string `json:"description,omitempty"`
}

type restRecordSet struct {
	SOA    *restSOA          `json:"soa"`
	A      []json.RawMessage `json:"a"`
	AAAA   []json.RawMessage `json:"aaaa"`
	CNAME  []json.RawMessage `json:"cname"`
	MX     []json.RawMessage `json:"mx"`
	NS     []json.RawMessage `json:"ns"`
	TXT    []json.RawMessage `json:"txt"`
	SRV    []json.RawMessage `json:"srv"`
	CAA    []json.RawMessage `json:"caa"`
	TLSA   []json.RawMessage `json:"tlsa"`
	DNSKEY []json.RawMessage `json:"dnskey"`
	DS     []json.RawMessage `json:"ds"`
}

// count returns the number of records in the set, the SOA included.
func (rs *restRecordSet) count() int {
	if rs == nil {
		return 0
	}
	count := len(rs.A) + len(rs.AAAA) + len(rs.CNAME) + len(rs.MX) + len(rs.NS) +
		len(rs.TXT) + len(rs.SRV) + len(rs.CAA) + len(rs.TLSA) + len(rs.DNSKEY) + len(rs.DS)
	if rs.SOA != nil {
		count++
	}
	return count
}

type restZone struct {
	ID          uint64         `json:"id"`
	Name        string         `json:"name"`
	TTL         uint32         `json:"ttl"`
	Description string         `json:"description"`
	Internal    bool           `json:"internal"`
	CreatedAt   string         `json:"created_at"`
	UpdatedAt   string         `json:"updated_at"`
	Records     *restRecordSet `json:"records"`
}

type restListZones struct {
	Total int64      `json:"total"`
	Zones []restZone `json:"zones"`
}

type restSuccess struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// restRecord is the union of the per-type record shapes; each type sends
// only its own fields.
type restRecord struct {
	Name         string `json:"name"`
	Value        string `json:"value,omitempty"`
	Target       string `json:"target,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Priority     uint16 `json:"priority,omitempty"`
	Weight       uint16 `json:"weight,omitempty"`
	Usage        uint8  `json:"usage,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	MatchingType uint8  `json:"matching_type,omitempty"`
	Data         string `json:"data,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
}

// value returns the record's data as the suite names it: the SRV target,
// the TLSA data, or the value of every other type.
func (rec restRecord) value(recordType string) string {
	switch recordType {
	case "SRV":
		return rec.Target
	case "TLSA":
		return rec.Data
	}
	return rec.Value
}

// restTypedRecord is the server's RecordResponse: a type and one filled field.
type restTypedRecord struct {
	Type  string      `json:"type"`
	A     *restRecord `json:"a"`
	AAAA  *restRecord `json:"aaaa"`
	CNAME *restRecord `json:"cname"`
	MX    *restRecord `json:"mx"`
	NS    *restRecord `json:"ns"`
	TXT   *restRecord `json:"txt"`
	SRV   *restRecord `json:"srv"`
	CAA   *restRecord `json:"caa"`
	TLSA  *restRecord `json:"tlsa"`
}

// record returns the filled field for the record's type.
func (t restTypedRecord) record() (string, restRecord, bool) {
	recordType := strings.ToUpper(t.Type)
	byType := map[string]*restRecord{
		"A": t.A, "AAAA": t.AAAA, "CNAME": t.CNAME, "MX": t.MX, "NS": t.NS,
		"TXT": t.TXT, "SRV": t.SRV, "CAA": t.CAA, "TLSA": t.TLSA,
	}
	rec := byType[recordType]
	if rec == nil {
		return recordType, restRecord{}, false
	}
	return recordType, *rec, true
}

type restRecordList struct {
	Total   int64             `json:"total"`
	Records []restTypedRecord `json:"records"`
}

// Zone operations

// CreateZone creates a new DNS zone.
func (r *RESTAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	body := restCreateZoneRequest{
		Name:        opts.Name,
		TTL:         opts.TTL,
		Description: opts.Description,
		Internal:    opts.Internal,
	}
	if opts.SOA != nil {
		body.SOA = &restSOA{
			Name:       opts.Name,
			MName:      opts.SOA.MName,
			RName:      opts.SOA.RName,
			Serial:     opts.SOA.Serial,
			Refresh:    opts.SOA.Refresh,
			Retry:      opts.SOA.Retry,
			Expire:     opts.SOA.Expire,
			MinimumTTL: opts.SOA.MinimumTTL,
			TTL:        opts.TTL,
		}
	}

	var zone restZone
	if err := r.do(ctx, http.MethodPost, "/zones", nil, body, &zone); err != nil {
		return nil, err
	}
	createdAt, err := parseRESTTime(zone.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &CreateZoneResult{
		Name:      zone.Name,
		ID:        strconv.FormatUint(zone.ID, 10),
		TTL:       zone.TTL,
		Internal:  zone.Internal,
		CreatedAt: createdAt,
	}, nil
}

// GetZone retrieves a DNS zone by name.
func (r *RESTAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	var zone restZone
	if err := r.do(ctx, http.MethodGet, zonePath(zoneName), nil, nil, &zone); err != nil {
		return nil, err
	}
	createdAt, err := parseRESTTime(zone.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := parseRESTTime(zone.UpdatedAt)
	if err != nil {
		return nil, err
	}

	result := &GetZoneResult{
		Name:        zone.Name,
		ID:          strconv.FormatUint(zone.ID, 10),
		TTL:         zone.TTL,
		Description: zone.Description,
		Internal:    zone.Internal,
		RecordCount: zone.Records.count(),
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
	if zone.Records != nil && zone.Records.SOA != nil {
		soa := zone.Records.SOA
		result.SOA = &SOARecordInfo{
			Name:       soa.Name,
			MName:      soa.MName,
			RName:      soa.RName,
			Serial:     soa.Serial,
			Refresh:    soa.Refresh,
			Retry:      soa.Retry,
			Expire:     soa.Expire,
			MinimumTTL: soa.MinimumTTL,
			TTL:        soa.TTL,
		}
	}
	return result, nil
}

// UpdateZone updates a zone's TTL and description.
func (r *RESTAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	body := restUpdateZoneRequest{TTL: opts.TTL, Description: opts.Description}
	var zone restZone
	if err := r.do(ctx, http.MethodPut, zonePath(zoneName), nil, body, &zone); err != nil {
		return nil, err
	}
	updatedAt, err := parseRESTTime(zone.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &UpdateZoneResult{Name: zone.Name, TTL: zone.TTL, UpdatedAt: updatedAt}, nil
}

// DeleteZone deletes a DNS zone.
func (r *RESTAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	var resp restSuccess
	if err := r.do(ctx, http.MethodDelete, zonePath(zoneName), nil, nil, &resp); err != nil {
		return nil, err
	}
	return &DeleteZoneResult{Name: zoneName, Deleted: resp.Success}, nil
}

// ListZones lists DNS zones, a page at a time when a limit is given.
func (r *RESTAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	query := url.Values{}
	if opts.Internal != nil {
		if *opts.Internal {
			query.Set("internal", "true")
		} else {
			query.Set("public", "true")
		}
	}
	offset, err := pageQuery(query, opts.Limit, opts.Cursor)
	if err != nil {
		return nil, err
	}

	var resp restListZones
	if err := r.do(ctx, http.MethodGet, "/zones", query, nil, &resp); err != nil {
		return nil, err
	}

	result := &ListZonesResult{
		Zones:      make([]ZoneSummary, 0, len(resp.Zones)),
		TotalCount: int32(resp.Total),
	}
	for _, zone := range resp.Zones {
		createdAt, err := parseRESTTime(zone.CreatedAt)
		if err != nil {
			return nil, err
		}
		result.Zones = append(result.Zones, ZoneSummary{
			Name:        zone.Name,
			ID:          strconv.FormatUint(zone.ID, 10),
			TTL:         zone.TTL,
			Internal:    zone.Internal,
			RecordCount: zone.Records.count(),
			CreatedAt:   createdAt,
		})
	}
	next := offset + len(resp.Zones)
	if int64(next) < resp.Total {
		result.HasMore = true
		result.NextCursor = strconv.Itoa(next)
	}
	return result, nil
}

// Record operations

// addRecord posts one record of recordType to the zone.
func (r *RESTAdapter) addRecord(ctx context.Context, zoneName, recordType string, rec restRecord) error {
	body := map[string]any{
		"type":                      recordType,
		strings.ToLower(recordType): rec,
	}
	return r.do(ctx, http.MethodPost, zonePath(zoneName)+"/records", nil, body, nil)
}

// getRecord reads one record; a 404 is ErrRecordNotFound, as on gRPC.
func (r *RESTAdapter) getRecord(ctx context.Context, zoneName, name, recordType string) (restRecord, error) {
	var typed restTypedRecord
	err := r.do(ctx, http.MethodGet, recordPath(zoneName, recordType, name), nil, nil, &typed)
	var apiErr ErrRESTAPIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return restRecord{}, ErrRecordNotFound{Name: name, Type: recordType}
	}
	if err != nil {
		return restRecord{}, err
	}
	_, rec, ok := typed.record()
	if !ok {
		return restRecord{}, ErrRecordNotFound{Name: name, Type: recordType}
	}
	return rec, nil
}

// AddRecord adds a DNS record to a zone.
func (r *RESTAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	recordType := strings.ToUpper(opts.RecordType)
	if err := r.addRecord(ctx, opts.ZoneName, recordType, recordFromOptions(recordType, opts.Name, opts.Value, opts.TTL, opts.Priority, opts.Weight, opts.Port)); err != nil {
		return nil, err
	}
	return &AddRecordResult{
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		CreatedAt:  time.Now(),
	}, nil
}

// recordFromOptions builds the wire record; SRV carries its value as the target.
func recordFromOptions(recordType, name, value string, ttl uint32, priority, weight, port uint16) restRecord {
	rec := restRecord{Name: name, TTL: ttl, Priority: priority, Weight: weight, Port: port}
	if recordType == "SRV" {
		rec.Target = value
	} else {
		rec.Value = value
	}
	return rec
}

// GetRecord retrieves a DNS record by name and type from the zone the name
// belongs to.
func (r *RESTAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	recordType = strings.ToUpper(recordType)
	rec, err := r.getRecord(ctx, extractZoneName(name), name, recordType)
	if err != nil {
		return nil, err
	}
	return &GetRecordResult{
		Name:       rec.Name,
		RecordType: recordType,
		Value:      rec.value(recordType),
		TTL:        rec.TTL,
		Priority:   rec.Priority,
		Weight:     rec.Weight,
		Port:       rec.Port,
	}, nil
}

// UpdateRecord replaces a record the way the gRPC server does: the record
// must exist, it is deleted, and the new one is added.
func (r *RESTAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	recordType := strings.ToUpper(opts.RecordType)
	if _, err := r.getRecord(ctx, opts.ZoneName, opts.Name, recordType); err != nil {
		return nil, err
	}
	if err := r.do(ctx, http.MethodDelete, recordPath(opts.ZoneName, recordType, opts.Name), nil, nil, nil); err != nil {
		return nil, err
	}
	if err := r.addRecord(ctx, opts.ZoneName, recordType, recordFromOptions(recordType, opts.Name, opts.Value, opts.TTL, opts.Priority, opts.Weight, opts.Port)); err != nil {
		return nil, err
	}
	return &UpdateRecordResult{
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		UpdatedAt:  time.Now(),
	}, nil
}

// DeleteRecord deletes a DNS record. The REST delete answers 200 for a
// record that is not there, so the record is looked up first and a missing
// one is ErrRecordNotFound, as on gRPC.
func (r *RESTAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	recordType = strings.ToUpper(recordType)
	zoneName := extractZoneName(name)
	if _, err := r.getRecord(ctx, zoneName, name, recordType); err != nil {
		return nil, err
	}
	if err := r.do(ctx, http.MethodDelete, recordPath(zoneName, recordType, name), nil, nil, nil); err != nil {
		return nil, err
	}
	return &DeleteRecordResult{Name: name, RecordType: recordType, Deleted: true}, nil
}

// ListRecords lists the records in a zone. The REST list carries no total,
// so TotalCount is the page size and a full page reports HasMore.
func (r *RESTAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	query := url.Values{}
	if opts.RecordType != "" {
		query.Set("type", strings.ToUpper(opts.RecordType))
	}
	offset, err := pageQuery(query, opts.Limit, opts.Cursor)
	if err != nil {
		return nil, err
	}

	var resp restRecordList
	if err := r.do(ctx, http.MethodGet, zonePath(zoneName)+"/records", query, nil, &resp); err != nil {
		return nil, err
	}

	result := &ListRecordsResult{Records: make([]RecordSummary, 0, len(resp.Records))}
	for _, typed := range resp.Records {
		recordType, rec, ok := typed.record()
		if !ok {
			continue
		}
		result.Records = append(result.Records, RecordSummary{
			Name:       rec.Name,
			RecordType: recordType,
			Value:      rec.value(recordType),
			TTL:        rec.TTL,
			Priority:   rec.Priority,
		})
	}
	result.TotalCount = int32(resp.Total)
	next := offset + len(resp.Records)
	if int64(next) < resp.Total {
		result.HasMore = true
		result.NextCursor = strconv.Itoa(next)
	}
	return result, nil
}

// Resolve resolves a name to its record values. An empty answer is
// ErrRecordNotFound, as on gRPC.
func (r *RESTAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	recordType = strings.ToUpper(recordType)
	query := url.Values{}
	query.Set("fqdn", name)
	query.Set("type", recordType)

	var resp restRecordList
	if err := r.do(ctx, http.MethodGet, "/resolve", query, nil, &resp); err != nil {
		return nil, err
	}

	result := &ResolveResult{Name: name, RecordType: recordType, Timestamp: time.Now()}
	for _, typed := range resp.Records {
		answerType, rec, ok := typed.record()
		if !ok {
			continue
		}
		if len(result.Values) == 0 {
			result.TTL = rec.TTL
		}
		result.Values = append(result.Values, rec.value(answerType))
	}
	if len(result.Values) == 0 {
		return nil, ErrRecordNotFound{Name: name, Type: recordType}
	}
	return result, nil
}

// TLSA operations

// AddTLSARecord adds a TLSA record for DANE.
func (r *RESTAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	rec := restRecord{
		Name:         opts.Name,
		Usage:        opts.Usage,
		Selector:     opts.Selector,
		MatchingType: opts.MatchingType,
		Data:         opts.Data,
		TTL:          opts.TTL,
	}
	if err := r.addRecord(ctx, opts.ZoneName, "TLSA", rec); err != nil {
		return nil, err
	}
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
