// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"encoding/json"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DNS records and zone deletion (#452). The webservice DNS router
// (pkg/webservice/v1/rest/dns/router.go) keys every record operation by the
// zone in the path and a single record by its type and name, as
// docs/dns/api.md specifies. The record type travels as the server spells
// it, "A" rather than "RECORD_TYPE_A".
//
// The server answers in its own JSON rather than the gRPC replies: a record
// carries its type as that mnemonic, a zone's record set names its lists
// "a" rather than "a_records", and record writes answer with the zone. The
// decoders below translate both.
func init() {
	templatedRouteTable[platformv1.DNSService_DeleteZone_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}", http.MethodDelete, "{zone}", "name")
	templatedRouteTable[platformv1.DNSService_AddRecord_FullMethodName] =
		itemRoute("/api/v1/dns/zones/{zone}/records", http.MethodPost, "{zone}", "zone_name")
	templatedRouteTable[platformv1.DNSService_ListRecords_FullMethodName] = templatedRoute{
		path:       "/api/v1/dns/zones/{zone}/records",
		method:     http.MethodGet,
		pathParams: []pathParam{{placeholder: "{zone}", field: "zone_name"}},
		queryParams: []queryParam{
			{name: "type", field: "type", encode: dnsRecordTypeField},
			{name: "limit", field: "limit"},
			{name: "offset", field: "offset"},
		},
	}
	templatedRouteTable[platformv1.DNSService_DeleteRecord_FullMethodName] = templatedRoute{
		path:   "/api/v1/dns/zones/{zone}/records/{type}/{name}",
		method: http.MethodDelete,
		pathParams: []pathParam{
			{placeholder: "{zone}", field: "zone_name"},
			{placeholder: "{type}", field: "type", encode: dnsRecordTypeField},
			{placeholder: "{name}", field: "name"},
		},
	}
	templatedRouteTable[platformv1.DNSService_Resolve_FullMethodName] = templatedRoute{
		path:   "/api/v1/dns/resolve",
		method: http.MethodGet,
		queryParams: []queryParam{
			{name: "fqdn", field: "fqdn"},
			{name: "type", field: "type", encode: dnsRecordTypeField},
		},
	}

	restRequestEncoders[platformv1.DNSService_AddRecord_FullMethodName] =
		requestEncoder(platformv1.DNSService_AddRecord_FullMethodName, encodeDNSAddRecord)

	restResponseDecoders[platformv1.DNSService_DeleteZone_FullMethodName] =
		wireDecoder(platformv1.DNSService_DeleteZone_FullMethodName, decodeDNSDeleteZone)
	restResponseDecoders[platformv1.DNSService_AddRecord_FullMethodName] =
		wireDecoder(platformv1.DNSService_AddRecord_FullMethodName, decodeDNSAddRecord)
	restResponseDecoders[platformv1.DNSService_DeleteRecord_FullMethodName] =
		wireDecoder(platformv1.DNSService_DeleteRecord_FullMethodName, decodeDNSDeleteRecord)
	restResponseDecoders[platformv1.DNSService_ListRecords_FullMethodName] =
		wireDecoder(platformv1.DNSService_ListRecords_FullMethodName, decodeDNSListRecords)
	restResponseDecoders[platformv1.DNSService_Resolve_FullMethodName] =
		wireDecoder(platformv1.DNSService_Resolve_FullMethodName, decodeDNSResolve)
}

// dnsRecordTypePrefix is the prefix every RecordType value name carries and
// the server's mnemonic does not.
const dnsRecordTypePrefix = "RECORD_TYPE_"

// dnsJSONOut writes record bodies with the proto field names, which are the
// names the server's request types use.
var dnsJSONOut = protojson.MarshalOptions{UseProtoNames: true}

// dnsJSONIn reads server answers, dropping the fields the gRPC replies do
// not carry (a zone's created_at and updated_at).
var dnsJSONIn = protojson.UnmarshalOptions{DiscardUnknown: true}

// dnsRecordSetKeys maps the server's record-set list names to the proto
// RecordSet field names. soa is spelled the same on both sides.
var dnsRecordSetKeys = map[string]string{
	"a":      "a_records",
	"aaaa":   "aaaa_records",
	"cname":  "cname_records",
	"mx":     "mx_records",
	"ns":     "ns_records",
	"txt":    "txt_records",
	"srv":    "srv_records",
	"caa":    "caa_records",
	"tlsa":   "tlsa_records",
	"dnskey": "dnskey_records",
	"ds":     "ds_records",
}

// dnsRecordTypeName returns the server's mnemonic for a record type, "" for
// RECORD_TYPE_UNSPECIFIED.
func dnsRecordTypeName(t platformv1.RecordType) string {
	if t == platformv1.RecordType_RECORD_TYPE_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(t.String(), dnsRecordTypePrefix)
}

// dnsRecordTypeValue returns the record type the server's mnemonic names,
// RECORD_TYPE_UNSPECIFIED for one the proto does not define.
func dnsRecordTypeValue(mnemonic string) platformv1.RecordType {
	return platformv1.RecordType(platformv1.RecordType_value[dnsRecordTypePrefix+strings.ToUpper(mnemonic)])
}

// dnsRecordTypeField renders a RecordType request field for the URL.
func dnsRecordTypeField(v protoreflect.Value) string {
	return dnsRecordTypeName(platformv1.RecordType(v.Enum()))
}

// encodeDNSAddRecord sends the record as the AddRecordRequest body the
// handler decodes: the record's own fields, with its type as the mnemonic.
func encodeDNSAddRecord(req *platformv1.AddRecordRequest) (map[string]interface{}, error) {
	recordType := dnsRecordTypeName(req.GetRecord().GetType())
	if recordType == "" {
		return nil, ErrDNSRecordTypeRequired{}
	}
	raw, err := dnsJSONOut.Marshal(req.GetRecord())
	if err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}
	body := map[string]interface{}{}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}
	body["type"] = recordType
	return body, nil
}

// dnsUnmarshalFields reads a server object, already rewritten to the proto
// field names, into msg.
func dnsUnmarshalFields(fields map[string]json.RawMessage, msg proto.Message) error {
	raw, err := json.Marshal(fields)
	if err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	if err := dnsJSONIn.Unmarshal(raw, msg); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}
	return nil
}

// dnsRecordFromWire reads one server record. Its fields match the proto
// Record's; only the type is spelled differently.
func dnsRecordFromWire(raw json.RawMessage) (*platformv1.Record, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	var mnemonic string
	if wireType, ok := fields["type"]; ok {
		if err := json.Unmarshal(wireType, &mnemonic); err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		delete(fields, "type")
	}
	record := &platformv1.Record{}
	if err := dnsUnmarshalFields(fields, record); err != nil {
		return nil, err
	}
	record.Type = dnsRecordTypeValue(mnemonic)
	return record, nil
}

// dnsRecordsFromWire reads a list of server records.
func dnsRecordsFromWire(raw []json.RawMessage) ([]*platformv1.Record, error) {
	records := make([]*platformv1.Record, 0, len(raw))
	for _, item := range raw {
		record, err := dnsRecordFromWire(item)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

// dnsZoneFromWire reads a server zone, renaming its record-set lists to the
// proto RecordSet field names.
func dnsZoneFromWire(raw []byte) (*platformv1.Zone, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	if wireSet, ok := fields["records"]; ok {
		var set map[string]json.RawMessage
		if err := json.Unmarshal(wireSet, &set); err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		renamed := make(map[string]json.RawMessage, len(set))
		for key, value := range set {
			if protoKey, ok := dnsRecordSetKeys[key]; ok {
				key = protoKey
			}
			renamed[key] = value
		}
		protoSet, err := json.Marshal(renamed)
		if err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		fields["records"] = protoSet
	}
	zone := &platformv1.Zone{}
	if err := dnsUnmarshalFields(fields, zone); err != nil {
		return nil, err
	}
	return zone, nil
}

// decodeDNSDeleteZone reads the server's {success, message} answer.
func decodeDNSDeleteZone(raw []byte) (*platformv1.DeleteZoneResponse, error) {
	var answer struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return &platformv1.DeleteZoneResponse{
		Status: &platformv1.Status{Success: answer.Success, Message: answer.Message},
	}, nil
}

// decodeDNSAddRecord reads the zone the server answers after the write.
func decodeDNSAddRecord(raw []byte) (*platformv1.AddRecordResponse, error) {
	zone, err := dnsZoneFromWire(raw)
	if err != nil {
		return nil, err
	}
	return &platformv1.AddRecordResponse{Status: &platformv1.Status{Success: true}, Zone: zone}, nil
}

// decodeDNSDeleteRecord reads the zone the server answers after the delete.
func decodeDNSDeleteRecord(raw []byte) (*platformv1.DeleteRecordResponse, error) {
	zone, err := dnsZoneFromWire(raw)
	if err != nil {
		return nil, err
	}
	return &platformv1.DeleteRecordResponse{Status: &platformv1.Status{Success: true}, Zone: zone}, nil
}

// dnsRecordsAnswer is the server's answer to list and resolve.
type dnsRecordsAnswer struct {
	Records       []json.RawMessage `json:"records"`
	Authoritative bool              `json:"authoritative"`
	Total         uint64            `json:"total"`
	Limit         uint32            `json:"limit"`
	Offset        uint32            `json:"offset"`
}

// readDNSRecordsAnswer reads a list or resolve answer and its records.
func readDNSRecordsAnswer(raw []byte) (dnsRecordsAnswer, []*platformv1.Record, error) {
	var answer dnsRecordsAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return answer, nil, ErrUnmarshalFailed{Err: err}
	}
	records, err := dnsRecordsFromWire(answer.Records)
	return answer, records, err
}

// decodeDNSListRecords reads the zone's records.
func decodeDNSListRecords(raw []byte) (*platformv1.ListRecordsResponse, error) {
	answer, records, err := readDNSRecordsAnswer(raw)
	if err != nil {
		return nil, err
	}
	return &platformv1.ListRecordsResponse{
		Records: records,
		Total:   answer.Total,
		Limit:   answer.Limit,
		Offset:  answer.Offset,
	}, nil
}

// decodeDNSResolve reads the resolved records and whether a managed zone
// answered for them.
func decodeDNSResolve(raw []byte) (*platformv1.ResolveResponse, error) {
	answer, records, err := readDNSRecordsAnswer(raw)
	if err != nil {
		return nil, err
	}
	return &platformv1.ResolveResponse{Records: records, Authoritative: answer.Authoritative}, nil
}
