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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginatedResponse_JSON(t *testing.T) {
	resp := PaginatedResponse{
		Total:  100,
		Limit:  50,
		Offset: 10,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded PaginatedResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Total, decoded.Total)
	assert.Equal(t, resp.Limit, decoded.Limit)
	assert.Equal(t, resp.Offset, decoded.Offset)
}

func TestSuccessResponse_JSON(t *testing.T) {
	resp := SuccessResponse{
		Success: true,
		Message: "operation completed",
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded SuccessResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Success, decoded.Success)
	assert.Equal(t, resp.Message, decoded.Message)
}

func TestCreateZoneRequest_JSON(t *testing.T) {
	req := CreateZoneRequest{
		Name:        "example.com.",
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
		SOA: &SOARequest{
			Name:       "example.com.",
			MName:      "ns1.example.com.",
			RName:      "admin.example.com.",
			Serial:     1,
			Refresh:    7200,
			Retry:      3600,
			Expire:     1209600,
			MinimumTTL: 3600,
			TTL:        3600,
		},
		NSRecords: []*NSRequest{
			{Name: "@", Value: "ns1.example.com.", TTL: 3600},
		},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded CreateZoneRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Name, decoded.Name)
	assert.Equal(t, req.TTL, decoded.TTL)
	assert.Equal(t, req.Description, decoded.Description)
	assert.Equal(t, req.Internal, decoded.Internal)
	require.NotNil(t, decoded.SOA)
	assert.Equal(t, req.SOA.MName, decoded.SOA.MName)
	require.Len(t, decoded.NSRecords, 1)
	assert.Equal(t, req.NSRecords[0].Value, decoded.NSRecords[0].Value)
}

func TestUpdateZoneRequest_JSON(t *testing.T) {
	req := UpdateZoneRequest{
		TTL:         7200,
		Description: "Updated description",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded UpdateZoneRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.TTL, decoded.TTL)
	assert.Equal(t, req.Description, decoded.Description)
}

func TestZoneResponse_JSON(t *testing.T) {
	resp := ZoneResponse{
		ID:          1,
		Name:        "example.com.",
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
		Records: &RecordSetResponse{
			SOA: &SOAResponse{
				Name:  "example.com.",
				MName: "ns1.example.com.",
			},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ZoneResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.ID, decoded.ID)
	assert.Equal(t, resp.Name, decoded.Name)
	assert.Equal(t, resp.TTL, decoded.TTL)
	require.NotNil(t, decoded.Records)
	require.NotNil(t, decoded.Records.SOA)
}

func TestListZonesResponse_JSON(t *testing.T) {
	resp := ListZonesResponse{
		PaginatedResponse: PaginatedResponse{
			Total:  2,
			Limit:  50,
			Offset: 0,
		},
		Zones: []ZoneResponse{
			{ID: 1, Name: "example.com."},
			{ID: 2, Name: "test.com."},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ListZonesResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Total, decoded.Total)
	assert.Len(t, decoded.Zones, 2)
}

func TestRecordSetResponse_JSON(t *testing.T) {
	resp := RecordSetResponse{
		SOA:    &SOAResponse{Name: "example.com.", MName: "ns1.example.com."},
		A:      []*AResponse{{Name: "www", Value: "192.168.1.1", TTL: 3600}},
		AAAA:   []*AAAAResponse{{Name: "www", Value: "2001:db8::1", TTL: 3600}},
		CNAME:  []*CNAMEResponse{{Name: "alias", Value: "www.example.com.", TTL: 3600}},
		MX:     []*MXResponse{{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600}},
		NS:     []*NSResponse{{Name: "@", Value: "ns1.example.com.", TTL: 3600}},
		TXT:    []*TXTResponse{{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600}},
		SRV:    []*SRVResponse{{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, TTL: 3600}},
		CAA:    []*CAAResponse{{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600}},
		TLSA:   []*TLSAResponse{{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600}},
		DNSKEY: []*DNSKEYResponse{{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "test", TTL: 3600}},
		DS:     []*DSResponse{{Name: "example.com.", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc", TTL: 3600}},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded RecordSetResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.SOA)
	require.Len(t, decoded.A, 1)
	require.Len(t, decoded.AAAA, 1)
	require.Len(t, decoded.CNAME, 1)
	require.Len(t, decoded.MX, 1)
	require.Len(t, decoded.NS, 1)
	require.Len(t, decoded.TXT, 1)
	require.Len(t, decoded.SRV, 1)
	require.Len(t, decoded.CAA, 1)
	require.Len(t, decoded.TLSA, 1)
	require.Len(t, decoded.DNSKEY, 1)
	require.Len(t, decoded.DS, 1)
}

func TestSOARequest_JSON(t *testing.T) {
	req := SOARequest{
		Name:       "example.com.",
		MName:      "ns1.example.com.",
		RName:      "admin.example.com.",
		Serial:     1,
		Refresh:    7200,
		Retry:      3600,
		Expire:     1209600,
		MinimumTTL: 3600,
		TTL:        3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded SOARequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestSOAResponse_JSON(t *testing.T) {
	resp := SOAResponse{
		Name:       "example.com.",
		MName:      "ns1.example.com.",
		RName:      "admin.example.com.",
		Serial:     1,
		Refresh:    7200,
		Retry:      3600,
		Expire:     1209600,
		MinimumTTL: 3600,
		TTL:        3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded SOAResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestARequest_JSON(t *testing.T) {
	req := ARequest{
		Name:  "www",
		Value: "192.168.1.1",
		TTL:   3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ARequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestAResponse_JSON(t *testing.T) {
	resp := AResponse{
		Name:  "www",
		Value: "192.168.1.1",
		TTL:   3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded AResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestAAAARequest_JSON(t *testing.T) {
	req := AAAARequest{
		Name:  "www",
		Value: "2001:db8::1",
		TTL:   3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded AAAARequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestAAAAResponse_JSON(t *testing.T) {
	resp := AAAAResponse{
		Name:  "www",
		Value: "2001:db8::1",
		TTL:   3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded AAAAResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestCNAMERequest_JSON(t *testing.T) {
	req := CNAMERequest{
		Name:  "alias",
		Value: "www.example.com.",
		TTL:   3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded CNAMERequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestCNAMEResponse_JSON(t *testing.T) {
	resp := CNAMEResponse{
		Name:  "alias",
		Value: "www.example.com.",
		TTL:   3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded CNAMEResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestMXRequest_JSON(t *testing.T) {
	req := MXRequest{
		Name:     "@",
		Value:    "mail.example.com.",
		Priority: 10,
		TTL:      3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded MXRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestMXResponse_JSON(t *testing.T) {
	resp := MXResponse{
		Name:     "@",
		Value:    "mail.example.com.",
		Priority: 10,
		TTL:      3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded MXResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestNSRequest_JSON(t *testing.T) {
	req := NSRequest{
		Name:  "@",
		Value: "ns1.example.com.",
		TTL:   3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded NSRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestNSResponse_JSON(t *testing.T) {
	resp := NSResponse{
		Name:  "@",
		Value: "ns1.example.com.",
		TTL:   3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded NSResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestTXTRequest_JSON(t *testing.T) {
	req := TXTRequest{
		Name:  "_dmarc",
		Value: "v=DMARC1; p=reject",
		TTL:   3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded TXTRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestTXTResponse_JSON(t *testing.T) {
	resp := TXTResponse{
		Name:  "_dmarc",
		Value: "v=DMARC1; p=reject",
		TTL:   3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded TXTResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestSRVRequest_JSON(t *testing.T) {
	req := SRVRequest{
		Name:     "_sip._tcp",
		Target:   "sip.example.com.",
		Port:     5060,
		Priority: 10,
		Weight:   100,
		TTL:      3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded SRVRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestSRVResponse_JSON(t *testing.T) {
	resp := SRVResponse{
		Name:     "_sip._tcp",
		Target:   "sip.example.com.",
		Port:     5060,
		Priority: 10,
		Weight:   100,
		TTL:      3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded SRVResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestCAARequest_JSON(t *testing.T) {
	req := CAARequest{
		Name:  "@",
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
		TTL:   3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded CAARequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestCAAResponse_JSON(t *testing.T) {
	resp := CAAResponse{
		Name:  "@",
		Flags: 0,
		Tag:   "issue",
		Value: "letsencrypt.org",
		TTL:   3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded CAAResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestTLSARequest_JSON(t *testing.T) {
	req := TLSARequest{
		Name:         "_443._tcp.www",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abc123",
		TTL:          3600,
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded TLSARequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req, decoded)
}

func TestTLSAResponse_JSON(t *testing.T) {
	resp := TLSAResponse{
		Name:         "_443._tcp.www",
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Data:         "abc123",
		TTL:          3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded TLSAResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestDNSKEYResponse_JSON(t *testing.T) {
	resp := DNSKEYResponse{
		Name:      "example.com.",
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		Key:       "test-key",
		TTL:       3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded DNSKEYResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestDSResponse_JSON(t *testing.T) {
	resp := DSResponse{
		Name:       "example.com.",
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "abcd1234",
		TTL:        3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded DSResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp, decoded)
}

func TestAddRecordRequest_JSON(t *testing.T) {
	req := AddRecordRequest{
		Type: "A",
		A:    &ARequest{Name: "www", Value: "192.168.1.1", TTL: 3600},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded AddRecordRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.Type, decoded.Type)
	require.NotNil(t, decoded.A)
	assert.Equal(t, req.A.Name, decoded.A.Name)
}

func TestAddRecordRequest_AllTypes(t *testing.T) {
	req := AddRecordRequest{
		Type:  "A",
		A:     &ARequest{Name: "www", Value: "192.168.1.1", TTL: 3600},
		AAAA:  &AAAARequest{Name: "www", Value: "2001:db8::1", TTL: 3600},
		CNAME: &CNAMERequest{Name: "alias", Value: "www.example.com.", TTL: 3600},
		MX:    &MXRequest{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600},
		NS:    &NSRequest{Name: "@", Value: "ns1.example.com.", TTL: 3600},
		TXT:   &TXTRequest{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600},
		SRV:   &SRVRequest{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, TTL: 3600},
		CAA:   &CAARequest{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
		TLSA:  &TLSARequest{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600},
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded AddRecordRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.A)
	require.NotNil(t, decoded.AAAA)
	require.NotNil(t, decoded.CNAME)
	require.NotNil(t, decoded.MX)
	require.NotNil(t, decoded.NS)
	require.NotNil(t, decoded.TXT)
	require.NotNil(t, decoded.SRV)
	require.NotNil(t, decoded.CAA)
	require.NotNil(t, decoded.TLSA)
}

func TestRecordResponse_JSON(t *testing.T) {
	resp := RecordResponse{
		Type: "A",
		A:    &AResponse{Name: "www", Value: "192.168.1.1", TTL: 3600},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded RecordResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, resp.Type, decoded.Type)
	require.NotNil(t, decoded.A)
}

func TestRecordResponse_AllTypes(t *testing.T) {
	resp := RecordResponse{
		Type:  "A",
		A:     &AResponse{Name: "www", Value: "192.168.1.1", TTL: 3600},
		AAAA:  &AAAAResponse{Name: "www", Value: "2001:db8::1", TTL: 3600},
		CNAME: &CNAMEResponse{Name: "alias", Value: "www.example.com.", TTL: 3600},
		MX:    &MXResponse{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600},
		NS:    &NSResponse{Name: "@", Value: "ns1.example.com.", TTL: 3600},
		TXT:   &TXTResponse{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600},
		SRV:   &SRVResponse{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, TTL: 3600},
		CAA:   &CAAResponse{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
		TLSA:  &TLSAResponse{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded RecordResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.A)
	require.NotNil(t, decoded.AAAA)
	require.NotNil(t, decoded.CNAME)
	require.NotNil(t, decoded.MX)
	require.NotNil(t, decoded.NS)
	require.NotNil(t, decoded.TXT)
	require.NotNil(t, decoded.SRV)
	require.NotNil(t, decoded.CAA)
	require.NotNil(t, decoded.TLSA)
}

func TestListRecordsResponse_JSON(t *testing.T) {
	resp := ListRecordsResponse{
		Records: []RecordResponse{
			{Type: "A", A: &AResponse{Name: "www", Value: "192.168.1.1", TTL: 3600}},
			{Type: "AAAA", AAAA: &AAAAResponse{Name: "www", Value: "2001:db8::1", TTL: 3600}},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ListRecordsResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Records, 2)
}

func TestDNSSECStatusResponse_JSON(t *testing.T) {
	resp := DNSSECStatusResponse{
		Enabled:    true,
		ZoneSigned: true,
		Keys: []*DNSKEYResponse{
			{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "test", TTL: 3600},
		},
		DSRecords: []*DSResponse{
			{Name: "example.com.", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc", TTL: 3600},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded DNSSECStatusResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, decoded.Enabled)
	assert.True(t, decoded.ZoneSigned)
	assert.Len(t, decoded.Keys, 1)
	assert.Len(t, decoded.DSRecords, 1)
}

func TestRegisterRequest_JSON(t *testing.T) {
	req := RegisterRequest{
		FQDN: "device.local.",
		IP:   "192.168.1.100",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded RegisterRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.FQDN, decoded.FQDN)
	assert.Equal(t, req.IP, decoded.IP)
}

func TestResolveRequest_JSON(t *testing.T) {
	req := ResolveRequest{
		FQDN: "www.example.com.",
		Type: "A",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded ResolveRequest
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, req.FQDN, decoded.FQDN)
	assert.Equal(t, req.Type, decoded.Type)
}

func TestResolveResponse_JSON(t *testing.T) {
	resp := ResolveResponse{
		Records: []RecordResponse{
			{Type: "A", A: &AResponse{Name: "www", Value: "192.168.1.1", TTL: 3600}},
		},
		Authoritative: true,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded ResolveResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.True(t, decoded.Authoritative)
	assert.Len(t, decoded.Records, 1)
}

// Test omitempty behavior

func TestZoneResponse_OmitEmpty(t *testing.T) {
	resp := ZoneResponse{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Check that empty fields with omitempty are not present
	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "description")
	assert.NotContains(t, jsonStr, "records")
}

func TestSuccessResponse_OmitEmpty(t *testing.T) {
	resp := SuccessResponse{
		Success: true,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Check that message is not present when empty
	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "message")
}
