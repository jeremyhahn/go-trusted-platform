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

// PaginatedResponse contains common pagination response fields
type PaginatedResponse struct {
	Total  int64 `json:"total"`
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
}

// SuccessResponse is a generic success response
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// CreateZoneRequest is the request body for creating a zone
type CreateZoneRequest struct {
	Name        string       `json:"name"`
	TTL         uint32       `json:"ttl,omitempty"`
	Description string       `json:"description,omitempty"`
	Internal    bool         `json:"internal,omitempty"`
	SOA         *SOARequest  `json:"soa,omitempty"`
	NSRecords   []*NSRequest `json:"ns_records,omitempty"`
}

// UpdateZoneRequest is the request body for updating a zone
type UpdateZoneRequest struct {
	TTL         uint32 `json:"ttl,omitempty"`
	Description string `json:"description,omitempty"`
}

// ZoneResponse is the response for zone operations.
//
// CreatedAt + UpdatedAt are RFC3339 strings reflecting the zone entity's
// real lifecycle timestamps. They are emitted even on zones with a
// zero-value time so the frontend can render "—" when unknown without
// falling back to `new Date()` and lying about when the zone was made.
type ZoneResponse struct {
	ID          uint64             `json:"id"`
	Name        string             `json:"name"`
	TTL         uint32             `json:"ttl"`
	Description string             `json:"description,omitempty"`
	Internal    bool               `json:"internal"`
	CreatedAt   string             `json:"created_at,omitempty"`
	UpdatedAt   string             `json:"updated_at,omitempty"`
	Records     *RecordSetResponse `json:"records,omitempty"`
}

// ListZonesResponse is the response for listing zones
type ListZonesResponse struct {
	PaginatedResponse
	Zones []ZoneResponse `json:"zones"`
}

// RecordSetResponse contains all records for a zone
type RecordSetResponse struct {
	SOA    *SOAResponse      `json:"soa,omitempty"`
	A      []*AResponse      `json:"a,omitempty"`
	AAAA   []*AAAAResponse   `json:"aaaa,omitempty"`
	CNAME  []*CNAMEResponse  `json:"cname,omitempty"`
	MX     []*MXResponse     `json:"mx,omitempty"`
	NS     []*NSResponse     `json:"ns,omitempty"`
	TXT    []*TXTResponse    `json:"txt,omitempty"`
	SRV    []*SRVResponse    `json:"srv,omitempty"`
	CAA    []*CAAResponse    `json:"caa,omitempty"`
	TLSA   []*TLSAResponse   `json:"tlsa,omitempty"`
	DNSKEY []*DNSKEYResponse `json:"dnskey,omitempty"`
	DS     []*DSResponse     `json:"ds,omitempty"`
}

// SOA Record types
type SOARequest struct {
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

type SOAResponse struct {
	Name       string `json:"name"`
	MName      string `json:"mname"`
	RName      string `json:"rname"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinimumTTL uint32 `json:"minimum_ttl"`
	TTL        uint32 `json:"ttl"`
}

// A Record types
type ARequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type AResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// AAAA Record types
type AAAARequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type AAAAResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// CNAME Record types
type CNAMERequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type CNAMEResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// MX Record types
type MXRequest struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority uint16 `json:"priority,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
}

type MXResponse struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority uint16 `json:"priority"`
	TTL      uint32 `json:"ttl"`
}

// NS Record types
type NSRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type NSResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// TXT Record types
type TXTRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type TXTResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// SRV Record types
type SRVRequest struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority,omitempty"`
	Weight   uint16 `json:"weight,omitempty"`
	TTL      uint32 `json:"ttl,omitempty"`
}

type SRVResponse struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	TTL      uint32 `json:"ttl"`
}

// CAA Record types
type CAARequest struct {
	Name  string `json:"name"`
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

type CAAResponse struct {
	Name  string `json:"name"`
	Flags uint8  `json:"flags"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// TLSA Record types
type TLSARequest struct {
	Name         string `json:"name"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Data         string `json:"data"`
	TTL          uint32 `json:"ttl,omitempty"`
}

type TLSAResponse struct {
	Name         string `json:"name"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Data         string `json:"data"`
	TTL          uint32 `json:"ttl"`
}

// DNSKEY Record types
type DNSKEYResponse struct {
	Name      string `json:"name"`
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	Key       string `json:"key"`
	TTL       uint32 `json:"ttl"`
}

// DS Record types
type DSResponse struct {
	Name       string `json:"name"`
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
	TTL        uint32 `json:"ttl"`
}

// AddRecordRequest is a generic request for adding records
type AddRecordRequest struct {
	Type  string        `json:"type"`
	A     *ARequest     `json:"a,omitempty"`
	AAAA  *AAAARequest  `json:"aaaa,omitempty"`
	CNAME *CNAMERequest `json:"cname,omitempty"`
	MX    *MXRequest    `json:"mx,omitempty"`
	NS    *NSRequest    `json:"ns,omitempty"`
	TXT   *TXTRequest   `json:"txt,omitempty"`
	SRV   *SRVRequest   `json:"srv,omitempty"`
	CAA   *CAARequest   `json:"caa,omitempty"`
	TLSA  *TLSARequest  `json:"tlsa,omitempty"`
}

// RecordResponse is a generic response for record operations
type RecordResponse struct {
	Type  string         `json:"type"`
	A     *AResponse     `json:"a,omitempty"`
	AAAA  *AAAAResponse  `json:"aaaa,omitempty"`
	CNAME *CNAMEResponse `json:"cname,omitempty"`
	MX    *MXResponse    `json:"mx,omitempty"`
	NS    *NSResponse    `json:"ns,omitempty"`
	TXT   *TXTResponse   `json:"txt,omitempty"`
	SRV   *SRVResponse   `json:"srv,omitempty"`
	CAA   *CAAResponse   `json:"caa,omitempty"`
	TLSA  *TLSAResponse  `json:"tlsa,omitempty"`
}

// ListRecordsResponse is the response for listing records
type ListRecordsResponse struct {
	Records []RecordResponse `json:"records"`
}

// DNSSECStatusResponse is the response for DNSSEC status
type DNSSECStatusResponse struct {
	Enabled    bool              `json:"enabled"`
	ZoneSigned bool              `json:"zone_signed"`
	Keys       []*DNSKEYResponse `json:"keys,omitempty"`
	DSRecords  []*DSResponse     `json:"ds_records,omitempty"`
}

// RegisterRequest is the request body for DNS registration
type RegisterRequest struct {
	FQDN string `json:"fqdn"`
	IP   string `json:"ip"`
}

// ResolveRequest is the request body for DNS resolution
type ResolveRequest struct {
	FQDN string `json:"fqdn"`
	Type string `json:"type,omitempty"`
}

// ResolveResponse is the response for DNS resolution
type ResolveResponse struct {
	Records       []RecordResponse `json:"records"`
	Authoritative bool             `json:"authoritative"`
}
