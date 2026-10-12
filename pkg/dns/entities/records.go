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

package entities

type RecordSet struct {
	ARecords          []*ARecord          `yaml:"a,omitempty" json:"a,omitempty" mapstructure:"a,omitempty"`
	AAAARecords       []*AAAARecord       `yaml:"aaaa,omitempty" json:"aaaa,omitempty" mapstructure:"aaaa,omitempty"`
	CAARecords        []*CAARecord        `yaml:"caa,omitempty" json:"caa,omitempty" mapstructure:"caa,omitempty"`
	CNAMERecords      []*CNAMERecord      `yaml:"cname,omitempty" json:"cname,omitempty" mapstructure:"cname,omitempty"`
	DNSKEYRecords     []*DNSKEYRecord     `yaml:"key,omitempty" json:"key,omitempty" mapstructure:"key,omitempty"`
	DSRecords         []*DSRecord         `yaml:"ds,omitempty" json:"ds,omitempty" mapstructure:"ds,omitempty"`
	MXRecords         []*MXRecord         `yaml:"mx,omitempty" json:"mx,omitempty" mapstructure:"mx,omitempty"`
	NSECRecords       []*NSECRecord       `yaml:"nsec,omitempty" json:"nsec,omitempty" mapstructure:"nsec,omitempty"`
	NSEC3Records      []*NSEC3Record      `yaml:"nsec3,omitempty" json:"nsec3,omitempty" mapstructure:"nsec3,omitempty"`
	NSEC3PARAMRecords []*NSEC3PARAMRecord `yaml:"nsec3param,omitempty" json:"nsec3param,omitempty" mapstructure:"nsec3param,omitempty"`
	NSRecords         []*NSRecord         `yaml:"ns,omitempty" json:"ns,omitempty" mapstructure:"ns,omitempty"`
	RRSIGRecords      []*RRSIGRecord      `yaml:"rrsig,omitempty" json:"rrsig,omitempty" mapstructure:"rrsig,omitempty"`
	SOARecord         SOARecord           `yaml:"soa,omitempty" json:"soa,omitempty" mapstructure:"soa,omitempty"`
	SRVRecords        []*SRVRecord        `yaml:"srv,omitempty" json:"srv,omitempty" mapstructure:"srv,omitempty"`
	TLSARecords       []*TLSARecord       `yaml:"tlsa,omitempty" json:"tlsa,omitempty" mapstructure:"tlsa,omitempty"`
	TXTRecords        []*TXTRecord        `yaml:"txt,omitempty" json:"txt,omitempty" mapstructure:"txt,omitempty"`
}

type ARecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type AAAARecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

// CAARecord represents a DNS CAA (Certification Authority Authorization) record
// per RFC 8659 for controlling certificate issuance.
type CAARecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Flags uint8  `yaml:"flags" json:"flags" mapstructure:"flags"`
	Tag   string `yaml:"tag" json:"tag" mapstructure:"tag"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type CNAMERecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type DNSKEYRecord struct {
	Algorithm uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Flags     uint16 `yaml:"flags" json:"flags" mapstructure:"flags"`
	ID        uint64 `yaml:"id" json:"id" mapstructure:"id"`
	Key       string `yaml:"key" json:"key" mapstructure:"key"`
	Name      string `yaml:"name" json:"name" mapstructure:"name"`
	Protocol  uint8  `yaml:"protocol" json:"protocol" mapstructure:"protocol"`
	TTL       uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
}

type DSRecord struct {
	Algorithm  uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Digest     string `yaml:"digest" json:"digest" mapstructure:"digest"`
	DigestType uint8  `yaml:"digest_type" json:"digest_type" mapstructure:"digest_type"`
	ID         uint64 `yaml:"id" json:"id" mapstructure:"id"`
	KeyTag     uint16 `yaml:"key-tag" json:"key_tag" mapstructure:"key_tag"`
	Name       string `yaml:"name" json:"name" mapstructure:"name"`
	TTL        uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
}

type MXRecord struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Priority uint16 `yaml:"priority" json:"priority" mapstructure:"priority"`
	TTL      uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value    string `yaml:"value" json:"value" mapstructure:"value"`
}

type NSRecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

type RRSIGRecord struct {
	// Name is the owner of the RRset the signature covers. Empty or "@" is
	// the zone apex, which is also how a signature persisted before the
	// owner was recorded is read.
	Name        string `yaml:"name,omitempty" json:"name,omitempty" mapstructure:"name,omitempty"`
	Algorithm   uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Expiration  string `yaml:"expiration" json:"expiration" mapstructure:"expiration"`
	Inception   string `yaml:"inception" json:"inception" mapstructure:"inception"`
	KeyTag      uint16 `yaml:"key-tag" json:"key_tag" mapstructure:"key_tag"`
	Labels      uint8  `yaml:"labels" json:"labels" mapstructure:"labels"`
	OriginalTTL uint32 `yaml:"original-ttl,omitempty" json:"original_ttl,omitempty" mapstructure:"original_ttl,omitempty"`
	Signature   string `yaml:"signature" json:"signature" mapstructure:"signature"`
	SignerName  string `yaml:"signer" json:"signer" mapstructure:"signer"`
	TypeCovered string `yaml:"type-covered" json:"type_covered" mapstructure:"type_covered"`
}

type SOARecord struct {
	Expire     uint32 `yaml:"expire" json:"expire" mapstructure:"expire"`
	MName      string `yaml:"mname" json:"mname" mapstructure:"mname"`
	MinimumTTL uint32 `yaml:"min-ttl,omitempty" json:"min_ttl,omitempty" mapstructure:"min_ttl,omitempty"`
	Name       string `yaml:"name" json:"name" mapstructure:"name"`
	RName      string `yaml:"rname" json:"rname" mapstructure:"rname"`
	Refresh    uint32 `yaml:"refresh" json:"refresh" mapstructure:"refresh"`
	Retry      uint32 `yaml:"retry" json:"retry" mapstructure:"retry"`
	Serial     uint32 `yaml:"serial" json:"serial" mapstructure:"serial"`
	TTL        uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
}

type SRVRecord struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Port     uint16 `yaml:"port" json:"port" mapstructure:"port"`
	Priority uint16 `yaml:"priority" json:"priority" mapstructure:"priority"`
	Target   string `yaml:"target" json:"target" mapstructure:"target"`
	TTL      uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Weight   uint16 `yaml:"weight" json:"weight" mapstructure:"weight"`
}

// TLSARecord represents a DNS TLSA record for DANE (DNS-based Authentication
// of Named Entities) per RFC 6698.
type TLSARecord struct {
	Name         string `yaml:"name" json:"name" mapstructure:"name"`
	TTL          uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Usage        uint8  `yaml:"usage" json:"usage" mapstructure:"usage"`
	Selector     uint8  `yaml:"selector" json:"selector" mapstructure:"selector"`
	MatchingType uint8  `yaml:"matching-type" json:"matching_type" mapstructure:"matching_type"`
	Data         string `yaml:"data" json:"data" mapstructure:"data"`
}

type TXTRecord struct {
	Name  string `yaml:"name" json:"name" mapstructure:"name"`
	TTL   uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Value string `yaml:"value" json:"value" mapstructure:"value"`
}

// NSECRecord represents an NSEC record for authenticated denial of existence
// per RFC 4034. NSEC records prove the non-existence of a name in the zone.
type NSECRecord struct {
	Name       string   `yaml:"name" json:"name" mapstructure:"name"`
	TTL        uint32   `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	NextDomain string   `yaml:"next-domain" json:"next_domain" mapstructure:"next-domain"`
	TypeBitMap []uint16 `yaml:"type-bitmap" json:"type_bitmap" mapstructure:"type-bitmap"`
}

// NSEC3Record represents an NSEC3 record for hashed authenticated denial
// of existence per RFC 5155. NSEC3 provides the same functionality as NSEC
// but uses hashed names to prevent zone enumeration.
type NSEC3Record struct {
	Name       string   `yaml:"name" json:"name" mapstructure:"name"`
	TTL        uint32   `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Algorithm  uint8    `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Flags      uint8    `yaml:"flags" json:"flags" mapstructure:"flags"`
	Iterations uint16   `yaml:"iterations" json:"iterations" mapstructure:"iterations"`
	Salt       string   `yaml:"salt" json:"salt" mapstructure:"salt"`
	NextHashed string   `yaml:"next-hashed" json:"next_hashed" mapstructure:"next-hashed"`
	TypeBitMap []uint16 `yaml:"type-bitmap" json:"type_bitmap" mapstructure:"type-bitmap"`
}

// NSEC3PARAMRecord represents NSEC3 parameters per RFC 5155.
// This record is stored at the zone apex and defines the NSEC3 parameters
// used for generating NSEC3 records in the zone.
type NSEC3PARAMRecord struct {
	Name       string `yaml:"name" json:"name" mapstructure:"name"`
	TTL        uint32 `yaml:"ttl,omitempty" json:"ttl,omitempty" mapstructure:"ttl,omitempty"`
	Algorithm  uint8  `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	Flags      uint8  `yaml:"flags" json:"flags" mapstructure:"flags"`
	Iterations uint16 `yaml:"iterations" json:"iterations" mapstructure:"iterations"`
	Salt       string `yaml:"salt" json:"salt" mapstructure:"salt"`
}
