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

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// Zone represents a DNS zone with its records and optional per-zone DNSSEC key configuration.
// KSK and ZSK fields allow per-zone key overrides using the standard KeyConfig pattern.
// When nil, the global DNSSECConfig defaults are used for zone signing.
type Zone struct {
	ID          uint64            `json:"id" yaml:"id" mapstructure:"id"`
	Name        string            `json:"name" yaml:"name" mapstructure:"name"`
	TenantID    string            `json:"tenant_id" yaml:"tenant_id" mapstructure:"tenant_id"`
	TTL         uint32            `json:"ttl" yaml:"ttl" mapstructure:"ttl"`
	KSK         *common.KeyConfig `json:"ksk,omitempty" yaml:"ksk,omitempty" mapstructure:"ksk"`
	ZSK         *common.KeyConfig `json:"zsk,omitempty" yaml:"zsk,omitempty" mapstructure:"zsk"`
	RecordSet   RecordSet         `json:"records" yaml:"records" mapstructure:"records"`
	Description string            `json:"description" yaml:"description" mapstructure:"description"`
	Internal    bool              `json:"internal" yaml:"internal" mapstructure:"internal"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at" mapstructure:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" yaml:"updated_at" mapstructure:"updated_at"`
}

func (z *Zone) SetEntityID(id uint64) {
	z.ID = id
}

func (z *Zone) EntityID() uint64 {
	return z.ID
}

// IsOwnedBy returns true if the zone belongs to the specified tenant.
func (z *Zone) IsOwnedBy(tenantID string) bool {
	return z.TenantID == tenantID
}

// ARecord methods
func (z *Zone) SetARecords(records []*ARecord) {
	z.RecordSet.ARecords = records
}

func (z *Zone) AddARecord(record *ARecord) {
	z.RecordSet.ARecords = append(z.RecordSet.ARecords, record)
}

// AAAARecord methods
func (z *Zone) SetAAAARecords(records []*AAAARecord) {
	z.RecordSet.AAAARecords = records
}

func (z *Zone) AddAAAARecord(record *AAAARecord) {
	z.RecordSet.AAAARecords = append(z.RecordSet.AAAARecords, record)
}

// CNAMERecord methods
func (z *Zone) SetCNAMERecords(records []*CNAMERecord) {
	z.RecordSet.CNAMERecords = records
}

func (z *Zone) AddCNAMERecord(record *CNAMERecord) {
	z.RecordSet.CNAMERecords = append(z.RecordSet.CNAMERecords, record)
}

// DNSKEYRecord methods
func (z *Zone) SetDNSKEYRecords(records []*DNSKEYRecord) {
	z.RecordSet.DNSKEYRecords = records
}

func (z *Zone) AddDNSKEYRecord(record *DNSKEYRecord) {
	z.RecordSet.DNSKEYRecords = append(z.RecordSet.DNSKEYRecords, record)
}

// DSRecord methods
func (z *Zone) SetDSRecords(records []*DSRecord) {
	z.RecordSet.DSRecords = records
}

func (z *Zone) AddDSRecord(record *DSRecord) {
	z.RecordSet.DSRecords = append(z.RecordSet.DSRecords, record)
}

// MXRecord methods
func (z *Zone) SetMXRecords(records []*MXRecord) {
	z.RecordSet.MXRecords = records
}

func (z *Zone) AddMXRecord(record *MXRecord) {
	z.RecordSet.MXRecords = append(z.RecordSet.MXRecords, record)
}

// NSRecord methods
func (z *Zone) SetNSRecords(records []*NSRecord) {
	z.RecordSet.NSRecords = records
}

func (z *Zone) AddNSRecord(record *NSRecord) {
	z.RecordSet.NSRecords = append(z.RecordSet.NSRecords, record)
}

// RRSIGRecord methods
func (z *Zone) SetRRSIGRecords(records []*RRSIGRecord) {
	z.RecordSet.RRSIGRecords = records
}

func (z *Zone) AddRRSIGRecord(record *RRSIGRecord) {
	z.RecordSet.RRSIGRecords = append(z.RecordSet.RRSIGRecords, record)
}

// SOARecord methods
func (z *Zone) SetSOARecord(record SOARecord) {
	z.RecordSet.SOARecord = record
}

// SRVRecord methods
func (z *Zone) SetSRVRecords(records []*SRVRecord) {
	z.RecordSet.SRVRecords = records
}

func (z *Zone) AddSRVRecord(record *SRVRecord) {
	z.RecordSet.SRVRecords = append(z.RecordSet.SRVRecords, record)
}

// TXTRecord methods
func (z *Zone) SetTXTRecords(records []*TXTRecord) {
	z.RecordSet.TXTRecords = records
}

func (z *Zone) AddTXTRecord(record *TXTRecord) {
	z.RecordSet.TXTRecords = append(z.RecordSet.TXTRecords, record)
}

// Remove methods by record name. Each removes the first record of its type
// with that name and reports whether the zone held one.
func (z *Zone) RemoveARecord(name string) bool {
	for i, record := range z.RecordSet.ARecords {
		if record.Name == name {
			z.RecordSet.ARecords = append(z.RecordSet.ARecords[:i], z.RecordSet.ARecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveAAAARecord(name string) bool {
	for i, record := range z.RecordSet.AAAARecords {
		if record.Name == name {
			z.RecordSet.AAAARecords = append(z.RecordSet.AAAARecords[:i], z.RecordSet.AAAARecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveCNAMERecord(name string) bool {
	for i, record := range z.RecordSet.CNAMERecords {
		if record.Name == name {
			z.RecordSet.CNAMERecords = append(z.RecordSet.CNAMERecords[:i], z.RecordSet.CNAMERecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveDNSKEYRecord(name string) bool {
	for i, record := range z.RecordSet.DNSKEYRecords {
		if record.Name == name {
			z.RecordSet.DNSKEYRecords = append(z.RecordSet.DNSKEYRecords[:i], z.RecordSet.DNSKEYRecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveDSRecord(name string) bool {
	for i, record := range z.RecordSet.DSRecords {
		if record.Name == name {
			z.RecordSet.DSRecords = append(z.RecordSet.DSRecords[:i], z.RecordSet.DSRecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveMXRecord(name string) bool {
	for i, record := range z.RecordSet.MXRecords {
		if record.Name == name {
			z.RecordSet.MXRecords = append(z.RecordSet.MXRecords[:i], z.RecordSet.MXRecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveNSRecord(name string) bool {
	for i, record := range z.RecordSet.NSRecords {
		if record.Name == name {
			z.RecordSet.NSRecords = append(z.RecordSet.NSRecords[:i], z.RecordSet.NSRecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveRRSIGRecord(name string) bool {
	for i, record := range z.RecordSet.RRSIGRecords {
		if record.SignerName == name {
			z.RecordSet.RRSIGRecords = append(z.RecordSet.RRSIGRecords[:i], z.RecordSet.RRSIGRecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveSRVRecord(name string) bool {
	for i, record := range z.RecordSet.SRVRecords {
		if record.Name == name {
			z.RecordSet.SRVRecords = append(z.RecordSet.SRVRecords[:i], z.RecordSet.SRVRecords[i+1:]...)
			return true
		}
	}
	return false
}

func (z *Zone) RemoveTXTRecord(name string) bool {
	for i, record := range z.RecordSet.TXTRecords {
		if record.Name == name {
			z.RecordSet.TXTRecords = append(z.RecordSet.TXTRecords[:i], z.RecordSet.TXTRecords[i+1:]...)
			return true
		}
	}
	return false
}

// CAARecord methods

// SetCAARecords sets the CAA records for the zone.
func (z *Zone) SetCAARecords(records []*CAARecord) {
	z.RecordSet.CAARecords = records
}

// AddCAARecord adds a CAA record to the zone.
func (z *Zone) AddCAARecord(record *CAARecord) {
	z.RecordSet.CAARecords = append(z.RecordSet.CAARecords, record)
}

// RemoveCAARecord removes a CAA record from the zone by name and reports whether the zone held one.
func (z *Zone) RemoveCAARecord(name string) bool {
	for i, record := range z.RecordSet.CAARecords {
		if record.Name == name {
			z.RecordSet.CAARecords = append(z.RecordSet.CAARecords[:i], z.RecordSet.CAARecords[i+1:]...)
			return true
		}
	}
	return false
}

// TLSARecord methods

// SetTLSARecords sets the TLSA records for the zone.
func (z *Zone) SetTLSARecords(records []*TLSARecord) {
	z.RecordSet.TLSARecords = records
}

// AddTLSARecord adds a TLSA record to the zone.
func (z *Zone) AddTLSARecord(record *TLSARecord) {
	z.RecordSet.TLSARecords = append(z.RecordSet.TLSARecords, record)
}

// RemoveTLSARecord removes a TLSA record from the zone by name and reports whether the zone held one.
func (z *Zone) RemoveTLSARecord(name string) bool {
	for i, record := range z.RecordSet.TLSARecords {
		if record.Name == name {
			z.RecordSet.TLSARecords = append(z.RecordSet.TLSARecords[:i], z.RecordSet.TLSARecords[i+1:]...)
			return true
		}
	}
	return false
}

// NSECRecord methods

// SetNSECRecords sets the NSEC records for the zone.
func (z *Zone) SetNSECRecords(records []*NSECRecord) {
	z.RecordSet.NSECRecords = records
}

// AddNSECRecord adds an NSEC record to the zone.
func (z *Zone) AddNSECRecord(record *NSECRecord) {
	z.RecordSet.NSECRecords = append(z.RecordSet.NSECRecords, record)
}

// RemoveNSECRecord removes an NSEC record from the zone by name and reports whether the zone held one.
func (z *Zone) RemoveNSECRecord(name string) bool {
	for i, record := range z.RecordSet.NSECRecords {
		if record.Name == name {
			z.RecordSet.NSECRecords = append(z.RecordSet.NSECRecords[:i], z.RecordSet.NSECRecords[i+1:]...)
			return true
		}
	}
	return false
}

// NSEC3Record methods

// SetNSEC3Records sets the NSEC3 records for the zone.
func (z *Zone) SetNSEC3Records(records []*NSEC3Record) {
	z.RecordSet.NSEC3Records = records
}

// AddNSEC3Record adds an NSEC3 record to the zone.
func (z *Zone) AddNSEC3Record(record *NSEC3Record) {
	z.RecordSet.NSEC3Records = append(z.RecordSet.NSEC3Records, record)
}

// RemoveNSEC3Record removes an NSEC3 record from the zone by name and reports whether the zone held one.
func (z *Zone) RemoveNSEC3Record(name string) bool {
	for i, record := range z.RecordSet.NSEC3Records {
		if record.Name == name {
			z.RecordSet.NSEC3Records = append(z.RecordSet.NSEC3Records[:i], z.RecordSet.NSEC3Records[i+1:]...)
			return true
		}
	}
	return false
}

// NSEC3PARAMRecord methods

// SetNSEC3PARAMRecords sets the NSEC3PARAM records for the zone.
func (z *Zone) SetNSEC3PARAMRecords(records []*NSEC3PARAMRecord) {
	z.RecordSet.NSEC3PARAMRecords = records
}

// AddNSEC3PARAMRecord adds an NSEC3PARAM record to the zone.
func (z *Zone) AddNSEC3PARAMRecord(record *NSEC3PARAMRecord) {
	z.RecordSet.NSEC3PARAMRecords = append(z.RecordSet.NSEC3PARAMRecords, record)
}

// RemoveNSEC3PARAMRecord removes an NSEC3PARAM record from the zone by name and reports whether the zone held one.
func (z *Zone) RemoveNSEC3PARAMRecord(name string) bool {
	for i, record := range z.RecordSet.NSEC3PARAMRecords {
		if record.Name == name {
			z.RecordSet.NSEC3PARAMRecords = append(z.RecordSet.NSEC3PARAMRecords[:i], z.RecordSet.NSEC3PARAMRecords[i+1:]...)
			return true
		}
	}
	return false
}
