package entities

type Zone struct {
	ID          uint64    `json:"id" yaml:"id" mapstructure:"id"`
	Name        string    `json:"name" yaml:"name" mapstructure:"name"`
	TTL         uint32    `json:"ttl" yaml:"ttl" mapstructure:"ttl"`
	RecordSet   RecordSet `json:"records" yaml:"records" mapstructure:"records"`
	Description string    `json:"description" yaml:"description" mapstructure:"description"`
	Internal    bool      `json:"internal" yaml:"internal" mapstructure:"internal"`
}

func (z *Zone) SetEntityID(id uint64) {
	z.ID = id
}

func (z *Zone) EntityID() uint64 {
	return z.ID
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

// Remove methods by record name
func (z *Zone) RemoveARecord(name string) {
	for i, record := range z.RecordSet.ARecords {
		if record.Name == name {
			z.RecordSet.ARecords = append(z.RecordSet.ARecords[:i], z.RecordSet.ARecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveAAAARecord(name string) {
	for i, record := range z.RecordSet.AAAARecords {
		if record.Name == name {
			z.RecordSet.AAAARecords = append(z.RecordSet.AAAARecords[:i], z.RecordSet.AAAARecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveCNAMERecord(name string) {
	for i, record := range z.RecordSet.CNAMERecords {
		if record.Name == name {
			z.RecordSet.CNAMERecords = append(z.RecordSet.CNAMERecords[:i], z.RecordSet.CNAMERecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveDNSKEYRecord(name string) {
	for i, record := range z.RecordSet.DNSKEYRecords {
		if record.Name == name {
			z.RecordSet.DNSKEYRecords = append(z.RecordSet.DNSKEYRecords[:i], z.RecordSet.DNSKEYRecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveDSRecord(name string) {
	for i, record := range z.RecordSet.DSRecords {
		if record.Name == name {
			z.RecordSet.DSRecords = append(z.RecordSet.DSRecords[:i], z.RecordSet.DSRecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveMXRecord(name string) {
	for i, record := range z.RecordSet.MXRecords {
		if record.Name == name {
			z.RecordSet.MXRecords = append(z.RecordSet.MXRecords[:i], z.RecordSet.MXRecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveNSRecord(name string) {
	for i, record := range z.RecordSet.NSRecords {
		if record.Name == name {
			z.RecordSet.NSRecords = append(z.RecordSet.NSRecords[:i], z.RecordSet.NSRecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveRRSIGRecord(name string) {
	for i, record := range z.RecordSet.RRSIGRecords {
		if record.SignerName == name {
			z.RecordSet.RRSIGRecords = append(z.RecordSet.RRSIGRecords[:i], z.RecordSet.RRSIGRecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveSRVRecord(name string) {
	for i, record := range z.RecordSet.SRVRecords {
		if record.Name == name {
			z.RecordSet.SRVRecords = append(z.RecordSet.SRVRecords[:i], z.RecordSet.SRVRecords[i+1:]...)
			break
		}
	}
}

func (z *Zone) RemoveTXTRecord(name string) {
	for i, record := range z.RecordSet.TXTRecords {
		if record.Name == name {
			z.RecordSet.TXTRecords = append(z.RecordSet.TXTRecords[:i], z.RecordSet.TXTRecords[i+1:]...)
			break
		}
	}
}
