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
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordTypePrefix is the proto enum prefix the --type mnemonic omits.
const recordTypePrefix = "RECORD_TYPE_"

// recordFlags carries the record fields from the command line. --value is
// the record's data for every type: the address for A/AAAA, the target for
// CNAME/MX/NS/SRV, the text for TXT, the value for CAA and the hex
// certificate association data for TLSA.
type recordFlags struct {
	Type         string
	Name         string
	Value        string
	TTL          uint32
	Priority     uint32
	Weight       uint32
	Port         uint32
	Flags        uint32
	Tag          string
	Usage        uint32
	Selector     uint32
	MatchingType uint32
}

// recordRow is one record as a table shows it.
type recordRow struct {
	Name  string
	Value string
	TTL   uint32
}

// recordKind builds the record a --type writes and reads one back for a
// table. Only the types the proto Record oneof carries have one.
type recordKind struct {
	build func(f recordFlags) *platformv1.Record
	view  func(r *platformv1.Record) recordRow
}

// recordKinds dispatches on the record type.
var recordKinds = map[platformv1.RecordType]recordKind{
	platformv1.RecordType_RECORD_TYPE_A: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: f.Name, Value: f.Value, Ttl: f.TTL}}}
		},
		view: func(r *platformv1.Record) recordRow {
			a := r.GetA()
			return recordRow{Name: a.GetName(), Value: a.GetValue(), TTL: a.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_AAAA: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: f.Name, Value: f.Value, Ttl: f.TTL}}}
		},
		view: func(r *platformv1.Record) recordRow {
			a := r.GetAaaa()
			return recordRow{Name: a.GetName(), Value: a.GetValue(), TTL: a.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_CNAME: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: f.Name, Value: f.Value, Ttl: f.TTL}}}
		},
		view: func(r *platformv1.Record) recordRow {
			c := r.GetCname()
			return recordRow{Name: c.GetName(), Value: c.GetValue(), TTL: c.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_MX: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: f.Name, Value: f.Value, Priority: f.Priority, Ttl: f.TTL}}}
		},
		view: func(r *platformv1.Record) recordRow {
			m := r.GetMx()
			return recordRow{Name: m.GetName(), Value: joinFields(uintField(m.GetPriority()), m.GetValue()), TTL: m.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_NS: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: f.Name, Value: f.Value, Ttl: f.TTL}}}
		},
		view: func(r *platformv1.Record) recordRow {
			n := r.GetNs()
			return recordRow{Name: n.GetName(), Value: n.GetValue(), TTL: n.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_TXT: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: f.Name, Value: f.Value, Ttl: f.TTL}}}
		},
		view: func(r *platformv1.Record) recordRow {
			t := r.GetTxt()
			return recordRow{Name: t.GetName(), Value: t.GetValue(), TTL: t.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_SRV: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{
				Name: f.Name, Target: f.Value, Port: f.Port, Priority: f.Priority, Weight: f.Weight, Ttl: f.TTL,
			}}}
		},
		view: func(r *platformv1.Record) recordRow {
			s := r.GetSrv()
			value := joinFields(uintField(s.GetPriority()), uintField(s.GetWeight()), uintField(s.GetPort()), s.GetTarget())
			return recordRow{Name: s.GetName(), Value: value, TTL: s.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_CAA: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{
				Name: f.Name, Flags: f.Flags, Tag: f.Tag, Value: f.Value, Ttl: f.TTL,
			}}}
		},
		view: func(r *platformv1.Record) recordRow {
			c := r.GetCaa()
			return recordRow{Name: c.GetName(), Value: joinFields(uintField(c.GetFlags()), c.GetTag(), c.GetValue()), TTL: c.GetTtl()}
		},
	},
	platformv1.RecordType_RECORD_TYPE_TLSA: {
		build: func(f recordFlags) *platformv1.Record {
			return &platformv1.Record{Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{
				Name: f.Name, Usage: f.Usage, Selector: f.Selector, MatchingType: f.MatchingType, Data: f.Value, Ttl: f.TTL,
			}}}
		},
		view: func(r *platformv1.Record) recordRow {
			t := r.GetTlsa()
			value := joinFields(uintField(t.GetUsage()), uintField(t.GetSelector()), uintField(t.GetMatchingType()), t.GetData())
			return recordRow{Name: t.GetName(), Value: value, TTL: t.GetTtl()}
		},
	},
}

// parseRecordType reads a --type mnemonic (A, aaaa, MX, ...). An empty
// mnemonic is RECORD_TYPE_UNSPECIFIED, which list reads as "every type".
func parseRecordType(mnemonic string) (platformv1.RecordType, error) {
	if mnemonic == "" {
		return platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, nil
	}
	upper := strings.ToUpper(mnemonic)
	value, ok := platformv1.RecordType_value[recordTypePrefix+upper]
	if !ok || upper == "UNSPECIFIED" {
		return platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, &ErrUnknownRecordType{Type: mnemonic}
	}
	return platformv1.RecordType(value), nil
}

// requireRecordType reads a --type that must be present.
func requireRecordType(mnemonic string) (platformv1.RecordType, error) {
	if mnemonic == "" {
		return platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, &ErrFlagRequired{Flag: "type"}
	}
	return parseRecordType(mnemonic)
}

// recordTypeName is the mnemonic of a record type: A, AAAA, MX, ...
func recordTypeName(recordType platformv1.RecordType) string {
	return strings.TrimPrefix(recordType.String(), recordTypePrefix)
}

// buildRecord builds the Record a write sends from the command line.
func buildRecord(f recordFlags) (*platformv1.Record, error) {
	recordType, err := requireRecordType(f.Type)
	if err != nil {
		return nil, err
	}
	if f.Name == "" {
		return nil, &ErrFlagRequired{Flag: "name"}
	}
	kind, ok := recordKinds[recordType]
	if !ok {
		return nil, &ErrRecordTypeNotWritable{Type: recordTypeName(recordType)}
	}
	record := kind.build(f)
	record.Type = recordType
	return record, nil
}

// viewRecord reads one record for a table. A record of a type the oneof does
// not carry shows only its type.
func viewRecord(record *platformv1.Record) recordRow {
	kind, ok := recordKinds[record.GetType()]
	if !ok {
		return recordRow{}
	}
	return kind.view(record)
}

// recordsTable renders records as a table.
func recordsTable(records []*platformv1.Record) *cli.TableData {
	table := cli.NewTableData("TYPE", "NAME", "VALUE", "TTL")
	for _, record := range records {
		row := viewRecord(record)
		table.AddRow(recordTypeName(record.GetType()), row.Name, row.Value, uintField(row.TTL))
	}
	return table
}

// uintField renders a uint32 field.
func uintField(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

// joinFields joins the presentation fields of a record's data.
func joinFields(fields ...string) string {
	return strings.Join(fields, " ")
}
