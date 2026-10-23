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

package quic

// DNS wire support for the QUIC transport.
//
// The DNS SDK operations are non-category opcodes: the adapter encodes the
// generated platform.v1 request struct directly and the daemon replies with
// the platform.v1 response struct (the payload codec keys on exact Go field
// names). Most DNS requests/responses round-trip as raw pb because they carry
// no protobuf oneof.
//
// Two responses are the exception: ListRecords and Resolve carry a repeated
// Record message, and Record holds an interface-typed protobuf oneof that
// PANICS when the codec tries to decode it into the raw pb struct. The daemon
// therefore encodes those two responses as FLAT MIRROR structs whose field
// names match the pb wire byte-for-byte (dnsListRecordsResponseWire /
// dnsResolveResponseWire in pkg/api/daemon/quic_dns_delegate.go). This file
// defines the symmetric decode mirrors and maps them back onto the pb oneof.
//
// The empirically-verified wire shape of a Record is:
//
//	{"Type": <enum int>, "Record": {"<Wrapper>": {<fields>}}}
//
// where <Wrapper> is the Go field name of the generated oneof wrapper (A,
// Aaaa, Cname, Mx, Ns, Txt, Srv, Caa, Tlsa).

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// dnsSimpleRecordWire mirrors the {name, value, ttl} record messages (A, AAAA,
// CNAME, NS, TXT). Field names match the pb messages exactly.
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
// one pointer is non-nil; its Go field name matches the wrapper field the
// codec emits for the pb oneof interface value.
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

// dnsRecordWire mirrors platformv1.Record. It is the FIELD-FOR-FIELD twin of
// the daemon-side dnsRecordWire (pkg/api/daemon/quic_dns_delegate.go); the
// field-name equality IS the msgpack contract, so these names MUST NOT be
// renamed independently of the daemon struct.
type dnsRecordWire struct {
	Type   int32               `codec:"Type"`
	Record *dnsRecordOneofWire `codec:"Record"`
}

// toProto rebuilds a platformv1.Record from the mirror without touching an
// interface-typed field during decode, so it never triggers the oneof panic.
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

// dnsListRecordsWire mirrors platformv1.ListRecordsResponse.
type dnsListRecordsWire struct {
	Records []*dnsRecordWire `codec:"Records"`
}

// dnsResolveWire mirrors platformv1.ResolveResponse.
type dnsResolveWire struct {
	Records       []*dnsRecordWire `codec:"Records"`
	Authoritative bool             `codec:"Authoritative"`
}

// init registers the DNS response decoders whose replies carry the Record
// oneof. Methods absent from methodResponseDecoders decode directly into the
// pb reply via the default codec path; ListRecords and Resolve MUST use these
// mirror decoders instead or the codec panics on the oneof interface field.
func init() {
	methodResponseDecoders[platformv1.DNSService_ListRecords_FullMethodName] = decodeDNSListRecordsReply
	methodResponseDecoders[platformv1.DNSService_Resolve_FullMethodName] = decodeDNSResolveReply
}

// decodeDNSListRecordsReply decodes the flattened ListRecords wire response
// and populates the pb reply's Records via the oneof-safe mirror.
func decodeDNSListRecordsReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListRecordsResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.DNSService_ListRecords_FullMethodName}
	}
	var wire dnsListRecordsWire
	if err := quicwire.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Records = out.Records[:0]
	for _, w := range wire.Records {
		out.Records = append(out.Records, w.toProto())
	}
	return nil
}

// decodeDNSResolveReply decodes the flattened Resolve wire response and
// populates the pb reply via the oneof-safe mirror.
func decodeDNSResolveReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ResolveResponse)
	if !ok {
		return ErrInvalidReplyType{Method: platformv1.DNSService_Resolve_FullMethodName}
	}
	var wire dnsResolveWire
	if err := quicwire.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Records = out.Records[:0]
	for _, w := range wire.Records {
		out.Records = append(out.Records, w.toProto())
	}
	out.Authoritative = wire.Authoritative
	return nil
}
