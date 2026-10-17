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

import (
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// addReqMirror mirrors platformv1.AddRecordRequest field-for-field. The SDK
// sends the raw pb request; this mirror proves the daemon-side decode path
// (dnsAddRecordRequestWire) reconstructs the pb Record without panicking on
// the oneof interface field.
type addReqMirror struct {
	ZoneName string         `codec:"ZoneName"`
	Record   *dnsRecordWire `codec:"Record"`
}

// allRecordArms returns one pb Record per oneof arm for exhaustive coverage.
func allRecordArms() []*platformv1.Record {
	return []*platformv1.Record{
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "1.2.3.4", Ttl: 300}}},
		{Type: platformv1.RecordType_RECORD_TYPE_AAAA, Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "2001:db8::1", Ttl: 300}}},
		{Type: platformv1.RecordType_RECORD_TYPE_CNAME, Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "alias", Value: "target.example.com.", Ttl: 600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_MX, Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "mail", Value: "mx1.example.com.", Priority: 10, Ttl: 3600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_NS, Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "sub", Value: "ns1.example.com.", Ttl: 86400}}},
		{Type: platformv1.RecordType_RECORD_TYPE_TXT, Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 -all", Ttl: 300}}},
		{Type: platformv1.RecordType_RECORD_TYPE_SRV, Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 1, Weight: 5, Ttl: 3600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_CAA, Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", Ttl: 3600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_TLSA, Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: "_443._tcp", Usage: 3, Selector: 1, MatchingType: 1, Data: "abcdef", Ttl: 3600}}},
	}
}

// TestDNSAddRecordRequestMirrorRoundTrip proves the SDK-sent pb AddRecordRequest
// (which carries the Record oneof) round-trips through the real msgpack codec
// into the daemon-side mirror shape without panicking, for every oneof arm.
func TestDNSAddRecordRequestMirrorRoundTrip(t *testing.T) {
	for _, rec := range allRecordArms() {
		rec := rec
		t.Run(rec.GetType().String(), func(t *testing.T) {
			req := &platformv1.AddRecordRequest{ZoneName: "example.com.", Record: rec}

			// The SDK encodes the raw pb request directly.
			payload, err := quicwire.EncodePayload(req)
			if err != nil {
				t.Fatalf("encode pb request: %v", err)
			}

			// The daemon decodes into the mirror — this MUST NOT panic.
			var got addReqMirror
			if err := quicwire.DecodePayload(payload, &got); err != nil {
				t.Fatalf("decode into mirror: %v", err)
			}
			if got.ZoneName != "example.com." {
				t.Fatalf("zone name lost: got %q", got.ZoneName)
			}
			if !proto.Equal(got.Record.toProto(), rec) {
				t.Fatalf("record mismatch:\n got %v\nwant %v", got.Record.toProto(), rec)
			}
		})
	}
}

// TestDNSRawPBDecodePanics documents the hazard the mirror exists to avoid:
// decoding a Record-bearing message into the raw pb struct panics on the
// interface-typed oneof field.
func TestDNSRawPBDecodePanics(t *testing.T) {
	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record:   &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "1.2.3.4", Ttl: 300}}},
	}
	payload, err := quicwire.EncodePayload(req)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic decoding Record oneof into raw pb, got none")
		}
	}()
	var raw platformv1.AddRecordRequest
	_ = quicwire.DecodePayload(payload, &raw)
	t.Fatal("decode into raw pb did not panic")
}

// TestDNSListRecordsReplyDecoder proves the SDK ListRecords response decoder
// reconstructs the pb Records from the daemon wire (byte-identical to encoding
// the pb ListRecordsResponse) without hitting the oneof panic.
func TestDNSListRecordsReplyDecoder(t *testing.T) {
	records := allRecordArms()
	// The daemon-side mirror encoding is byte-identical to encoding the pb
	// response directly (verified empirically), so encode the pb form as the
	// wire fixture.
	payload, err := quicwire.EncodePayload(&platformv1.ListRecordsResponse{
		Records: records,
		Total:   uint64(len(records)) + 40,
		Limit:   uint32(len(records)),
		Offset:  20,
	})
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}

	reply := &platformv1.ListRecordsResponse{}
	if err := decodeDNSListRecordsReply(payload, reply); err != nil {
		t.Fatalf("decodeDNSListRecordsReply: %v", err)
	}
	if len(reply.GetRecords()) != len(records) {
		t.Fatalf("record count: got %d want %d", len(reply.GetRecords()), len(records))
	}
	for i, want := range records {
		if !proto.Equal(reply.GetRecords()[i], want) {
			t.Fatalf("record %d mismatch:\n got %v\nwant %v", i, reply.GetRecords()[i], want)
		}
	}
	if reply.GetTotal() != uint64(len(records))+40 || reply.GetLimit() != uint32(len(records)) || reply.GetOffset() != 20 {
		t.Fatalf("page: got total=%d limit=%d offset=%d", reply.GetTotal(), reply.GetLimit(), reply.GetOffset())
	}
}

// TestDNSResolveReplyDecoder proves the SDK Resolve response decoder
// reconstructs pb Records and the authoritative flag.
func TestDNSResolveReplyDecoder(t *testing.T) {
	records := allRecordArms()
	payload, err := quicwire.EncodePayload(&platformv1.ResolveResponse{Records: records, Authoritative: true})
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}

	reply := &platformv1.ResolveResponse{}
	if err := decodeDNSResolveReply(payload, reply); err != nil {
		t.Fatalf("decodeDNSResolveReply: %v", err)
	}
	if !reply.GetAuthoritative() {
		t.Fatal("authoritative flag lost")
	}
	if len(reply.GetRecords()) != len(records) {
		t.Fatalf("record count: got %d want %d", len(reply.GetRecords()), len(records))
	}
	for i, want := range records {
		if !proto.Equal(reply.GetRecords()[i], want) {
			t.Fatalf("record %d mismatch:\n got %v\nwant %v", i, reply.GetRecords()[i], want)
		}
	}
}

// TestDNSReplyDecodersRegistered proves the DNS decoders are wired into the
// non-category dispatch table so the adapter routes ListRecords / Resolve
// through them instead of the panicking default path.
func TestDNSReplyDecodersRegistered(t *testing.T) {
	if _, ok := methodResponseDecoders[platformv1.DNSService_ListRecords_FullMethodName]; !ok {
		t.Fatal("ListRecords decoder not registered")
	}
	if _, ok := methodResponseDecoders[platformv1.DNSService_Resolve_FullMethodName]; !ok {
		t.Fatal("Resolve decoder not registered")
	}
}
