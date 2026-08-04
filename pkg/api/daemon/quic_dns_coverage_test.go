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

//go:build codec_msgpack

package daemon

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// daemonRecordArms returns one pb Record per oneof arm for exhaustive mirror
// coverage.
func daemonRecordArms() []*platformv1.Record {
	return []*platformv1.Record{
		{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "1.2.3.4", Ttl: 300}}},
		{Type: platformv1.RecordType_RECORD_TYPE_AAAA, Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "2001:db8::1", Ttl: 300}}},
		{Type: platformv1.RecordType_RECORD_TYPE_CNAME, Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "alias", Value: "target.", Ttl: 600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_MX, Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "mail", Value: "mx1.", Priority: 10, Ttl: 3600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_NS, Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "sub", Value: "ns1.", Ttl: 86400}}},
		{Type: platformv1.RecordType_RECORD_TYPE_TXT, Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 -all", Ttl: 300}}},
		{Type: platformv1.RecordType_RECORD_TYPE_SRV, Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp", Target: "sip.", Port: 5060, Priority: 1, Weight: 5, Ttl: 3600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_CAA, Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", Ttl: 3600}}},
		{Type: platformv1.RecordType_RECORD_TYPE_TLSA, Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: "_443._tcp", Usage: 3, Selector: 1, MatchingType: 1, Data: "abcdef", Ttl: 3600}}},
	}
}

// TestRecordWireRoundTrip proves recordToWire -> dnsRecordWire.toProto is a
// lossless round-trip for every oneof arm (the mirror never touches an
// interface-typed field, so it never panics).
func TestRecordWireRoundTrip(t *testing.T) {
	for _, rec := range daemonRecordArms() {
		rec := rec
		t.Run(rec.GetType().String(), func(t *testing.T) {
			got := recordToWire(rec).toProto()
			if !proto.Equal(got, rec) {
				t.Fatalf("round trip mismatch:\n got %v\nwant %v", got, rec)
			}
		})
	}
}

func TestRecordToWire_Nil(t *testing.T) {
	assert.Nil(t, recordToWire(nil))
}

func TestDNSRecordWireToProto_Nil(t *testing.T) {
	var w *dnsRecordWire
	assert.Nil(t, w.toProto())

	// A record with no oneof arm set carries only the type.
	empty := (&dnsRecordWire{Type: int32(platformv1.RecordType_RECORD_TYPE_A)}).toProto()
	require.NotNil(t, empty)
	assert.Equal(t, platformv1.RecordType_RECORD_TYPE_A, empty.GetType())
	assert.Nil(t, empty.GetRecord())
}

func TestDNSListRecordsResponseFromProto(t *testing.T) {
	arms := daemonRecordArms()
	wire := dnsListRecordsResponseFromProto(&platformv1.ListRecordsResponse{Records: arms})
	require.Len(t, wire.Records, len(arms))
	for i, want := range arms {
		assert.True(t, proto.Equal(wire.Records[i].toProto(), want))
	}

	// Nil / empty input yields an empty (non-panicking) wire.
	empty := dnsListRecordsResponseFromProto(&platformv1.ListRecordsResponse{})
	assert.Empty(t, empty.Records)
}

func TestDNSResolveResponseFromProto(t *testing.T) {
	arms := daemonRecordArms()
	wire := dnsResolveResponseFromProto(&platformv1.ResolveResponse{Records: arms, Authoritative: true})
	assert.True(t, wire.Authoritative)
	require.Len(t, wire.Records, len(arms))
	for i, want := range arms {
		assert.True(t, proto.Equal(wire.Records[i].toProto(), want))
	}
}

func TestDNSErrorToQUICResponse(t *testing.T) {
	handler := createDNSUnitTestHandler(NewMockDNSService())

	cases := []struct {
		name string
		code codes.Code
		want byte
	}{
		{"invalid argument", codes.InvalidArgument, quic.StatusInvalidArgument},
		{"not found", codes.NotFound, quic.StatusNotFound},
		{"already exists", codes.AlreadyExists, quic.StatusAlreadyExists},
		{"unauthenticated", codes.Unauthenticated, quic.StatusUnauthorized},
		{"permission denied", codes.PermissionDenied, quic.StatusPermissionDenied},
		{"failed precondition", codes.FailedPrecondition, quic.StatusInvalidRequest},
		{"unavailable", codes.Unavailable, quic.StatusUnavailable},
		{"internal", codes.Internal, quic.StatusInternalError},
		{"unknown maps to internal", codes.DataLoss, quic.StatusInternalError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.dnsErrorToQUICResponse("Op", status.Error(tc.code, "boom"))
			assert.Equal(t, tc.want, resp.Status)
		})
	}
}
