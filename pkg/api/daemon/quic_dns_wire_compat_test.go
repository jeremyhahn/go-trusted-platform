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

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/require"
)

// These tests pin the DNS QUIC wire contract through the REAL msgpack codec
// (built with -tags codec_msgpack). They prove:
//
//   - the codec-safe request messages (no oneof) round-trip as raw pb;
//   - the oneof-bearing AddRecord request decodes into the daemon mirror
//     WITHOUT panicking and reconstructs the pb Record exactly;
//   - the ListRecords / Resolve mirror responses round-trip losslessly;
//   - decoding an oneof-bearing message into raw pb panics (the hazard the
//     mirror exists to avoid).

// TestDNSCodecSafeRequestsRoundTrip proves the non-oneof SDK-mapped request
// messages round-trip as raw pb (encode as the SDK does, decode as the daemon
// does).
func TestDNSCodecSafeRequestsRoundTrip(t *testing.T) {
	t.Run("DeleteRecordRequest", func(t *testing.T) {
		in := &platformv1.DeleteRecordRequest{ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A, Name: "www"}
		payload, err := quicwire.EncodePayload(in)
		require.NoError(t, err)
		var out platformv1.DeleteRecordRequest
		require.NoError(t, quicwire.DecodePayload(payload, &out))
		require.True(t, proto.Equal(&out, in))
	})

	t.Run("CreateZoneRequest", func(t *testing.T) {
		in := &platformv1.CreateZoneRequest{Name: "example.com.", Ttl: 3600, Description: "d", Internal: true}
		payload, err := quicwire.EncodePayload(in)
		require.NoError(t, err)
		var out platformv1.CreateZoneRequest
		require.NoError(t, quicwire.DecodePayload(payload, &out))
		require.True(t, proto.Equal(&out, in))
	})

	t.Run("DeleteZoneRequest", func(t *testing.T) {
		in := &platformv1.DeleteZoneRequest{Name: "example.com."}
		payload, err := quicwire.EncodePayload(in)
		require.NoError(t, err)
		var out platformv1.DeleteZoneRequest
		require.NoError(t, quicwire.DecodePayload(payload, &out))
		require.True(t, proto.Equal(&out, in))
	})

	t.Run("ListZonesRequest", func(t *testing.T) {
		in := &platformv1.ListZonesRequest{InternalOnly: true}
		payload, err := quicwire.EncodePayload(in)
		require.NoError(t, err)
		var out platformv1.ListZonesRequest
		require.NoError(t, quicwire.DecodePayload(payload, &out))
		require.True(t, proto.Equal(&out, in))
	})
}

// TestDNSAddRecordRequestMirrorRoundTrip proves the SDK-sent pb AddRecordRequest
// decodes into the daemon mirror without panicking on the oneof, for every arm.
func TestDNSAddRecordRequestMirrorRoundTrip(t *testing.T) {
	for _, rec := range daemonRecordArms() {
		rec := rec
		t.Run(rec.GetType().String(), func(t *testing.T) {
			in := &platformv1.AddRecordRequest{ZoneName: "example.com.", Record: rec}
			payload, err := quicwire.EncodePayload(in) // SDK encodes raw pb
			require.NoError(t, err)

			var got dnsAddRecordRequestWire
			require.NoError(t, quicwire.DecodePayload(payload, &got)) // daemon decodes mirror
			require.Equal(t, "example.com.", got.ZoneName)
			require.True(t, proto.Equal(got.Record.toProto(), rec))
		})
	}
}

// TestDNSListRecordsResponseWireRoundTrip proves the flattened ListRecords
// response wire round-trips losslessly through the codec.
func TestDNSListRecordsResponseWireRoundTrip(t *testing.T) {
	arms := daemonRecordArms()
	wire := dnsListRecordsResponseFromProto(&platformv1.ListRecordsResponse{Records: arms})
	payload, err := quicwire.EncodePayload(wire)
	require.NoError(t, err)

	var got dnsListRecordsResponseWire
	require.NoError(t, quicwire.DecodePayload(payload, &got))
	require.Len(t, got.Records, len(arms))
	for i, want := range arms {
		require.True(t, proto.Equal(got.Records[i].toProto(), want))
	}
}

// TestDNSResolveResponseWireRoundTrip proves the flattened Resolve response
// wire round-trips losslessly through the codec.
func TestDNSResolveResponseWireRoundTrip(t *testing.T) {
	arms := daemonRecordArms()
	wire := dnsResolveResponseFromProto(&platformv1.ResolveResponse{Records: arms, Authoritative: true})
	payload, err := quicwire.EncodePayload(wire)
	require.NoError(t, err)

	var got dnsResolveResponseWire
	require.NoError(t, quicwire.DecodePayload(payload, &got))
	require.True(t, got.Authoritative)
	require.Len(t, got.Records, len(arms))
	for i, want := range arms {
		require.True(t, proto.Equal(got.Records[i].toProto(), want))
	}
}

// TestDNSRawPBOneofDecodePanics documents the hazard the mirror avoids:
// decoding a Record-bearing message into raw pb panics on the oneof interface.
func TestDNSRawPBOneofDecodePanics(t *testing.T) {
	in := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record:   &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "1.2.3.4", Ttl: 300}}},
	}
	payload, err := quicwire.EncodePayload(in)
	require.NoError(t, err)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic decoding Record oneof into raw pb")
		}
	}()
	var raw platformv1.AddRecordRequest
	_ = quicwire.DecodePayload(payload, &raw)
	t.Fatal("decode into raw pb did not panic")
}
