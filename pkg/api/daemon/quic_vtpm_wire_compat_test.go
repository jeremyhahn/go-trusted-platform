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

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The tests in this file guard the QUIC wire contract for the unified vTPM
// surface between the platform SDK client and the daemon. The SDK QUIC
// transport maps the VTPMService runtime (quote/seal/pcr) and lifecycle
// (start/stop/is-running) RPCs onto OpVTPM* opcodes and hands the generated pb
// request struct straight to the payload codec (keyed on exact Go field
// names). Before the pb-wire fix the daemon decoded flat local structs whose
// Go field names did not match:
//
//   - QuoteVTPMRequest.BundleId / Pcrs      (flat BundleID / PCRs -> dropped)
//   - SealVTPMRequest.BundleId / Pcrs / AuthValue
//   - StartVTPMRequest.BundleId             (flat BundleID -> dropped)
//
// The separate VTPMInstanceService (profile/instance model) was collapsed into
// VTPMService by the vTPM model reconciliation: bundle IS instance, and profile
// binding is expressed via CreateBundleOptions.DeviceProfileId /
// ListBundleOptions.DeviceProfileId. There is no ErrVTPMModelMismatch path any
// more; every runtime and lifecycle op round-trips onto the bundle model.

func roundTripVTPMWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quic.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quic.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

func TestQUICVTPMWireCompatRuntime(t *testing.T) {
	roundTripVTPMWire(t,
		&platformv1.QuoteVTPMRequest{
			BundleId: "bundle-1",
			Nonce:    []byte{0x01, 0x02, 0x03, 0x04},
			Pcrs:     []int32{0, 1, 7, 11},
		},
		&platformv1.QuoteVTPMRequest{})
	roundTripVTPMWire(t,
		&platformv1.SealVTPMRequest{
			BundleId:  "bundle-1",
			Data:      []byte("secret"),
			Pcrs:      []int32{0, 7},
			AuthValue: "auth",
		},
		&platformv1.SealVTPMRequest{})
	roundTripVTPMWire(t,
		&platformv1.UnsealVTPMRequest{
			BundleId:   "bundle-1",
			SealedData: []byte{0xde, 0xad, 0xbe, 0xef},
			AuthValue:  "auth",
		},
		&platformv1.UnsealVTPMRequest{})
	roundTripVTPMWire(t,
		&platformv1.ExtendVTPMPCRRequest{
			BundleId: "bundle-1",
			PcrIndex: 16,
			Data:     []byte("measure"),
		},
		&platformv1.ExtendVTPMPCRRequest{})
	roundTripVTPMWire(t,
		&platformv1.ReadVTPMPCRRequest{BundleId: "bundle-1", PcrIndex: 7},
		&platformv1.ReadVTPMPCRRequest{})
}

func TestQUICVTPMWireCompatLifecycle(t *testing.T) {
	roundTripVTPMWire(t,
		&platformv1.StartVTPMRequest{BundleId: "bundle-1"},
		&platformv1.StartVTPMRequest{})
	roundTripVTPMWire(t,
		&platformv1.StopVTPMRequest{BundleId: "bundle-1"},
		&platformv1.StopVTPMRequest{})
	roundTripVTPMWire(t,
		&platformv1.IsVTPMRunningRequest{BundleId: "bundle-1"},
		&platformv1.IsVTPMRunningRequest{})
}

// TestQUICVTPMWireCompatProfileBinding round-trips the profile-facade fields
// that were folded onto the bundle create/list options when VTPMInstanceService
// was collapsed into VTPMService. These carry the device-profile binding the
// QEMU orchestrator uses to discover a prestaged bundle for a VM.
func TestQUICVTPMWireCompatProfileBinding(t *testing.T) {
	roundTripVTPMWire(t,
		&platformv1.CreateBundleOptions{
			Mode:            platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
			Hostname:        "vm-1",
			DeviceProfileId: 4242,
		},
		&platformv1.CreateBundleOptions{})
	roundTripVTPMWire(t,
		&platformv1.ListBundleOptions{
			DeviceProfileId: 4242,
			Limit:           25,
			Offset:          0,
		},
		&platformv1.ListBundleOptions{})
}
