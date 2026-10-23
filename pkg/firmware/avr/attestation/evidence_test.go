// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"
)

func TestParseFrame_ReadsEveryFieldAtItsWireOffset(t *testing.T) {
	// The offsets are a second copy of a definition trusted-firmware owns,
	// so this test pins them against a frame built field by field: a
	// silently shifted offset would otherwise read a neighbouring field.
	nonce := attestNonce(0x11)
	sig := bytes.Repeat([]byte{0x5A}, lenFrameSig)
	raw := buildFrame(frameOpts{
		version:   frameVersion,
		nonce:     nonce,
		deviceID:  testDeviceID,
		fwHash:    goldenFWHash,
		bootCount: 0xDEADBEEF,
		uptimeMs:  0x01020304,
		algorithm: 0x01,
		signature: sig,
	})

	f, err := parseFrame(raw)
	if err != nil {
		t.Fatalf("parseFrame: %v", err)
	}
	if f.version != frameVersion {
		t.Errorf("version = %d", f.version)
	}
	if !bytes.Equal(f.nonce, nonce) {
		t.Errorf("nonce = %x", f.nonce)
	}
	if !bytes.Equal(f.deviceID, testDeviceID) {
		t.Errorf("deviceID = %x", f.deviceID)
	}
	if !bytes.Equal(f.fwHash, goldenFWHash) {
		t.Errorf("fwHash = %x", f.fwHash)
	}
	if f.bootCount != 0xDEADBEEF {
		t.Errorf("bootCount = %#x", f.bootCount)
	}
	if f.uptimeMs != 0x01020304 {
		t.Errorf("uptimeMs = %#x", f.uptimeMs)
	}
	if f.algorithm != 0x01 {
		t.Errorf("algorithm = %#x", f.algorithm)
	}
	if !bytes.Equal(f.signature, sig) {
		t.Errorf("signature = %x", f.signature)
	}

	// Everything is copied, never aliased.
	f.fwHash[0] ^= 0xFF
	if raw[offFrameFWHash] == f.fwHash[0] {
		t.Error("the parsed measurement aliases the raw evidence")
	}
}

func TestParseFrame_RefusesFramesItMustNotGuessAt(t *testing.T) {
	good := defaultFrame(attestNonce(1))

	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{name: "empty", raw: nil, want: ErrEvidenceLength{}},
		{name: "one byte short", raw: good[:tfw.EvidenceLen-1], want: ErrEvidenceLength{}},
		{name: "one byte long", raw: append(append([]byte{}, good...), 0), want: ErrEvidenceLength{}},
		{
			name: "a version this host does not parse",
			raw:  append([]byte{frameVersion + 1}, good[1:]...),
			want: ErrEvidenceVersion{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFrame(tc.raw)
			if err == nil {
				t.Fatal("parseFrame accepted a frame it must refuse")
			}
			if !sameErrorType(err, tc.want) {
				t.Fatalf("err = %T (%v), want %T", err, err, tc.want)
			}
		})
	}
}

func TestParseFrame_ReadsAnUnprovisionedDeviceAsUnprovisioned(t *testing.T) {
	// Device id and firmware hash are ZERO until the trusted bootloader
	// supplies them, deliberately: a verifier must be able to see an
	// unprovisioned device for what it is.
	raw := buildFrame(frameOpts{version: frameVersion, nonce: attestNonce(1)})

	f, err := parseFrame(raw)
	if err != nil {
		t.Fatalf("parseFrame: %v", err)
	}
	if !bytes.Equal(f.fwHash, make([]byte, lenFrameFWHash)) {
		t.Fatalf("fwHash = %x, want all zeroes", f.fwHash)
	}
	if f.algorithm != 0 {
		t.Fatalf("algorithm = %d, want 0 (TFW_ALG_NONE)", f.algorithm)
	}
}

func TestHexOrEmpty(t *testing.T) {
	if got := hexOrEmpty(nil); got != "" {
		t.Errorf("hexOrEmpty(nil) = %q, want empty rather than an empty hex string", got)
	}
	if got := hexOrEmpty([]byte{}); got != "" {
		t.Errorf("hexOrEmpty(empty) = %q, want empty", got)
	}
	if got, want := hexOrEmpty(testSerial), hex.EncodeToString(testSerial); got != want {
		t.Errorf("hexOrEmpty = %q, want %q", got, want)
	}
}

func TestClone_SharesNoBackingArray(t *testing.T) {
	src := []byte{1, 2, 3}
	got := clone(src)
	if !bytes.Equal(got, src) {
		t.Fatalf("clone = %v, want %v", got, src)
	}
	got[0] = 9
	if src[0] != 1 {
		t.Fatal("clone shares a backing array with its source")
	}
	if len(clone(nil)) != 0 {
		t.Fatal("clone(nil) is not empty")
	}
}

func TestSyntheticPCRIndicesDoNotCollide(t *testing.T) {
	// The bootloader index is reserved and must stay distinct, so that the
	// day the bootloader reports its own measurement nothing renumbers.
	if PCRBootloader == PCRApplication {
		t.Fatal("the synthetic PCR indices collide")
	}
}

func TestDeviceFailure_NamesTheCommandAndKeepsTheCause(t *testing.T) {
	// A wrapped device failure must stay diagnosable: which wire command
	// failed, on which link, and what the SDK actually said.
	cause := errors.New("link closed")
	b := &Backend{config: &Config{DeviceRef: "usb0"}}

	err := b.deviceFailure(ActionDump, "ATTEST", cause)
	if !errors.Is(err, cause) {
		t.Fatal("the device failure lost its cause")
	}
	msg := err.Error()
	for _, want := range []string{string(Vendor), string(ActionDump), "ATTEST", "usb0", "link closed"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q does not contain %q", msg, want)
		}
	}
}
