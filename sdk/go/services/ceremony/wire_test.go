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

package ceremony

import (
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestEnumToWire(t *testing.T) {
	auth, err := AuthenticatorTypeToWire(platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2)
	if err != nil || auth != "fido2" {
		t.Fatalf("AuthenticatorTypeToWire = %q, %v; want fido2", auth, err)
	}
	role, err := OfficerRoleToWire(platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_SO)
	if err != nil || role != "so" {
		t.Fatalf("OfficerRoleToWire = %q, %v; want so", role, err)
	}
	unset, err := OfficerRoleToWire(platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_UNSPECIFIED)
	if err != nil || unset != "" {
		t.Fatalf("unspecified role = %q, %v; want empty", unset, err)
	}
}

func TestEnumToWireRejectsUnknown(t *testing.T) {
	var unknown *ErrUnknownWireValue
	if _, err := AuthenticatorTypeToWire(platformv1.CeremonyAuthenticatorType(99)); !errors.As(err, &unknown) {
		t.Fatalf("AuthenticatorTypeToWire(99) error = %v; want ErrUnknownWireValue", err)
	}
	if _, err := OfficerRoleToWire(platformv1.CeremonyOfficerRole(99)); !errors.As(err, &unknown) {
		t.Fatalf("OfficerRoleToWire(99) error = %v; want ErrUnknownWireValue", err)
	}
}

func TestStateFromWire(t *testing.T) {
	want := map[string]platformv1.CeremonyState{
		"":              platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED,
		"unknown":       platformv1.CeremonyState_CEREMONY_STATE_UNSPECIFIED,
		"uninitialized": platformv1.CeremonyState_CEREMONY_STATE_UNINITIALIZED,
		"in_progress":   platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS,
		"complete":      platformv1.CeremonyState_CEREMONY_STATE_COMPLETE,
	}
	for in, state := range want {
		got, err := StateFromWire(in)
		if err != nil || got != state {
			t.Errorf("StateFromWire(%q) = %v, %v; want %v", in, got, err, state)
		}
	}
	var unknown *ErrUnknownWireValue
	if _, err := StateFromWire("sealed"); !errors.As(err, &unknown) {
		t.Fatalf("StateFromWire(sealed) error = %v; want ErrUnknownWireValue", err)
	}
}

func TestTimestampOrNil(t *testing.T) {
	if TimestampOrNil(time.Time{}) != nil {
		t.Fatal("zero time must map to nil")
	}
	at := time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)
	if got := TimestampOrNil(at); got == nil || !got.AsTime().Equal(at) {
		t.Fatalf("TimestampOrNil = %v; want %v", got, at)
	}
}

func TestDecodeInitJSON(t *testing.T) {
	out, err := DecodeInitJSON([]byte(`{"ceremony_id":"c1","state":"in_progress","initialized_at":"2026-10-09T01:02:03Z"}`))
	if err != nil {
		t.Fatalf("DecodeInitJSON: %v", err)
	}
	if out.GetCeremonyId() != "c1" || out.GetState() != platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS {
		t.Fatalf("DecodeInitJSON = %v", out)
	}
	if out.GetInitializedAt().AsTime().Year() != 2026 {
		t.Fatalf("initialized_at = %v", out.GetInitializedAt())
	}
	// A zero time (MCP always emits the key) must come back unset.
	out, err = DecodeInitJSON([]byte(`{"ceremony_id":"c1","state":"uninitialized","initialized_at":"0001-01-01T00:00:00Z"}`))
	if err != nil || out.GetInitializedAt() != nil {
		t.Fatalf("zero initialized_at = %v, %v; want nil", out.GetInitializedAt(), err)
	}
}

func TestDecodeStatusJSON(t *testing.T) {
	out, err := DecodeStatusJSON([]byte(`{"ceremony_id":"c1","state":"complete","threshold":"2-of-3","officers_enrolled":2,"officers_required":3}`))
	if err != nil {
		t.Fatalf("DecodeStatusJSON: %v", err)
	}
	if out.GetThreshold() != "2-of-3" || out.GetOfficersEnrolled() != 2 || out.GetOfficersRequired() != 3 ||
		out.GetState() != platformv1.CeremonyState_CEREMONY_STATE_COMPLETE {
		t.Fatalf("DecodeStatusJSON = %v", out)
	}
}

func TestDecodeChallengeJSON(t *testing.T) {
	cert, err := DecodeClaimCertBeginJSON([]byte(`{"nonce":"n","challenge_id":"ch","expires_at":"2026-10-09T01:02:03Z"}`))
	if err != nil || cert.GetNonce() != "n" || cert.GetChallengeId() != "ch" || cert.GetExpiresAt() == nil {
		t.Fatalf("DecodeClaimCertBeginJSON = %v, %v", cert, err)
	}
	share, err := DecodeClaimShareBeginJSON([]byte(`{"nonce":"n","expires_at":"2026-10-09T01:02:03Z"}`))
	if err != nil || share.GetNonce() != "n" || share.GetExpiresAt() == nil {
		t.Fatalf("DecodeClaimShareBeginJSON = %v, %v", share, err)
	}
}

func TestDecodeJSONRejectsBadInput(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"init":        func(b []byte) error { _, err := DecodeInitJSON(b); return err },
		"status":      func(b []byte) error { _, err := DecodeStatusJSON(b); return err },
		"claim-cert":  func(b []byte) error { _, err := DecodeClaimCertBeginJSON(b); return err },
		"claim-share": func(b []byte) error { _, err := DecodeClaimShareBeginJSON(b); return err },
	}
	for name, decode := range decoders {
		var wireErr *ErrWireDecode
		if err := decode([]byte(`not json`)); !errors.As(err, &wireErr) {
			t.Errorf("%s: malformed JSON error = %v; want ErrWireDecode", name, err)
		}
	}
	var unknown *ErrUnknownWireValue
	if _, err := DecodeInitJSON([]byte(`{"state":"sealed"}`)); !errors.As(err, &unknown) {
		t.Errorf("init unknown state error = %v; want ErrUnknownWireValue", err)
	}
	if _, err := DecodeStatusJSON([]byte(`{"state":"sealed"}`)); !errors.As(err, &unknown) {
		t.Errorf("status unknown state error = %v; want ErrUnknownWireValue", err)
	}
}
