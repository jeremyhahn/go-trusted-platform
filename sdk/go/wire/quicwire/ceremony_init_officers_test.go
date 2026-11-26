// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-only

package quicwire

import (
	"reflect"
	"testing"
)

// An M-of-N ceremony init names its officers; they must survive the wire
// or the daemon sees zero officers and refuses the request.
func TestCeremonyInitReqCarriesOfficers(t *testing.T) {
	in := &CeremonyInitReq{
		SOPIN: "so", Threshold: "2-of-2",
		Officers: []CeremonyInitOfficerReq{
			{Username: "alice", CSRPEM: "CSR-A"},
			{Username: "bob", CSRPEM: "CSR-B"},
		},
	}
	body, err := EncodePayload(in)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	var out CeremonyInitReq
	if err := DecodePayload(body, &out); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if !reflect.DeepEqual(out.Officers, in.Officers) {
		t.Errorf("officers = %+v, want %+v", out.Officers, in.Officers)
	}
}
