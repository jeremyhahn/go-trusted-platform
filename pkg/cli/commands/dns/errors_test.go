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
	"errors"
	"testing"
)

func TestErrorMessages(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"wrapped":      {&WrappedError{Msg: "failed to get zone a.", Err: errRPC}, "failed to get zone a.: rpc unavailable"},
		"unknown type": {&ErrUnknownRecordType{Type: "X"}, `unknown DNS record type "X" (A, AAAA, CNAME, MX, NS, TXT, SRV, SOA, CAA, TLSA, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM)`},
		"not writable": {&ErrRecordTypeNotWritable{Type: "SOA"}, "record type SOA cannot be written directly (A, AAAA, CNAME, MX, NS, TXT, SRV, CAA, TLSA)"},
		"flag":         {&ErrFlagRequired{Flag: "name"}, "--name is required"},
		"not found":    {&ErrRecordNotFound{Zone: "a.", Type: "A", Name: "www"}, `zone a. has no A record named "www"`},
		"render":       {&ErrRenderFailed{Err: errRPC}, "failed to render DNS response: rpc unavailable"},
	}
	for name, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%s: Error() = %q, want %q", name, got, tc.want)
		}
	}
}

func TestErrorUnwrap(t *testing.T) {
	if !errors.Is(&WrappedError{Msg: "m", Err: errRPC}, errRPC) {
		t.Error("WrappedError does not unwrap to its cause")
	}
	if !errors.Is(&ErrRenderFailed{Err: errRPC}, errRPC) {
		t.Error("ErrRenderFailed does not unwrap to its cause")
	}
	if errors.Is(&WrappedError{Msg: "m", Err: errors.New("other")}, errRPC) {
		t.Error("WrappedError matched an unrelated cause")
	}
}
