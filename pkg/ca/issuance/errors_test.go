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

package issuance

import (
	"errors"
	"strings"
	"testing"
)

// Every error says what to fix and keeps its cause, and only the caller's
// errors read as an invalid request: transports map that to 400 or
// InvalidArgument, everything else to a server failure.
func TestErrors_NameTheProblemAndClassifyIt(t *testing.T) {
	cause := errors.New("the cause")
	cases := []struct {
		err     error
		invalid bool
		says    []string
	}{
		{&UnknownStoreTypeError{Name: "kms"}, true, []string{`"kms"`, "software (pkcs8)"}},
		{&CSRError{Reason: "it has no common name"}, true, []string{"invalid CSR: it has no common name"}},
		{&CSRError{Reason: "it does not parse", Err: cause}, true, []string{"it does not parse: the cause"}},
		{&CSRSubjectError{Attributes: []string{"O"}}, true, []string{"carries O"}},
		{&CSRSANError{}, true, []string{"no subject alternative names"}},
		{&CSRKeyError{KeyID: "rpi/fleet", Err: cause}, true, []string{`"rpi/fleet"`, "the cause"}},
		{&CSRKeyMismatchError{KeyID: "rpi/fleet"}, true, []string{`"rpi/fleet"`}},
		{&KMSUnavailableError{}, false, []string{"no KMS"}},
		{&KMSPublicKeyError{KeyID: "rpi/fleet", Err: cause}, false, []string{`"rpi/fleet"`, "the cause"}},
		{&SignCSRError{CommonName: "rpi/fleet", Err: cause}, false, []string{"rpi/fleet", "the cause"}},
	}
	for _, tc := range cases {
		msg := tc.err.Error()
		for _, want := range tc.says {
			if !strings.Contains(msg, want) {
				t.Errorf("%T: %q does not say %q", tc.err, msg, want)
			}
		}
		if got := IsInvalidRequest(tc.err); got != tc.invalid {
			t.Errorf("%T: IsInvalidRequest = %v, want %v", tc.err, got, tc.invalid)
		}
		if strings.Contains(msg, "the cause") && !errors.Is(tc.err, cause) {
			t.Errorf("%T does not unwrap to its cause", tc.err)
		}
	}
}

func TestIsInvalidRequest_RejectsAForeignError(t *testing.T) {
	if IsInvalidRequest(errors.New("a transport failure")) {
		t.Error("an error this package did not make is not the caller's")
	}
	if IsInvalidRequest(nil) {
		t.Error("no error is not an invalid request")
	}
}
