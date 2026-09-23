// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package secrets

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorMessagesNameTheReference(t *testing.T) {
	cause := errors.New("cause")
	cases := []struct {
		err  error
		want []string
	}{
		{&ErrRefInvalid{Ref: "kms://x", Reason: "bad"}, []string{"kms://x", "bad"}},
		{&ErrSchemeUnsupported{Ref: "hunter2"}, []string{"hunter2", "not a secret reference"}},
		{&ErrSchemeUnsupported{Ref: "env://X", Scheme: "env"}, []string{"env://X", "scheme env"}},
		{&ErrStoreUnavailable{Cause: cause}, []string{"store unavailable", "cause"}},
		{&ErrSecretUnresolvable{Ref: "kms://x", Cause: cause}, []string{"kms://x", "cause"}},
		{&ErrSecretEmpty{Ref: "kms://x"}, []string{"kms://x", "empty"}},
		{&ErrFieldMissing{Ref: "kms://x", Field: "f"}, []string{"kms://x", "no field f"}},
		{&ErrFieldAmbiguous{Ref: "kms://x", Fields: []string{"a", "b"}}, []string{"kms://x", "a, b", "#<field>"}},
		{&ErrFieldNotText{Ref: "kms://x", Field: "f"}, []string{"kms://x", "field f is not text"}},
		{&ErrEncodingInvalid{Ref: "kms://x", Encoding: "hex", Cause: cause}, []string{"kms://x", "hex", "cause"}},
		{&ErrConfigInvalid{Field: "quicbaas-addr", Reason: "required"}, []string{"quicbaas-addr", "required"}},
		{&ErrNilDialFunc{}, []string{"nil dial"}},
		{&ErrNilSecretsClient{}, []string{"no secrets service"}},
		{&ErrTrustRequired{}, []string{"platform-ca-file:"}},
	}
	for _, tc := range cases {
		msg := tc.err.Error()
		for _, w := range tc.want {
			if !strings.Contains(msg, w) {
				t.Fatalf("%T: %q lacks %q", tc.err, msg, w)
			}
		}
	}
}

func TestErrorsUnwrapTheirCause(t *testing.T) {
	cause := errors.New("cause")
	for _, err := range []error{
		&ErrStoreUnavailable{Cause: cause},
		&ErrSecretUnresolvable{Ref: "kms://x", Cause: cause},
		&ErrEncodingInvalid{Ref: "kms://x", Encoding: "hex", Cause: cause},
	} {
		if !errors.Is(err, cause) {
			t.Fatalf("%T does not unwrap to its cause", err)
		}
	}
}
