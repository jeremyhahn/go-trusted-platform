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

package fips

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// TestAlgorithmErrorMessages asserts every typed algorithm error names the
// values the operator needs to correct the request: the rejected input and
// what would have been accepted instead.
func TestAlgorithmErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want []string
	}{
		{
			name: "kdf not approved",
			err:  ErrKDFNotApproved{KDF: "argon2id", Approved: KDFPBKDF2},
			want: []string{`"argon2id"`, `"` + KDFPBKDF2 + `"`, "not FIPS 140-3 approved"},
		},
		{
			name: "hash not approved",
			err:  ErrHashNotApproved{Hash: "sha1", Approved: []string{"sha256", "sha512"}},
			want: []string{`"sha1"`, "[sha256 sha512]", "not FIPS 140-3 approved"},
		},
		{
			name: "unknown kdf",
			err:  ErrUnknownKDF{KDF: "scrypt"},
			want: []string{`unknown key-derivation function "scrypt"`},
		},
		{
			name: "unknown hash",
			err:  ErrUnknownHash{Hash: "md4"},
			want: []string{`unknown hash algorithm "md4"`},
		},
		{
			name: "hash unsupported by luks",
			err:  ErrHashUnsupportedByLUKS{Hash: "sha384", Supported: []string{"sha256", "sha512"}},
			want: []string{`"sha384"`, "[sha256 sha512]", "anti-forensic splitter"},
		},
		{
			name: "qualified kdf hash conflict",
			err:  ErrQualifiedKDFHashConflict{KDF: "pbkdf2-sha512", Hash: "sha256", ImpliedPRF: "sha512"},
			want: []string{
				`KDF "pbkdf2-sha512" implies PRF "sha512"`,
				`hash "sha256" was also specified`,
				`Specify KDF "` + KDFPBKDF2 + `"`,
			},
		},
		{
			name: "indicator unreadable",
			err:  ErrFIPSIndicatorUnreadable{Path: "/proc/sys/crypto/fips_enabled", Cause: fs.ErrPermission},
			want: []string{"/proc/sys/crypto/fips_enabled", fs.ErrPermission.Error()},
		},
		{
			name: "indicator malformed",
			err:  ErrFIPSIndicatorMalformed{Path: "/proc/sys/crypto/fips_enabled", Contents: "yes"},
			want: []string{"/proc/sys/crypto/fips_enabled", `holds "yes"`, `expected "0" or "1"`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("Error() = %q, missing %q", msg, w)
				}
			}
		})
	}
}

// TestFIPSIndicatorUnreadableUnwrap asserts the read failure stays reachable
// through errors.Is, so a caller can tell a permission problem from I/O.
func TestFIPSIndicatorUnreadableUnwrap(t *testing.T) {
	err := error(ErrFIPSIndicatorUnreadable{Path: "/x", Cause: fs.ErrPermission})
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("errors.Is(%v, fs.ErrPermission) = false, want true", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("errors.Is(%v, fs.ErrNotExist) = true, want false", err)
	}

	noCause := ErrFIPSIndicatorUnreadable{Path: "/x"}
	if noCause.Unwrap() != nil {
		t.Fatalf("Unwrap() with no cause = %v, want nil", noCause.Unwrap())
	}
}
