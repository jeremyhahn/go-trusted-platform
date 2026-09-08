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

package tunnel

import "context"

// KeyProvider resolves a key reference to key material. The platform
// implementation is backed by the quicbaas SDK KMS; configuration carries
// only the reference (handbook configuration.md §4 — secrets are references,
// never values). Callers zeroize what they receive as soon as the kernel
// holds it.
type KeyProvider interface {
	// Key returns the material behind ref. The slice belongs to the caller.
	Key(ctx context.Context, ref string) ([]byte, error)
}

// zeroize overwrites key material once it has been handed to the kernel.
// The caller's slice may still be referenced by netlink message buffers
// that have already been sent; this clears the copy we own.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// fetchKey resolves ref through provider and checks the length the
// transport needs, so a short or empty key is refused before any state is
// programmed.
func fetchKey(ctx context.Context, provider KeyProvider, name, ref string, want int) ([]byte, error) {
	if provider == nil {
		return nil, &ErrKeyProviderRequired{Name: name}
	}
	material, err := provider.Key(ctx, ref)
	if err != nil {
		return nil, &ErrKeyMaterial{Name: name, KeyRef: ref, Reason: "resolve", Cause: err}
	}
	if len(material) != want {
		zeroize(material)
		return nil, &ErrKeyMaterial{Name: name, KeyRef: ref, Reason: "material must be exactly " + itoa(want) + " bytes"}
	}
	return material, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
