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

package entities

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"regexp"
	"testing"
)

func TestEKNodeIdentity(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("stable, distinct per key and a DNS label", func(t *testing.T) {
		label := regexp.MustCompile(`^ek-[0-9a-f]{32}$`)
		first, err := EKNodeIdentity(&ecKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		again, err := EKNodeIdentity(&ecKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		other, err := EKNodeIdentity(&otherKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		withRSA, err := EKNodeIdentity(&rsaKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if first != again {
			t.Fatalf("identity not stable: %q then %q", first, again)
		}
		if first == other || first == withRSA {
			t.Fatalf("distinct EKs share identity %q", first)
		}
		for _, id := range []string{first, other, withRSA} {
			if !label.MatchString(id) || !IsEKNodeIdentity(id) {
				t.Fatalf("identity %q is not an EK node identity label", id)
			}
		}
	})

	t.Run("an unsupported key is refused", func(t *testing.T) {
		_, err := EKNodeIdentity(struct{}{})
		var invalid ErrEKPublicKeyInvalid
		if !errors.As(err, &invalid) || invalid.Cause == nil {
			t.Fatalf("err = %v, want ErrEKPublicKeyInvalid with a cause", err)
		}
		if !errors.Is(err, invalid.Cause) {
			t.Fatal("the cause must stay reachable through Unwrap")
		}
	})

	t.Run("a nil key is refused", func(t *testing.T) {
		_, err := EKNodeIdentity(nil)
		var invalid ErrEKPublicKeyInvalid
		if !errors.As(err, &invalid) {
			t.Fatalf("err = %v, want ErrEKPublicKeyInvalid", err)
		}
	})
}

func TestIsEKNodeIdentity(t *testing.T) {
	for _, name := range []string{"node-01", "", "ek", "EK-0123", "r640-compute-01"} {
		if IsEKNodeIdentity(name) {
			t.Fatalf("IsEKNodeIdentity(%q) = true, want false", name)
		}
	}
	if !IsEKNodeIdentity("ek-0123") {
		t.Fatal(`IsEKNodeIdentity("ek-0123") = false, want true`)
	}
}
