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

package memguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNew_WipesSourceAndStoresValue(t *testing.T) {
	src := []byte("hunter2")
	want := append([]byte(nil), src...)

	s := New(src)
	defer s.Destroy()

	if !s.IsAlive() {
		t.Fatal("Secret not alive after New")
	}
	if got := s.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("Bytes() = %q, want %q", got, want)
	}
	if s.Size() != len(want) {
		t.Errorf("Size() = %d, want %d", s.Size(), len(want))
	}
	for i, b := range src {
		if b != 0 {
			t.Errorf("source byte %d = %x, want 0 (memguard should wipe)", i, b)
		}
	}
}

func TestNew_EmptyInput(t *testing.T) {
	s := New(nil)
	defer s.Destroy()

	if !s.IsAlive() {
		t.Fatal("empty Secret not alive")
	}
	if s.Size() != 0 {
		t.Errorf("Size() = %d, want 0", s.Size())
	}
}

func TestNewFromString(t *testing.T) {
	s := NewFromString("password123")
	defer s.Destroy()

	if got := string(s.Bytes()); got != "password123" {
		t.Errorf("Bytes() = %q, want %q", got, "password123")
	}
}

func TestNewFromString_Empty(t *testing.T) {
	s := NewFromString("")
	defer s.Destroy()

	if s.Size() != 0 {
		t.Errorf("Size() = %d, want 0", s.Size())
	}
}

func TestNewRandom(t *testing.T) {
	s, err := NewRandom(32)
	if err != nil {
		t.Fatalf("NewRandom(32): %v", err)
	}
	defer s.Destroy()

	if s.Size() != 32 {
		t.Errorf("Size() = %d, want 32", s.Size())
	}
	all := s.Bytes()
	zero := true
	for _, b := range all {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		t.Error("NewRandom returned all-zero buffer")
	}
}

func TestNewRandom_NegativeSize(t *testing.T) {
	_, err := NewRandom(-1)
	var want ErrInvalidSize
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrInvalidSize", err)
	}
	if want.Size != -1 {
		t.Errorf("err.Size = %d, want -1", want.Size)
	}
}

func TestDestroy_Idempotent(t *testing.T) {
	s := New([]byte("x"))
	s.Destroy()
	s.Destroy() // must not panic
	if s.IsAlive() {
		t.Error("IsAlive() = true after Destroy")
	}
}

func TestDestroy_NilReceiver(t *testing.T) {
	var s *Secret
	s.Destroy()
	if s.IsAlive() {
		t.Error("nil Secret reported alive")
	}
	if s.Size() != 0 {
		t.Error("nil Secret size != 0")
	}
	if s.Bytes() != nil {
		t.Error("nil Secret Bytes != nil")
	}
}

func TestBytes_AfterDestroy(t *testing.T) {
	s := New([]byte("x"))
	s.Destroy()
	if got := s.Bytes(); got != nil {
		t.Errorf("Bytes() after Destroy = %v, want nil", got)
	}
}

func TestWithBytes(t *testing.T) {
	s := New([]byte("api-key"))
	defer s.Destroy()

	called := false
	err := s.WithBytes(func(b []byte) error {
		called = true
		if string(b) != "api-key" {
			return fmt.Errorf("unexpected: %q", b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if !called {
		t.Error("fn not invoked")
	}
}

func TestWithBytes_PropagatesError(t *testing.T) {
	s := New([]byte("x"))
	defer s.Destroy()

	sentinel := errors.New("boom")
	err := s.WithBytes(func(b []byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want %v", err, sentinel)
	}
}

func TestWithBytes_AfterDestroy(t *testing.T) {
	s := New([]byte("x"))
	s.Destroy()

	err := s.WithBytes(func(b []byte) error { return nil })
	var want ErrDestroyed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrDestroyed", err)
	}
}

func TestWithBytes_NilReceiver(t *testing.T) {
	var s *Secret
	err := s.WithBytes(func(b []byte) error { return nil })
	var want ErrDestroyed
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrDestroyed", err)
	}
}

func TestEqual(t *testing.T) {
	cases := []struct {
		name string
		a, b *Secret
		want bool
	}{
		{"both alive equal", New([]byte("xyz")), New([]byte("xyz")), true},
		{"both alive differ", New([]byte("xyz")), New([]byte("abc")), false},
		{"both alive diff length", New([]byte("xy")), New([]byte("xyz")), false},
		{"both nil", nil, nil, true},
		{"nil vs live", nil, New([]byte("x")), false},
		{"live vs nil", New([]byte("x")), nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Equal(tc.b); got != tc.want {
				t.Errorf("Equal() = %v, want %v", got, tc.want)
			}
			if tc.a != nil {
				tc.a.Destroy()
			}
			if tc.b != nil {
				tc.b.Destroy()
			}
		})
	}
}

func TestEqual_DestroyedPair(t *testing.T) {
	a := New([]byte("x"))
	b := New([]byte("x"))
	a.Destroy()
	b.Destroy()
	if !a.Equal(b) {
		t.Error("two destroyed secrets should compare equal")
	}
}

func TestEqualBytes(t *testing.T) {
	s := New([]byte("token"))
	defer s.Destroy()

	if !s.EqualBytes([]byte("token")) {
		t.Error("EqualBytes(equal) = false")
	}
	if s.EqualBytes([]byte("other")) {
		t.Error("EqualBytes(diff) = true")
	}
}

func TestEqualBytes_AfterDestroy(t *testing.T) {
	s := New([]byte("x"))
	s.Destroy()
	if s.EqualBytes([]byte("x")) {
		t.Error("EqualBytes on destroyed secret returned true")
	}
}

func TestString_Redacted(t *testing.T) {
	s := New([]byte("super-sensitive"))
	defer s.Destroy()

	if got := s.String(); got != redactedPlaceholder {
		t.Errorf("String() = %q, want %q", got, redactedPlaceholder)
	}
	if strings.Contains(fmt.Sprintf("%v", s), "super-sensitive") {
		t.Error("fmt verb v leaked secret value")
	}
	if strings.Contains(s.String(), "super-sensitive") {
		t.Error("fmt verb s leaked secret value")
	}
}

func TestMarshalJSON_Redacted(t *testing.T) {
	s := New([]byte("api-key-value"))
	defer s.Destroy()

	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != `"[REDACTED]"` {
		t.Errorf("MarshalJSON = %s, want \"[REDACTED]\"", out)
	}
	if strings.Contains(string(out), "api-key-value") {
		t.Error("MarshalJSON leaked secret value")
	}
}

func TestMarshalJSON_NestedInStruct(t *testing.T) {
	type cred struct {
		User string  `json:"user"`
		Pass *Secret `json:"pass"`
	}
	c := cred{User: "alice", Pass: New([]byte("p@ss"))}
	defer c.Pass.Destroy()

	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"user":"alice","pass":"[REDACTED]"}`
	if string(out) != want {
		t.Errorf("got %s, want %s", out, want)
	}
}

func TestUnmarshalJSON(t *testing.T) {
	var s Secret
	if err := json.Unmarshal([]byte(`"hunter2"`), &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	defer s.Destroy()
	if string(s.Bytes()) != "hunter2" {
		t.Errorf("Bytes() = %q, want hunter2", s.Bytes())
	}
}

func TestUnmarshalJSON_RejectsRedacted(t *testing.T) {
	var s Secret
	err := json.Unmarshal([]byte(`"[REDACTED]"`), &s)
	var want ErrRedactedInput
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRedactedInput", err)
	}
}

func TestUnmarshalJSON_RejectsNonString(t *testing.T) {
	var s Secret
	err := json.Unmarshal([]byte(`123`), &s)
	var want ErrInvalidEncoding
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidEncoding", err)
	}
}

func TestMarshalYAML_Redacted(t *testing.T) {
	s := New([]byte("yaml-secret"))
	defer s.Destroy()

	out, err := yaml.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(out), redactedPlaceholder) {
		t.Errorf("MarshalYAML = %q, want contains %q", out, redactedPlaceholder)
	}
	if strings.Contains(string(out), "yaml-secret") {
		t.Error("MarshalYAML leaked secret value")
	}
}

func TestUnmarshalYAML(t *testing.T) {
	var s Secret
	if err := yaml.Unmarshal([]byte(`pa55w0rd`), &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	defer s.Destroy()
	if string(s.Bytes()) != "pa55w0rd" {
		t.Errorf("Bytes() = %q, want pa55w0rd", s.Bytes())
	}
}

func TestUnmarshalYAML_RejectsRedacted(t *testing.T) {
	var s Secret
	err := yaml.Unmarshal([]byte(`"[REDACTED]"`), &s)
	var want ErrRedactedInput
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrRedactedInput", err)
	}
}

func TestUnmarshalYAML_RejectsBadShape(t *testing.T) {
	var s Secret
	// A YAML mapping cannot decode into a string.
	err := yaml.Unmarshal([]byte("foo:\n  bar: baz\n"), &s)
	var want ErrInvalidEncoding
	if !errors.As(err, &want) {
		t.Errorf("err = %v, want ErrInvalidEncoding", err)
	}
}

func TestErrorMessages(t *testing.T) {
	cases := []struct {
		err      error
		contains string
	}{
		{ErrDestroyed{}, "destroyed"},
		{ErrInvalidSize{Size: -5}, "-5"},
		{ErrInvalidEncoding{Reason: "bad"}, "bad"},
		{ErrRedactedInput{}, "redacted"},
	}
	for _, tc := range cases {
		t.Run(tc.contains, func(t *testing.T) {
			if !strings.Contains(tc.err.Error(), tc.contains) {
				t.Errorf("%T.Error() = %q, want contains %q",
					tc.err, tc.err.Error(), tc.contains)
			}
		})
	}
}
