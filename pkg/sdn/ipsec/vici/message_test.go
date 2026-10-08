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

package vici

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestMessageWireFormat pins the encoding to the README's element layout,
// so a regression cannot hide behind a symmetric encode/decode bug.
func TestMessageWireFormat(t *testing.T) {
	inner := NewMessage()
	inner.SetList("l", "x")
	m := NewMessage()
	m.SetValue("a", "b")
	m.SetSection("s", inner)

	got, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	want := []byte{
		3, 1, 'a', 0, 1, 'b', // key-value a=b
		1, 1, 's', // section s
		4, 1, 'l', 5, 0, 1, 'x', 6, // list l [x]
		2, // section end
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding = %v, want %v", got, want)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	der := []byte{0x30, 0x82, 0x00, 0xff, 0x00}
	child := NewMessage()
	child.SetValue("mode", "transport")
	child.SetList("esp_proposals", "aes256gcm16-x25519-esn")
	children := NewMessage()
	children.SetSection("vxlan", child)
	conn := NewMessage()
	conn.SetList("local_addrs", "10.0.0.1")
	conn.SetSection("children", children)
	m := NewMessage()
	m.SetSection("vtep-10.0.0.2", conn)
	m.SetBytes("data", der)
	m.SetList("empty")

	raw, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var got Message
	if err := got.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	if keys := got.Keys(); !slices.Equal(keys, []string{"vtep-10.0.0.2", "data", "empty"}) {
		t.Fatalf("keys = %v, want insertion order", keys)
	}
	if b, ok := got.Bytes("data"); !ok || !bytes.Equal(b, der) {
		t.Fatalf("data = %v, %v; want the DER bytes unchanged", b, ok)
	}
	if l, ok := got.List("empty"); !ok || len(l) != 0 {
		t.Fatalf("empty list = %v, %v", l, ok)
	}
	c, ok := got.Section("vtep-10.0.0.2")
	if !ok {
		t.Fatal("connection section missing")
	}
	if addrs, _ := c.List("local_addrs"); !slices.Equal(addrs, []string{"10.0.0.1"}) {
		t.Fatalf("local_addrs = %v", addrs)
	}
	chs, _ := c.Section("children")
	ch, _ := chs.Section("vxlan")
	if mode, _ := ch.Value("mode"); mode != "transport" {
		t.Fatalf("mode = %q, want transport", mode)
	}
}

func TestMessageSetReplacesInPlace(t *testing.T) {
	m := NewMessage()
	m.SetValue("a", "1")
	m.SetValue("b", "2")
	m.SetList("a", "3", "4")

	if keys := m.Keys(); !slices.Equal(keys, []string{"a", "b"}) {
		t.Fatalf("keys = %v, want [a b]", keys)
	}
	if _, ok := m.Value("a"); ok {
		t.Fatal("a still reads as a value after being replaced by a list")
	}
	if l, _ := m.List("a"); !slices.Equal(l, []string{"3", "4"}) {
		t.Fatalf("a = %v", l)
	}
}

func TestMessageAccessorsRejectWrongKind(t *testing.T) {
	m := NewMessage()
	m.SetValue("v", "x")
	m.SetList("l", "x")
	m.SetSection("s", nil)

	if _, ok := m.Section("v"); ok {
		t.Error("Section(v) succeeded on a value")
	}
	if _, ok := m.List("s"); ok {
		t.Error("List(s) succeeded on a section")
	}
	if _, ok := m.Bytes("l"); ok {
		t.Error("Bytes(l) succeeded on a list")
	}
	if _, ok := m.Value("missing"); ok {
		t.Error("Value(missing) succeeded")
	}
	if s, ok := m.Section("s"); !ok || s.Len() != 0 {
		t.Errorf("Section(s) = %v, %v; want an empty section", s, ok)
	}

	var nilMsg *Message
	if nilMsg.Has("x") || nilMsg.Len() != 0 || nilMsg.Keys() != nil {
		t.Error("a nil message is not empty")
	}
}

func TestMessageZeroValueIsUsable(t *testing.T) {
	var m Message
	m.SetValue("k", "v")
	if v, ok := m.Value("k"); !ok || v != "v" {
		t.Fatalf("zero-value message lost its key: %q, %v", v, ok)
	}
}

func TestMarshalRejectsOversizedElements(t *testing.T) {
	tests := []struct {
		name  string
		build func() *Message
		key   string
	}{
		{
			name:  "empty key",
			build: func() *Message { m := NewMessage(); m.SetValue("", "x"); return m },
			key:   "",
		},
		{
			name:  "key over 255 bytes",
			build: func() *Message { m := NewMessage(); m.SetValue(strings.Repeat("k", 256), "x"); return m },
			key:   strings.Repeat("k", 256),
		},
		{
			name: "value over 65535 bytes in a section",
			build: func() *Message {
				s := NewMessage()
				s.SetBytes("data", make([]byte, 65536))
				m := NewMessage()
				m.SetSection("outer", s)
				return m
			},
			key: "outer.data",
		},
		{
			name: "list item over 65535 bytes",
			build: func() *Message {
				m := NewMessage()
				m.SetBytesList("certs", []byte("ok"), make([]byte, 65536))
				return m
			},
			key: "certs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.build().MarshalBinary()
			var encErr *EncodeError
			if !errors.As(err, &encErr) {
				t.Fatalf("err = %v, want *EncodeError", err)
			}
			if encErr.Key != tt.key {
				t.Fatalf("EncodeError.Key = %q, want %q", encErr.Key, tt.key)
			}
		})
	}
}

func TestMarshalAcceptsLimits(t *testing.T) {
	m := NewMessage()
	m.SetBytes(strings.Repeat("k", 255), make([]byte, 65535))
	raw, err := m.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary at the limits: %v", err)
	}
	var got Message
	if err := got.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if b, _ := got.Bytes(strings.Repeat("k", 255)); len(b) != 65535 {
		t.Fatalf("value length = %d, want 65535", len(b))
	}
}

func TestUnmarshalRejectsMalformed(t *testing.T) {
	deep := []byte{}
	for range maxDepth + 2 {
		deep = append(deep, 1, 1, 's')
	}
	tests := []struct {
		name string
		data []byte
	}{
		{"unknown element", []byte{9}},
		{"truncated name length", []byte{3}},
		{"empty name", []byte{3, 0}},
		{"truncated name", []byte{3, 5, 'a'}},
		{"truncated value length", []byte{3, 1, 'a', 0}},
		{"truncated value", []byte{3, 1, 'a', 0, 4, 'x'}},
		{"section not closed", []byte{1, 1, 's', 3, 1, 'a', 0, 0}},
		{"section end outside a section", []byte{3, 1, 'a', 0, 0, 2}},
		{"list not closed", []byte{4, 1, 'l', 5, 0, 0}},
		{"key-value inside a list", []byte{4, 1, 'l', 3, 1, 'a', 0, 0, 6}},
		{"nesting too deep", deep},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m Message
			var decErr *DecodeError
			if err := m.UnmarshalBinary(tt.data); !errors.As(err, &decErr) {
				t.Fatalf("err = %v, want *DecodeError", err)
			}
		})
	}
}

func TestUnmarshalCopiesValues(t *testing.T) {
	raw := []byte{3, 1, 'a', 0, 1, 'b'}
	var m Message
	if err := m.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	raw[5] = 'z'
	if v, _ := m.Value("a"); v != "b" {
		t.Fatalf("value aliased the input buffer: %q", v)
	}
}
