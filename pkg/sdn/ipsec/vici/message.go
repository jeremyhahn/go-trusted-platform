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

// Package vici is a client for strongSwan's Versatile IKE Control Interface,
// the socket protocol charon is configured and driven through (strongSwan
// src/libcharon/plugins/vici/README.md). It speaks the protocol directly:
// length-prefixed packets carrying commands, responses and events, whose
// payload is a tree of key/value pairs, lists and sections.
package vici

import (
	"encoding/binary"
	"strconv"
)

// Message element types (README, "Message format").
const (
	elementSectionStart byte = 1
	elementSectionEnd   byte = 2
	elementKeyValue     byte = 3
	elementListStart    byte = 4
	elementListItem     byte = 5
	elementListEnd      byte = 6
)

// Encoding limits. A name carries an 8-bit length and a value a 16-bit one.
const (
	maxNameLength  = 255
	maxValueLength = 65535

	// maxDepth bounds section nesting when decoding, so a hostile peer
	// cannot drive the decoder into unbounded recursion. charon's deepest
	// messages (list-sas) nest four levels.
	maxDepth = 32
)

// entryKind says what an entry of a Message holds.
type entryKind uint8

const (
	kindValue entryKind = iota
	kindList
	kindSection
)

// entry is one keyed element of a Message.
type entry struct {
	key     string
	kind    entryKind
	value   []byte
	list    [][]byte
	section *Message
}

// Message is a VICI message: an ordered set of keys, each holding a value,
// a list of values or a nested section. Keys are unique; setting a key
// again replaces its entry in place. Values are byte strings, so binary
// data (DER certificates and CRLs) travels unencoded.
//
// A Message holds the slices it is given without copying them, so a
// caller that sets a secret (a PIN) can wipe its slice once the message
// has been sent.
type Message struct {
	entries []entry
	index   map[string]int
}

// NewMessage returns an empty message.
func NewMessage() *Message {
	return &Message{index: make(map[string]int)}
}

// set adds or replaces the entry for e.key.
func (m *Message) set(e entry) {
	if m.index == nil {
		m.index = make(map[string]int)
	}
	if i, ok := m.index[e.key]; ok {
		m.entries[i] = e
		return
	}
	m.index[e.key] = len(m.entries)
	m.entries = append(m.entries, e)
}

// SetValue sets key to a string value.
func (m *Message) SetValue(key, value string) {
	m.set(entry{key: key, kind: kindValue, value: []byte(value)})
}

// SetBytes sets key to a byte-string value. The slice is held, not copied.
func (m *Message) SetBytes(key string, value []byte) {
	m.set(entry{key: key, kind: kindValue, value: value})
}

// SetList sets key to a list of string values.
func (m *Message) SetList(key string, values ...string) {
	list := make([][]byte, len(values))
	for i, v := range values {
		list[i] = []byte(v)
	}
	m.set(entry{key: key, kind: kindList, list: list})
}

// SetBytesList sets key to a list of byte-string values. The slices are
// held, not copied.
func (m *Message) SetBytesList(key string, values ...[]byte) {
	m.set(entry{key: key, kind: kindList, list: values})
}

// SetSection sets key to a nested section.
func (m *Message) SetSection(key string, section *Message) {
	if section == nil {
		section = NewMessage()
	}
	m.set(entry{key: key, kind: kindSection, section: section})
}

// lookup returns the entry for key.
func (m *Message) lookup(key string) (entry, bool) {
	if m == nil {
		return entry{}, false
	}
	i, ok := m.index[key]
	if !ok {
		return entry{}, false
	}
	return m.entries[i], true
}

// Has reports whether key is set.
func (m *Message) Has(key string) bool {
	_, ok := m.lookup(key)
	return ok
}

// Value returns key's value as a string; ok is false when key is absent or
// is not a plain value.
func (m *Message) Value(key string) (string, bool) {
	e, ok := m.lookup(key)
	if !ok || e.kind != kindValue {
		return "", false
	}
	return string(e.value), true
}

// Bytes returns key's value; ok is false when key is absent or is not a
// plain value.
func (m *Message) Bytes(key string) ([]byte, bool) {
	e, ok := m.lookup(key)
	if !ok || e.kind != kindValue {
		return nil, false
	}
	return e.value, true
}

// List returns key's list as strings; ok is false when key is absent or is
// not a list.
func (m *Message) List(key string) ([]string, bool) {
	e, ok := m.lookup(key)
	if !ok || e.kind != kindList {
		return nil, false
	}
	out := make([]string, len(e.list))
	for i, v := range e.list {
		out[i] = string(v)
	}
	return out, true
}

// Section returns key's section; ok is false when key is absent or is not
// a section.
func (m *Message) Section(key string) (*Message, bool) {
	e, ok := m.lookup(key)
	if !ok || e.kind != kindSection {
		return nil, false
	}
	return e.section, true
}

// Keys returns the message's keys in order.
func (m *Message) Keys() []string {
	if m == nil {
		return nil
	}
	keys := make([]string, len(m.entries))
	for i, e := range m.entries {
		keys[i] = e.key
	}
	return keys
}

// Len returns the number of keys.
func (m *Message) Len() int {
	if m == nil {
		return 0
	}
	return len(m.entries)
}

// MarshalBinary encodes the message. It fails on a name longer than 255
// bytes, an empty name, or a value longer than 65535 bytes.
func (m *Message) MarshalBinary() ([]byte, error) {
	var b []byte
	return m.appendTo(b, "")
}

// appendTo appends the message's elements to b; path names the enclosing
// sections for error reports.
func (m *Message) appendTo(b []byte, path string) ([]byte, error) {
	if m == nil {
		return b, nil
	}
	var err error
	for _, e := range m.entries {
		key := joinPath(path, e.key)
		switch e.kind {
		case kindValue:
			if b, err = appendName(b, elementKeyValue, e.key, key); err != nil {
				return nil, err
			}
			if b, err = appendValue(b, e.value, key); err != nil {
				return nil, err
			}
		case kindList:
			if b, err = appendName(b, elementListStart, e.key, key); err != nil {
				return nil, err
			}
			for _, item := range e.list {
				b = append(b, elementListItem)
				if b, err = appendValue(b, item, key); err != nil {
					return nil, err
				}
			}
			b = append(b, elementListEnd)
		case kindSection:
			if b, err = appendName(b, elementSectionStart, e.key, key); err != nil {
				return nil, err
			}
			if b, err = e.section.appendTo(b, key); err != nil {
				return nil, err
			}
			b = append(b, elementSectionEnd)
		}
	}
	return b, nil
}

// appendName appends an element type and its length-prefixed name.
func appendName(b []byte, element byte, name, path string) ([]byte, error) {
	if name == "" || len(name) > maxNameLength {
		return nil, &EncodeError{Key: path, Reason: "name length " + strconv.Itoa(len(name)) + " outside 1.." + strconv.Itoa(maxNameLength)}
	}
	b = append(b, element, byte(len(name)))
	return append(b, name...), nil
}

// appendValue appends a 16-bit length-prefixed value.
func appendValue(b, value []byte, path string) ([]byte, error) {
	if len(value) > maxValueLength {
		return nil, &EncodeError{Key: path, Reason: "value length " + strconv.Itoa(len(value)) + " exceeds " + strconv.Itoa(maxValueLength)}
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...), nil
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// UnmarshalBinary decodes an encoded message into m, replacing its
// contents. Values are copied out of data.
func (m *Message) UnmarshalBinary(data []byte) error {
	d := decoder{data: data}
	decoded, err := d.section(0)
	if err != nil {
		return err
	}
	*m = *decoded
	return nil
}

// decoder walks an encoded message.
type decoder struct {
	data []byte
	pos  int
}

// section decodes elements until the matching section end, or the end of
// the data at depth zero.
func (d *decoder) section(depth int) (*Message, error) {
	if depth > maxDepth {
		return nil, &DecodeError{Offset: d.pos, Reason: "sections nested deeper than " + strconv.Itoa(maxDepth)}
	}
	m := NewMessage()
	for d.pos < len(d.data) {
		start := d.pos
		element := d.data[d.pos]
		d.pos++
		switch element {
		case elementSectionEnd:
			if depth == 0 {
				return nil, &DecodeError{Offset: start, Reason: "section end outside a section"}
			}
			return m, nil
		case elementKeyValue:
			name, err := d.name()
			if err != nil {
				return nil, err
			}
			value, err := d.value()
			if err != nil {
				return nil, err
			}
			m.set(entry{key: name, kind: kindValue, value: value})
		case elementListStart:
			name, err := d.name()
			if err != nil {
				return nil, err
			}
			list, err := d.list()
			if err != nil {
				return nil, err
			}
			m.set(entry{key: name, kind: kindList, list: list})
		case elementSectionStart:
			name, err := d.name()
			if err != nil {
				return nil, err
			}
			sub, err := d.section(depth + 1)
			if err != nil {
				return nil, err
			}
			m.set(entry{key: name, kind: kindSection, section: sub})
		default:
			return nil, &DecodeError{Offset: start, Reason: "unexpected element type " + strconv.Itoa(int(element))}
		}
	}
	if depth > 0 {
		return nil, &DecodeError{Offset: d.pos, Reason: "section not closed"}
	}
	return m, nil
}

// list decodes list items up to the list end.
func (d *decoder) list() ([][]byte, error) {
	list := [][]byte{}
	for d.pos < len(d.data) {
		element := d.data[d.pos]
		d.pos++
		switch element {
		case elementListItem:
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		case elementListEnd:
			return list, nil
		default:
			return nil, &DecodeError{Offset: d.pos - 1, Reason: "unexpected element type " + strconv.Itoa(int(element)) + " in a list"}
		}
	}
	return nil, &DecodeError{Offset: d.pos, Reason: "list not closed"}
}

// name decodes an 8-bit length-prefixed name.
func (d *decoder) name() (string, error) {
	if d.pos >= len(d.data) {
		return "", &DecodeError{Offset: d.pos, Reason: "truncated name length"}
	}
	n := int(d.data[d.pos])
	d.pos++
	if n == 0 {
		return "", &DecodeError{Offset: d.pos - 1, Reason: "empty name"}
	}
	if d.pos+n > len(d.data) {
		return "", &DecodeError{Offset: d.pos, Reason: "truncated name"}
	}
	name := string(d.data[d.pos : d.pos+n])
	d.pos += n
	return name, nil
}

// value decodes a 16-bit length-prefixed value into a fresh slice.
func (d *decoder) value() ([]byte, error) {
	if d.pos+2 > len(d.data) {
		return nil, &DecodeError{Offset: d.pos, Reason: "truncated value length"}
	}
	n := int(binary.BigEndian.Uint16(d.data[d.pos:]))
	d.pos += 2
	if d.pos+n > len(d.data) {
		return nil, &DecodeError{Offset: d.pos, Reason: "truncated value"}
	}
	v := make([]byte, n)
	copy(v, d.data[d.pos:d.pos+n])
	d.pos += n
	return v, nil
}
