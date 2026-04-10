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

package util

import (
	"testing"
)

func TestNewID_ValidInput(t *testing.T) {
	// Test with valid input
	input := []byte("test-input-string")
	id := NewID(input)

	if id == 0 {
		t.Error("Expected non-zero ID")
	}

	// Verify deterministic behavior - same input should produce same output
	id2 := NewID(input)
	if id != id2 {
		t.Errorf("Expected deterministic ID generation: got %d and %d", id, id2)
	}
}

func TestNewID_EmptyInput(t *testing.T) {
	// Test with empty input
	input := []byte{}
	id := NewID(input)

	// Empty input should still produce a valid hash
	if id == 0 {
		t.Error("Expected non-zero ID even for empty input")
	}

	// Verify consistency
	id2 := NewID(input)
	if id != id2 {
		t.Errorf("Expected deterministic ID generation for empty input: got %d and %d", id, id2)
	}
}

func TestNewID_DifferentInputs(t *testing.T) {
	// Test that different inputs produce different IDs
	input1 := []byte("input-one")
	input2 := []byte("input-two")

	id1 := NewID(input1)
	id2 := NewID(input2)

	if id1 == id2 {
		t.Error("Expected different IDs for different inputs")
	}
}

func TestNewID_NilInput(t *testing.T) {
	// Test with nil input
	var input []byte = nil
	id := NewID(input)

	// Nil input should still produce a valid hash
	if id == 0 {
		t.Error("Expected non-zero ID even for nil input")
	}
}
