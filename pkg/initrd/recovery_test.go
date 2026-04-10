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

package initrd

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestReadUserChoiceValid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"zero", "0\n", 0},
		{"one", "1\n", 1},
		{"six", "6\n", 6},
		{"large_number", "42\n", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Redirect stdin
			oldStdin := os.Stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdin = r

			go func() {
				io.WriteString(w, tt.input)
				w.Close()
			}()

			result, err := readUserChoice()
			os.Stdin = oldStdin

			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestReadUserChoiceInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty_input", "\n"},
		{"not_a_number", "abc\n"},
		{"special_chars", "@#$\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdin := os.Stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdin = r

			go func() {
				io.WriteString(w, tt.input)
				w.Close()
			}()

			_, err = readUserChoice()
			os.Stdin = oldStdin

			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestReadUserChoiceEOF(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdin = r

	// Close writer immediately to simulate EOF
	w.Close()

	_, err = readUserChoice()
	os.Stdin = oldStdin

	if err == nil {
		t.Error("expected error for EOF")
	}
}

func TestConfirmActionYes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"yes_full", "yes\n", true},
		{"y_short", "y\n", true},
		{"YES_upper", "YES\n", true},
		{"Y_upper", "Y\n", true},
		{"no_full", "no\n", false},
		{"n_short", "n\n", false},
		{"empty", "\n", false},
		{"other", "maybe\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdin := os.Stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdin = r

			go func() {
				io.WriteString(w, tt.input)
				w.Close()
			}()

			result, err := confirmAction("test action")
			os.Stdin = oldStdin

			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConfirmActionEOF(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdin = r

	w.Close()

	_, err = confirmAction("test action")
	os.Stdin = oldStdin

	if err == nil {
		t.Error("expected error for EOF")
	}
}

func TestConfirmActionCaseSensitivity(t *testing.T) {
	// Verify that "Yes", "yEs", etc. all work
	inputs := []string{"Yes", "yEs", "yeS", "YeS", "yES"}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			oldStdin := os.Stdin
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			os.Stdin = r

			go func() {
				io.WriteString(w, input+"\n")
				w.Close()
			}()

			result, err := confirmAction("test")
			os.Stdin = oldStdin

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			lower := strings.ToLower(input)
			expected := lower == "yes" || lower == "y"
			if result != expected {
				t.Errorf("for input %q: expected %v, got %v", input, expected, result)
			}
		})
	}
}
