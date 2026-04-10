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
	"math/big"
	"testing"
)

func TestSerialNumber_Success(t *testing.T) {
	serial, err := SerialNumber()
	if err != nil {
		t.Fatalf("SerialNumber() returned error: %v", err)
	}

	if serial == nil {
		t.Fatal("SerialNumber() returned nil")
	}

	// Verify the serial number is positive
	if serial.Sign() <= 0 {
		t.Errorf("Expected positive serial number, got %s", serial.String())
	}

	// Verify the serial number is within valid range (< 2^128)
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	if serial.Cmp(limit) >= 0 {
		t.Errorf("Serial number %s exceeds maximum value", serial.String())
	}
}

func TestSerialNumber_Uniqueness(t *testing.T) {
	// Generate multiple serial numbers and verify they're different
	// While theoretically possible to get duplicates, the probability is astronomically low
	serials := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		serial, err := SerialNumber()
		if err != nil {
			t.Fatalf("SerialNumber() iteration %d returned error: %v", i, err)
		}

		serialStr := serial.String()
		if serials[serialStr] {
			t.Errorf("Duplicate serial number generated: %s", serialStr)
		}
		serials[serialStr] = true
	}

	if len(serials) != iterations {
		t.Errorf("Expected %d unique serial numbers, got %d", iterations, len(serials))
	}
}

func TestSerialNumber_BitLength(t *testing.T) {
	// Test that serial numbers are within the 128-bit range
	for i := 0; i < 10; i++ {
		serial, err := SerialNumber()
		if err != nil {
			t.Fatalf("SerialNumber() iteration %d returned error: %v", i, err)
		}

		bitLen := serial.BitLen()
		if bitLen > 128 {
			t.Errorf("Serial number bit length %d exceeds 128 bits", bitLen)
		}
	}
}
