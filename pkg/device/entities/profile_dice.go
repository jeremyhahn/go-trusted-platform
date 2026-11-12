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
	"encoding/hex"
	"fmt"
)

const (
	// MaxDICEDeviceIDBytes is the largest DICE device id a profile accepts,
	// in bytes (128 hex digits).
	MaxDICEDeviceIDBytes = 64

	// GoldenFWHashBytes is the length of a golden firmware hash (FWHash),
	// in bytes (64 hex digits).
	GoldenFWHashBytes = 32

	// DICEReasonBadLength reports a value of the wrong length.
	DICEReasonBadLength = "bad length"
	// DICEReasonNotHex reports a value that is not hex.
	DICEReasonNotHex = "not hex"
)

// ErrInvalidDICEDeviceID reports a DeviceProfile.DICEDeviceID that is not
// 1 to MaxDICEDeviceIDBytes bytes of hex.
type ErrInvalidDICEDeviceID struct {
	Value  string
	Reason string
}

func (e ErrInvalidDICEDeviceID) Error() string {
	return fmt.Sprintf("invalid DICE device id %q: %s (want 1 to %d bytes of hex)", e.Value, e.Reason, MaxDICEDeviceIDBytes)
}

// ErrInvalidGoldenFWHash reports a DeviceProfile.GoldenFWHash that is not
// exactly GoldenFWHashBytes bytes of hex.
type ErrInvalidGoldenFWHash struct {
	Value  string
	Reason string
}

func (e ErrInvalidGoldenFWHash) Error() string {
	return fmt.Sprintf("invalid golden firmware hash %q: %s (want %d bytes of hex)", e.Value, e.Reason, GoldenFWHashBytes)
}

// ValidateDICEFields checks DICEDeviceID and GoldenFWHash. Both are
// optional; a set value must be hex of the documented length.
func (p *DeviceProfile) ValidateDICEFields() error {
	if p.DICEDeviceID != "" {
		if reason := hexReason(p.DICEDeviceID, 1, MaxDICEDeviceIDBytes); reason != "" {
			return ErrInvalidDICEDeviceID{Value: p.DICEDeviceID, Reason: reason}
		}
	}
	if p.GoldenFWHash != "" {
		if reason := hexReason(p.GoldenFWHash, GoldenFWHashBytes, GoldenFWHashBytes); reason != "" {
			return ErrInvalidGoldenFWHash{Value: p.GoldenFWHash, Reason: reason}
		}
	}
	return nil
}

// hexReason returns "" when s is hex of minBytes to maxBytes bytes, else
// the reason it is not.
func hexReason(s string, minBytes, maxBytes int) string {
	if len(s)%2 != 0 || len(s)/2 < minBytes || len(s)/2 > maxBytes {
		return DICEReasonBadLength
	}
	if _, err := hex.DecodeString(s); err != nil {
		return DICEReasonNotHex
	}
	return ""
}
