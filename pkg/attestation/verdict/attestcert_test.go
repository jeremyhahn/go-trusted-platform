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

package verdict

import (
	"errors"
	"testing"
)

func TestAttestCertEvent_ValidateAcceptsConsistentEvents(t *testing.T) {
	for name, ev := range map[string]AttestCertEvent{
		"recorded": {DeviceID: 1, Recorded: true, Source: "ca", Subject: "CN=x"},
		"refused":  {DeviceID: 1, Reason: "does not chain"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ev.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestAttestCertEvent_ValidateRefusesInconsistentEvents(t *testing.T) {
	for name, ev := range map[string]AttestCertEvent{
		"no device id":            {Recorded: true, Source: "ca"},
		"recorded with reason":    {DeviceID: 1, Recorded: true, Source: "ca", Reason: "x"},
		"recorded without source": {DeviceID: 1, Recorded: true},
		"refused without reason":  {DeviceID: 1},
	} {
		t.Run(name, func(t *testing.T) {
			err := ev.Validate()
			var invalid ErrInvalidVerdict
			if !errors.As(err, &invalid) {
				t.Fatalf("want ErrInvalidVerdict, got %v", err)
			}
		})
	}
}
