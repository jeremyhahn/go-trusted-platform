// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package memguard

import (
	"errors"
	"testing"
)

// cov964FnError is the error a borrow callback returns, so a test can prove
// Open hands the callback's own error back to the caller unchanged.
type cov964FnError struct{}

func (cov964FnError) Error() string { return "cov964 callback failed" }

// TestCov964NewRandomMemoryEnclaveSize covers the size contract: a negative
// size is refused with a typed error, and a zero size is a live, empty
// enclave rather than a construction failure.
func TestCov964NewRandomMemoryEnclaveSize(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		wantErr   bool
		wantAlive bool
	}{
		{name: "negative size is refused", size: -1, wantErr: true},
		{name: "zero size is a live empty enclave", size: 0, wantAlive: true},
		{name: "positive size is a live enclave", size: 16, wantAlive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewRandomMemoryEnclave(tt.size)
			if tt.wantErr {
				var sizeErr ErrInvalidSize
				if !errors.As(err, &sizeErr) {
					t.Fatalf("NewRandomMemoryEnclave(%d) error = %v, want ErrInvalidSize", tt.size, err)
				}
				if sizeErr.Size != tt.size {
					t.Errorf("ErrInvalidSize.Size = %d, want %d", sizeErr.Size, tt.size)
				}
				if e != nil {
					t.Errorf("NewRandomMemoryEnclave(%d) returned an enclave with an error", tt.size)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRandomMemoryEnclave(%d) error = %v", tt.size, err)
			}
			defer e.Destroy()
			if e.IsAlive() != tt.wantAlive {
				t.Errorf("IsAlive() = %v, want %v", e.IsAlive(), tt.wantAlive)
			}
			if e.Size() != tt.size {
				t.Errorf("Size() = %d, want %d", e.Size(), tt.size)
			}
		})
	}
}

// TestCov964OpenEmptyEnclave proves a zero-length enclave lends its callback
// a non-nil empty slice, and that the callback's error reaches the caller.
func TestCov964OpenEmptyEnclave(t *testing.T) {
	tests := []struct {
		name    string
		enclave func(t *testing.T) *MemoryEnclave
	}{
		{
			name:    "empty bytes",
			enclave: func(t *testing.T) *MemoryEnclave { return NewMemoryEnclave(nil) },
		},
		{
			name: "zero-size random",
			enclave: func(t *testing.T) *MemoryEnclave {
				e, err := NewRandomMemoryEnclave(0)
				if err != nil {
					t.Fatalf("NewRandomMemoryEnclave(0) error = %v", err)
				}
				return e
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.enclave(t)
			defer e.Destroy()

			var lent []byte
			if err := e.Open(func(b []byte) error {
				lent = b
				return nil
			}); err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if lent == nil || len(lent) != 0 {
				t.Errorf("Open() lent %v, want a non-nil empty slice", lent)
			}

			err := e.Open(func([]byte) error { return cov964FnError{} })
			if !errors.As(err, new(cov964FnError)) {
				t.Errorf("Open() error = %v, want the callback's cov964FnError", err)
			}
		})
	}
}
