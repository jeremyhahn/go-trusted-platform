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

package tpmnv

import (
	"errors"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// cov964AssertInvalidArgument checks that err converts to a gRPC
// InvalidArgument status carrying want as its message.
func cov964AssertInvalidArgument(t *testing.T, err error, want string) {
	t.Helper()
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("%T does not carry a gRPC status", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("status code = %v, want %v", st.Code(), codes.InvalidArgument)
	}
	if st.Message() != want {
		t.Fatalf("status message = %q, want %q", st.Message(), want)
	}
}

func TestCov964CheckIndexOutsideRangeIsInvalidArgument(t *testing.T) {
	tests := []struct {
		name  string
		index uint32
		want  string
	}{
		{
			name:  "one below the first NV index",
			index: IndexFirst - 1,
			want:  "NV index 0x00ffffff is outside the NV index range 0x01000000-0x01ffffff",
		},
		{
			name:  "one past the last NV index",
			index: IndexLast + 1,
			want:  "NV index 0x02000000 is outside the NV index range 0x01000000-0x01ffffff",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckIndex(tt.index)
			var rangeErr ErrIndexOutOfRange
			if !errors.As(err, &rangeErr) {
				t.Fatalf("CheckIndex(0x%08x) = %v, want ErrIndexOutOfRange", tt.index, err)
			}
			if rangeErr.Index != tt.index {
				t.Fatalf("Index = 0x%08x, want 0x%08x", rangeErr.Index, tt.index)
			}
			cov964AssertInvalidArgument(t, err, tt.want)
		})
	}
}

func TestCov964CheckSpanPastMaxIsInvalidArgument(t *testing.T) {
	tests := []struct {
		name   string
		offset uint32
		size   uint64
		want   string
	}{
		{
			name:   "one byte at the end of the address space",
			offset: MaxSpan,
			size:   1,
			want:   "NV access of 1 bytes at offset 65535 exceeds the 65535-byte NV address space",
		},
		{
			name:   "one byte more than the address space from offset zero",
			offset: 0,
			size:   MaxSpan + 1,
			want:   "NV access of 65536 bytes at offset 0 exceeds the 65535-byte NV address space",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSpan(tt.offset, tt.size)
			var spanErr ErrSpanTooLarge
			if !errors.As(err, &spanErr) {
				t.Fatalf("CheckSpan(%d, %d) = %v, want ErrSpanTooLarge", tt.offset, tt.size, err)
			}
			if spanErr.Offset != tt.offset || spanErr.Size != tt.size {
				t.Fatalf("ErrSpanTooLarge = %+v, want offset %d size %d", spanErr, tt.offset, tt.size)
			}
			cov964AssertInvalidArgument(t, err, tt.want)
		})
	}
}

func TestCov964CheckTargetWithoutTransport(t *testing.T) {
	err := checkTarget(nil, IndexFirst)
	if !errors.As(err, &ErrTransportUnavailable{}) {
		t.Fatalf("checkTarget(nil, valid index) = %v, want ErrTransportUnavailable", err)
	}
}

func TestCov964CheckTargetValidatesIndexBeforeTransport(t *testing.T) {
	err := checkTarget(nil, IndexLast+1)
	if !errors.As(err, &ErrIndexOutOfRange{}) {
		t.Fatalf("checkTarget(nil, out-of-range index) = %v, want ErrIndexOutOfRange", err)
	}
}

func TestCov964AuthHandleHierarchy(t *testing.T) {
	const nvHandle = tpmgo.TPMHandle(IndexFirst + 7)
	name := tpmgo.TPM2BName{Buffer: []byte("cov964-name")}
	password := []byte("cov964-password")

	tests := []struct {
		name       string
		attrs      tpmgo.TPMANV
		wantRead   tpmgo.TPMHandle
		wantWrite  tpmgo.TPMHandle
		wantNVName bool
	}{
		{
			name:      "owner hierarchy without index auth",
			attrs:     tpmgo.TPMANV{OwnerRead: true, OwnerWrite: true},
			wantRead:  tpmgo.TPMRHOwner,
			wantWrite: tpmgo.TPMRHOwner,
		},
		{
			name:      "platform hierarchy",
			attrs:     tpmgo.TPMANV{PPRead: true, PPWrite: true},
			wantRead:  tpmgo.TPMRHPlatform,
			wantWrite: tpmgo.TPMRHPlatform,
		},
		{
			name:       "owner bits with index auth use the index itself",
			attrs:      tpmgo.TPMANV{OwnerRead: true, AuthRead: true, OwnerWrite: true, AuthWrite: true},
			wantRead:   nvHandle,
			wantWrite:  nvHandle,
			wantNVName: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &tpmgo.TPMSNVPublic{NVIndex: nvHandle, Attributes: tt.attrs}
			checks := map[string]struct {
				got  tpmgo.AuthHandle
				want tpmgo.TPMHandle
			}{
				"read":  {got: readAuthHandle(pub, nvHandle, name, password), want: tt.wantRead},
				"write": {got: writeAuthHandle(pub, nvHandle, name, password), want: tt.wantWrite},
			}
			for op, c := range checks {
				if c.got.Handle != c.want {
					t.Fatalf("%s auth handle = 0x%08x, want 0x%08x", op, c.got.Handle, c.want)
				}
				hasName := len(c.got.Name.Buffer) > 0
				if hasName != tt.wantNVName {
					t.Fatalf("%s auth handle carries the NV name = %v, want %v", op, hasName, tt.wantNVName)
				}
				if c.got.Auth == nil {
					t.Fatalf("%s auth handle has no password session", op)
				}
			}
		})
	}
}
