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
	"fmt"
	"math"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// IndexFirst and IndexLast bound the TPM_HT_NV_INDEX handle range
	// (TPM 2.0 Part 2, 7.4): every NV index handle has 0x01 in its top
	// byte. A handle outside it names a PCR, session, transient or
	// persistent object, never an NV index.
	IndexFirst uint32 = 0x01000000
	IndexLast  uint32 = 0x01FFFFFF

	// MaxSpan is the furthest byte an NV command can address. NVRead and
	// NVWrite carry the offset and size as UINT16, so offset+size beyond
	// it would wrap to the start of the index instead of failing.
	MaxSpan = math.MaxUint16
)

// ErrIndexOutOfRange is returned for a handle outside the NV index range.
type ErrIndexOutOfRange struct {
	Index uint32
}

func (e ErrIndexOutOfRange) Error() string {
	return fmt.Sprintf("NV index 0x%08x is outside the NV index range 0x%08x-0x%08x",
		e.Index, IndexFirst, IndexLast)
}

func (e ErrIndexOutOfRange) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrSpanTooLarge is returned when offset+size runs past MaxSpan.
type ErrSpanTooLarge struct {
	Offset uint32
	Size   uint64
}

func (e ErrSpanTooLarge) Error() string {
	return fmt.Sprintf("NV access of %d bytes at offset %d exceeds the %d-byte NV address space",
		e.Size, e.Offset, MaxSpan)
}

func (e ErrSpanTooLarge) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// CheckIndex reports whether index is an NV index handle.
func CheckIndex(index uint32) error {
	if index < IndexFirst || index > IndexLast {
		return ErrIndexOutOfRange{Index: index}
	}
	return nil
}

// CheckSpan reports whether size bytes starting at offset fit in the NV
// address space every NV command shares.
func CheckSpan(offset uint32, size uint64) error {
	if uint64(offset)+size > MaxSpan {
		return ErrSpanTooLarge{Offset: offset, Size: size}
	}
	return nil
}
