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
	"bytes"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/tpmnv/tpmnvtest"
)

const testIndex = 0x01500001

var authRW = tpmgo.TPMANV{AuthRead: true, AuthWrite: true, NoDA: true}

func TestWriteRead_RoundTripChunked(t *testing.T) {
	tpm := tpmnvtest.New()
	tpm.Define(testIndex, 1100, authRW, []byte("pw"))
	payload := bytes.Repeat([]byte("0123456789"), 110)

	require.NoError(t, Write(tpm, testIndex, payload, 0, []byte("pw")))

	got, err := Read(tpm, testIndex, 0, 0, []byte("pw"))
	require.NoError(t, err)
	assert.Equal(t, payload, got, "a read spanning three chunks returns every byte written")
}

func TestRead_SizeAndOffset(t *testing.T) {
	tpm := tpmnvtest.New()
	tpm.Define(testIndex, 16, authRW, nil)
	require.NoError(t, Write(tpm, testIndex, []byte("abcdef"), 4, nil))

	got, err := Read(tpm, testIndex, 6, 4, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("abcdef"), got)
}

func TestReadWrite_OwnerHierarchyAuth(t *testing.T) {
	tpm := tpmnvtest.New()
	tpm.OwnerAuth = []byte("owner")
	tpm.Define(testIndex, 4, tpmgo.TPMANV{OwnerRead: true, OwnerWrite: true}, []byte("index-auth"))

	require.NoError(t, Write(tpm, testIndex, []byte("ok"), 0, []byte("owner")))
	got, err := Read(tpm, testIndex, 2, 0, []byte("owner"))
	require.NoError(t, err)
	assert.Equal(t, []byte("ok"), got)

	_, err = Read(tpm, testIndex, 2, 0, []byte("index-auth"))
	assert.Error(t, err, "an OWNERREAD index authorizes against the owner hierarchy, not its own auth")
}

func TestReadWrite_WrongPassword(t *testing.T) {
	tpm := tpmnvtest.New()
	tpm.Define(testIndex, 8, authRW, []byte("pw"))

	assert.Error(t, Write(tpm, testIndex, []byte("x"), 0, []byte("wrong")))
	_, err := Read(tpm, testIndex, 0, 0, nil)
	assert.Error(t, err)
	data, _ := tpm.Data(testIndex)
	assert.Equal(t, make([]byte, 8), data, "a rejected write leaves the index untouched")
}

func TestReadWrite_UndefinedIndex(t *testing.T) {
	tpm := tpmnvtest.New()

	_, err := Read(tpm, testIndex, 0, 0, nil)
	assert.Error(t, err)
	assert.Error(t, Write(tpm, testIndex, []byte("x"), 0, nil))
	assert.Error(t, Undefine(tpm, testIndex, nil))
}

func TestWrite_PastEndOfIndex(t *testing.T) {
	tpm := tpmnvtest.New()
	tpm.Define(testIndex, 4, authRW, nil)

	assert.Error(t, Write(tpm, testIndex, []byte("too long"), 0, nil))
}

func TestUndefine_RemovesIndex(t *testing.T) {
	tpm := tpmnvtest.New()
	tpm.OwnerAuth = []byte("owner")
	tpm.Define(testIndex, 4, authRW, nil)

	assert.Error(t, Undefine(tpm, testIndex, []byte("wrong")))
	_, defined := tpm.Data(testIndex)
	assert.True(t, defined, "a rejected undefine keeps the index")

	require.NoError(t, Undefine(tpm, testIndex, []byte("owner")))
	_, defined = tpm.Data(testIndex)
	assert.False(t, defined)
}

func TestValidation_TypedErrors(t *testing.T) {
	tpm := tpmnvtest.New()

	tests := []struct {
		name string
		call func() error
		want error
		code codes.Code
	}{
		{"read index 0", func() error { _, err := Read(tpm, 0, 0, 0, nil); return err }, ErrIndexRequired{}, codes.InvalidArgument},
		{"write index 0", func() error { return Write(tpm, 0, []byte("x"), 0, nil) }, ErrIndexRequired{}, codes.InvalidArgument},
		{"undefine index 0", func() error { return Undefine(tpm, 0, nil) }, ErrIndexRequired{}, codes.InvalidArgument},
		{"write no data", func() error { return Write(tpm, testIndex, nil, 0, nil) }, ErrDataRequired{}, codes.InvalidArgument},
		{"read no transport", func() error { _, err := Read(nil, testIndex, 0, 0, nil); return err }, ErrTransportUnavailable{}, codes.Unavailable},
		{"write no transport", func() error { return Write(nil, testIndex, []byte("x"), 0, nil) }, ErrTransportUnavailable{}, codes.Unavailable},
		{"undefine no transport", func() error { return Undefine(nil, testIndex, nil) }, ErrTransportUnavailable{}, codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			assert.ErrorIs(t, err, tt.want)
			assert.Equal(t, tt.code, status.Code(err))
		})
	}
}

func TestPassword(t *testing.T) {
	assert.Nil(t, Password(""), "an empty password sends no auth value")
	assert.Equal(t, []byte("secret"), Password("secret"))
}
