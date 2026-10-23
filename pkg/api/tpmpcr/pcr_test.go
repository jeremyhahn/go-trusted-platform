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

package tpmpcr

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errExtendFailed = errors.New("extend failed")

// recordingTPM records the extend it receives.
type recordingTPM struct {
	calls   int
	index   int
	hashAlg string
	data    []byte
	err     error
}

func (r *recordingTPM) ExtendPCR(pcrIndex int, hashAlg string, data []byte) error {
	r.calls++
	r.index, r.hashAlg, r.data = pcrIndex, hashAlg, data
	return r.err
}

func TestExtend_DefaultsToSHA256(t *testing.T) {
	tpm := &recordingTPM{}

	assert.NoError(t, Extend(tpm, 16, "", []byte("measurement")))
	assert.Equal(t, 16, tpm.index)
	assert.Equal(t, DefaultHashAlg, tpm.hashAlg)
	assert.Equal(t, []byte("measurement"), tpm.data)
}

func TestExtend_NamedBankAndBounds(t *testing.T) {
	for _, index := range []int{0, MaxIndex} {
		tpm := &recordingTPM{}
		assert.NoError(t, Extend(tpm, index, "sha384", []byte("x")))
		assert.Equal(t, index, tpm.index)
		assert.Equal(t, "sha384", tpm.hashAlg)
	}
}

func TestExtend_RejectsBadRequests(t *testing.T) {
	tests := []struct {
		name  string
		index int
		data  []byte
		want  error
	}{
		{"negative index", -1, []byte("x"), ErrInvalidIndex{Index: -1}},
		{"index past 23", MaxIndex + 1, []byte("x"), ErrInvalidIndex{Index: MaxIndex + 1}},
		{"no data", 16, nil, ErrDataRequired{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := &recordingTPM{}
			err := Extend(tpm, tt.index, "", tt.data)
			assert.ErrorIs(t, err, tt.want)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
			assert.Zero(t, tpm.calls, "a rejected request never reaches the TPM")
		})
	}
}

func TestExtend_PassesTPMErrorThrough(t *testing.T) {
	tpm := &recordingTPM{err: errExtendFailed}

	assert.ErrorIs(t, Extend(tpm, 16, "", []byte("x")), errExtendFailed)
}

func TestErrInvalidIndex_Message(t *testing.T) {
	assert.Equal(t, "invalid PCR index 24 (must be 0-23)", ErrInvalidIndex{Index: 24}.Error())
}

func TestExtendedMessage_NamesThePCR(t *testing.T) {
	assert.Equal(t, "PCR 16 extended", ExtendedMessage(16))
	assert.Equal(t, "PCR 0 extended", ExtendedMessage(0))
}
