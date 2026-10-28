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

package datastore

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeEntity_DecodesDocument(t *testing.T) {
	var blob entities.Blob
	require.NoError(t, DecodeEntity([]byte(`{"id":7,"entity":{"n":9007199254740993}}`), &blob))

	assert.Equal(t, uint64(7), blob.ID)
	assert.Equal(t, map[string]any{"n": json.Number("9007199254740993")}, blob.Entity)
}

// DecodeEntity refuses what json.Unmarshal refuses: malformed JSON, and a
// second value or garbage after the document.
func TestDecodeEntity_Errors(t *testing.T) {
	var blob entities.Blob

	var syntaxErr *json.SyntaxError
	assert.ErrorIs(t, DecodeEntity([]byte(`{"id":`), &blob), io.ErrUnexpectedEOF)
	assert.ErrorAs(t, DecodeEntity([]byte(`{"id":7} x`), &blob), &syntaxErr)
	assert.ErrorIs(t, DecodeEntity([]byte(`{"id":7} {"id":8}`), &blob), ErrTrailingData{})
	assert.Error(t, DecodeEntity(nil, &blob))
}
