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
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrTrailingData is returned when a stored entity's JSON document is
// followed by further data, which json.Unmarshal would also refuse.
type ErrTrailingData struct{}

func (e ErrTrailingData) Error() string {
	return "trailing data after the entity's JSON document"
}

// DecodeEntity decodes a stored entity's JSON document into v. It is the one
// decode path of every DAO (pkg/storage/quicbaas and
// pkg/store/datastore/kvstore).
//
// The decoder runs with UseNumber, so a number held in an any-typed field
// (for example entities.DeviceProfile.Config or entities.Blob.Entity) decodes
// as json.Number rather than float64, and an integer above 2^53 reads back
// exactly (#125). Like json.Unmarshal, it refuses data after the document.
//
// The entity bytes are always encoding/json: the codec_json, codec_msgpack
// and codec_cbor build tags select the SDK's wire codec, which carries the
// stored value as an opaque byte string and never decodes it.
func DecodeEntity(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return ErrTrailingData{}
	}
	return nil
}
