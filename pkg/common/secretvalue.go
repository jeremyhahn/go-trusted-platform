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

package common

import (
	"encoding/base64"
	"fmt"
)

// ErrMalformedSecretValue reports a stored secret value that cannot be
// turned back into the bytes that were stored: a string that is not
// standard base64, or a value of an unexpected type.
type ErrMalformedSecretValue struct {
	Type string
	Err  error
}

func (e ErrMalformedSecretValue) Error() string {
	if e.Err != nil {
		return "stored secret value is not base64 text: " + e.Err.Error()
	}
	return "stored secret value has unexpected type " + e.Type
}

func (e ErrMalformedSecretValue) Unwrap() error { return e.Err }

// DecodeSecretValue returns the bytes stored as a secret's "value" data
// entry. The quicbaas Secrets client JSON-encodes the data map, so a
// []byte stored by the platform comes back from a get as its base64 text;
// a transport that keeps the bytes returns them unchanged. A nil value
// (no "value" entry) decodes to nil.
func DecodeSecretValue(value interface{}) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case []byte:
		return typed, nil
	case string:
		decoded, err := base64.StdEncoding.DecodeString(typed)
		if err != nil {
			return nil, ErrMalformedSecretValue{Type: "string", Err: err}
		}
		return decoded, nil
	default:
		return nil, ErrMalformedSecretValue{Type: fmt.Sprintf("%T", value)}
	}
}
