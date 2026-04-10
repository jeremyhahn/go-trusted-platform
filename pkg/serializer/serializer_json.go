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

package serializer

import "encoding/json"

type JSONSerializer[E any] struct {
	Serializer[E]
}

func NewJSONSerializer[E any]() Serializer[E] {
	return &JSONSerializer[E]{}
}

func (js JSONSerializer[E]) Serialize(entity E) ([]byte, error) {
	return json.Marshal(entity)
}

func (js JSONSerializer[E]) Deserialize(data []byte, e any) error {
	if err := json.Unmarshal(data, e); err != nil {
		return err
	}
	return nil
}

func (js JSONSerializer[E]) Type() SerializerType {
	return SERIALIZER_JSON
}

func (js JSONSerializer[E]) Name() string {
	return "json"
}

func (js JSONSerializer[E]) Extension() string {
	return ".json"
}
