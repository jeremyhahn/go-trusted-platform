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

import (
	YAML "gopkg.in/yaml.v2"
)

type YAMLSerializer[E any] struct {
	Serializer[E]
}

func NewYAMLSerializer[E any]() Serializer[E] {
	return &YAMLSerializer[E]{}
}

func (js YAMLSerializer[E]) Serialize(entity E) ([]byte, error) {
	return YAML.Marshal(entity)
}

func (js YAMLSerializer[E]) Deserialize(data []byte, e any) error {
	if err := YAML.Unmarshal(data, e); err != nil {
		return err
	}
	return nil
}

func (js YAMLSerializer[E]) Type() SerializerType {
	return SERIALIZER_YAML
}

func (js YAMLSerializer[E]) Name() string {
	return "yaml"
}

func (js YAMLSerializer[E]) Extension() string {
	return ".yaml"
}
