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

package main

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// protoToMap converts a protobuf message to a map[string]interface{} suitable
// for Wails JSON serialization. It uses protojson for canonical field naming
// (camelCase) and proper enum string representation.
func protoToMap(msg proto.Message) (map[string]interface{}, error) {
	if msg == nil {
		return nil, nil
	}

	opts := protojson.MarshalOptions{
		UseProtoNames:   false, // Use camelCase field names for JS
		EmitUnpopulated: false, // Skip zero-value fields
		UseEnumNumbers:  false, // Use string names for enums
	}

	data, err := opts.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}
