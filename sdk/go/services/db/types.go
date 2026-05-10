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

// Package db provides a client for database administration service operations.
package db

// DumpParams contains parameters for dumping entity data.
type DumpParams struct {
	// EntityType filters by entity type (empty for all).
	EntityType string
	// Format is the output format (json or yaml).
	Format string
	// Pretty enables pretty-printed output.
	Pretty bool
}

// DumpEntry represents a single entity from the dump stream.
type DumpEntry struct {
	// EntityType is the type of the entity.
	EntityType string `json:"entity_type" yaml:"entity_type"`
	// EntityID is the unique identifier of the entity.
	EntityID uint64 `json:"entity_id" yaml:"entity_id"`
	// Data is the serialized entity data.
	Data []byte `json:"data" yaml:"data"`
}

// EntityTypeInfo describes an entity type in the database.
type EntityTypeInfo struct {
	// Name is the entity type name.
	Name string `json:"name" yaml:"name"`
	// EntityCount is the number of entities of this type.
	EntityCount uint64 `json:"entity_count" yaml:"entity_count"`
	// Status is the current status of the entity type.
	Status string `json:"status" yaml:"status"`
}

// ListEntityTypesResult contains the result of listing entity types.
type ListEntityTypesResult struct {
	// DatabasePath is the path to the database.
	DatabasePath string `json:"database_path" yaml:"database_path"`
	// EntityTypes is the list of entity type information.
	EntityTypes []*EntityTypeInfo `json:"entity_types" yaml:"entity_types"`
	// TotalEntities is the total number of entities.
	TotalEntities uint64 `json:"total_entities" yaml:"total_entities"`
	// ActiveTypes is the number of active entity types.
	ActiveTypes uint32 `json:"active_types" yaml:"active_types"`
}
