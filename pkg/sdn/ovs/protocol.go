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

package ovs

import (
	"encoding/json"
	"sync/atomic"
)

// OVSDB Protocol constants
const (
	// ProtocolVersion is the OVSDB protocol version (RFC 7047)
	ProtocolVersion = "1.0"

	// DefaultDatabase is the default OVSDB database name
	DefaultDatabase = "Open_vSwitch"
)

// JSONRPCRequest represents an OVSDB JSON-RPC 2.0 request
type JSONRPCRequest struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
	ID     uint64        `json:"id"`
}

// JSONRPCResponse represents an OVSDB JSON-RPC 2.0 response
type JSONRPCResponse struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
	ID     uint64          `json:"id"`
}

// RPCError represents an OVSDB RPC error
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// TransactRequest represents an OVSDB transact request
type TransactRequest struct {
	Database   string
	Operations []Operation
}

// Operation represents a single OVSDB operation
// Note: Where uses a pointer to distinguish between nil (omit field) and empty (include as [])
type Operation struct {
	Op        string                   `json:"op"`
	Table     string                   `json:"table,omitempty"`
	Row       map[string]interface{}   `json:"row,omitempty"`
	Rows      []map[string]interface{} `json:"rows,omitempty"`
	Where     *[][]interface{}         `json:"where,omitempty"` // nil=omit, non-nil=[]=include empty array
	Columns   []string                 `json:"columns,omitempty"`
	Mutations [][]interface{}          `json:"mutations,omitempty"`
	Timeout   uint                     `json:"timeout,omitempty"`
	UUID      string                   `json:"uuid,omitempty"`
	UUIDName  string                   `json:"uuid-name,omitempty"`
	Comment   string                   `json:"comment,omitempty"`
	Durable   *bool                    `json:"durable,omitempty"`
}

// OperationResult represents the result of a single operation
type OperationResult struct {
	Count   *int                     `json:"count,omitempty"`
	UUID    *UUID                    `json:"uuid,omitempty"`
	Rows    []map[string]interface{} `json:"rows,omitempty"`
	Error   string                   `json:"error,omitempty"`
	Details string                   `json:"details,omitempty"`
}

// TransactResponse represents the response to a transact request
type TransactResponse []OperationResult

// Condition represents an OVSDB where condition
type Condition struct {
	Column   string
	Function string
	Value    interface{}
}

// MarshalJSON implements json.Marshaler for Condition
func (c Condition) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{c.Column, c.Function, c.Value})
}

// Mutation represents an OVSDB mutation
type Mutation struct {
	Column  string
	Mutator string
	Value   interface{}
}

// MarshalJSON implements json.Marshaler for Mutation
func (m Mutation) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{m.Column, m.Mutator, m.Value})
}

// ListDatabasesResult represents the result of list_databases method
type ListDatabasesResult []string

// GetSchemaResult represents the result of get_schema method
type GetSchemaResult struct {
	Name    string                 `json:"name"`
	Version string                 `json:"version"`
	Tables  map[string]TableSchema `json:"tables"`
}

// TableSchema represents a database table schema
type TableSchema struct {
	Columns map[string]ColumnSchema `json:"columns"`
	Indexes [][]string              `json:"indexes,omitempty"`
}

// ColumnSchema represents a column schema
type ColumnSchema struct {
	Type      interface{} `json:"type"`
	Ephemeral bool        `json:"ephemeral,omitempty"`
	Mutable   bool        `json:"mutable,omitempty"`
}

// MonitorRequest represents a monitor request
type MonitorRequest struct {
	Columns []string       `json:"columns,omitempty"`
	Select  *MonitorSelect `json:"select,omitempty"`
}

// MonitorSelect specifies what updates to receive
type MonitorSelect struct {
	Initial bool `json:"initial,omitempty"`
	Insert  bool `json:"insert,omitempty"`
	Delete  bool `json:"delete,omitempty"`
	Modify  bool `json:"modify,omitempty"`
}

// MonitorUpdate represents a monitor update notification
type MonitorUpdate struct {
	TableUpdates map[string]TableUpdate `json:"table_updates"`
}

// TableUpdate represents updates to a table
type TableUpdate map[string]RowUpdate

// RowUpdate represents an update to a row
type RowUpdate struct {
	Old map[string]interface{} `json:"old,omitempty"`
	New map[string]interface{} `json:"new,omitempty"`
}

// requestIDCounter is an atomic counter for request IDs
var requestIDCounter uint64

// nextRequestID generates the next request ID
func nextRequestID() uint64 {
	return atomic.AddUint64(&requestIDCounter, 1)
}

// NewJSONRPCRequest creates a new JSONRPC request
func NewJSONRPCRequest(method string, params []interface{}) *JSONRPCRequest {
	return &JSONRPCRequest{
		Method: method,
		Params: params,
		ID:     nextRequestID(),
	}
}

// NewOperation creates a new OVSDB operation
func NewOperation(op, table string) Operation {
	return Operation{
		Op:    op,
		Table: table,
	}
}

// NewInsertOperation creates an insert operation
func NewInsertOperation(table string, row map[string]interface{}, uuidName string) Operation {
	return Operation{
		Op:       "insert",
		Table:    table,
		Row:      row,
		UUIDName: uuidName,
	}
}

// NewSelectOperation creates a select operation
func NewSelectOperation(table string, where []Condition, columns []string) Operation {
	// OVSDB requires "where" to be an array, even if empty
	whereClause := make([][]interface{}, 0, len(where))
	for _, cond := range where {
		whereClause = append(whereClause, []interface{}{cond.Column, cond.Function, cond.Value})
	}

	return Operation{
		Op:      "select",
		Table:   table,
		Where:   &whereClause,
		Columns: columns,
	}
}

// NewUpdateOperation creates an update operation
func NewUpdateOperation(table string, where []Condition, row map[string]interface{}) Operation {
	// OVSDB requires "where" to be an array, even if empty
	whereClause := make([][]interface{}, 0, len(where))
	for _, cond := range where {
		whereClause = append(whereClause, []interface{}{cond.Column, cond.Function, cond.Value})
	}

	return Operation{
		Op:    "update",
		Table: table,
		Where: &whereClause,
		Row:   row,
	}
}

// NewDeleteOperation creates a delete operation
func NewDeleteOperation(table string, where []Condition) Operation {
	// OVSDB requires "where" to be an array, even if empty
	whereClause := make([][]interface{}, 0, len(where))
	for _, cond := range where {
		whereClause = append(whereClause, []interface{}{cond.Column, cond.Function, cond.Value})
	}

	return Operation{
		Op:    "delete",
		Table: table,
		Where: &whereClause,
	}
}

// NewMutateOperation creates a mutate operation
func NewMutateOperation(table string, where []Condition, mutations []Mutation) Operation {
	// OVSDB requires "where" to be an array, even if empty
	whereClause := make([][]interface{}, 0, len(where))
	for _, cond := range where {
		whereClause = append(whereClause, []interface{}{cond.Column, cond.Function, cond.Value})
	}

	mutationClause := make([][]interface{}, 0, len(mutations))
	for _, mut := range mutations {
		mutationClause = append(mutationClause, []interface{}{mut.Column, mut.Mutator, mut.Value})
	}

	return Operation{
		Op:        "mutate",
		Table:     table,
		Where:     &whereClause,
		Mutations: mutationClause,
	}
}

// NewCondition creates a new OVSDB condition
func NewCondition(column, function string, value interface{}) Condition {
	return Condition{
		Column:   column,
		Function: function,
		Value:    value,
	}
}

// NewMutation creates a new OVSDB mutation
func NewMutation(column, mutator string, value interface{}) Mutation {
	return Mutation{
		Column:  column,
		Mutator: mutator,
		Value:   value,
	}
}
