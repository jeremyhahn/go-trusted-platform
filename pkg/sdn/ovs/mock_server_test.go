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
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// mockOVSDBServer implements a minimal OVSDB server for testing
type mockOVSDBServer struct {
	listener  net.Listener
	conn      net.Conn
	databases map[string]*mockDatabase
	t         *testing.T
	mu        sync.RWMutex
	done      chan struct{}
	wg        sync.WaitGroup
}

// mockDatabase represents an in-memory OVSDB database
type mockDatabase struct {
	name   string
	tables map[string]*mockTable
	mu     sync.RWMutex
}

// mockTable represents an in-memory OVSDB table
type mockTable struct {
	name string
	rows map[string]map[string]interface{}
	mu   sync.RWMutex
}

// newMockOVSDBServer creates a new mock OVSDB server
func newMockOVSDBServer(t *testing.T, socketPath string) (*mockOVSDBServer, error) {
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	s := &mockOVSDBServer{
		listener:  listener,
		databases: make(map[string]*mockDatabase),
		t:         t,
		done:      make(chan struct{}),
	}

	// Initialize default database
	s.initializeDatabase()

	return s, nil
}

// initializeDatabase creates the default Open_vSwitch database with schema
func (s *mockOVSDBServer) initializeDatabase() {
	db := &mockDatabase{
		name:   DefaultDatabase,
		tables: make(map[string]*mockTable),
	}

	// Generate a proper UUID for the Open_vSwitch table
	ovsUUID := uuid.New().String()

	// Create tables
	db.tables["Open_vSwitch"] = &mockTable{
		name: "Open_vSwitch",
		rows: map[string]map[string]interface{}{
			ovsUUID: {
				"_uuid":   []interface{}{"uuid", ovsUUID},
				"bridges": []interface{}{"set", []interface{}{}},
			},
		},
	}
	db.tables["Bridge"] = &mockTable{name: "Bridge", rows: make(map[string]map[string]interface{})}
	db.tables["Port"] = &mockTable{name: "Port", rows: make(map[string]map[string]interface{})}
	db.tables["Interface"] = &mockTable{name: "Interface", rows: make(map[string]map[string]interface{})}

	s.mu.Lock()
	s.databases[DefaultDatabase] = db
	s.mu.Unlock()
}

// Start begins accepting connections
func (s *mockOVSDBServer) Start() {
	s.wg.Add(1)
	go s.acceptLoop()
}

// acceptLoop accepts incoming connections
func (s *mockOVSDBServer) acceptLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				s.t.Logf("Accept error: %v", err)
				continue
			}
		}

		s.mu.Lock()
		s.conn = conn
		s.mu.Unlock()

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (s *mockOVSDBServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			s.t.Logf("cleanup: connection close: %v", err)
		}
	}()

	decoder := json.NewDecoder(bufio.NewReader(conn))
	encoder := json.NewEncoder(conn)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		var req JSONRPCRequest
		if err := decoder.Decode(&req); err != nil {
			return
		}

		resp := s.handleRequest(&req)
		if err := encoder.Encode(resp); err != nil {
			return
		}
	}
}

// handleRequest processes a JSON-RPC request
func (s *mockOVSDBServer) handleRequest(req *JSONRPCRequest) *JSONRPCResponse {
	resp := &JSONRPCResponse{ID: req.ID}

	switch req.Method {
	case "list_dbs":
		resp.Result = s.handleListDatabases()
	case "get_schema":
		resp.Result = s.handleGetSchema(req.Params)
	case "echo":
		resp.Result = s.handleEcho(req.Params)
	case "transact":
		resp.Result = s.handleTransact(req.Params)
	default:
		resp.Error = &RPCError{
			Code:    -32601,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}
	}

	return resp
}

// handleListDatabases handles list_dbs method
func (s *mockOVSDBServer) handleListDatabases() json.RawMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dbs := make([]string, 0, len(s.databases))
	for name := range s.databases {
		dbs = append(dbs, name)
	}

	data, _ := json.Marshal(dbs)
	return data
}

// handleGetSchema handles get_schema method
func (s *mockOVSDBServer) handleGetSchema(params []interface{}) json.RawMessage {
	if len(params) == 0 {
		return json.RawMessage(`{}`)
	}

	dbName, ok := params[0].(string)
	if !ok {
		return json.RawMessage(`{}`)
	}

	schema := GetSchemaResult{
		Name:    dbName,
		Version: "8.0.0",
		Tables: map[string]TableSchema{
			"Bridge": {
				Columns: map[string]ColumnSchema{
					"name":          {Type: "string"},
					"ports":         {Type: "set"},
					"datapath_type": {Type: "string"},
					"fail_mode":     {Type: "string"},
				},
			},
			"Port": {
				Columns: map[string]ColumnSchema{
					"name":       {Type: "string"},
					"interfaces": {Type: "set"},
					"tag":        {Type: "integer"},
					"trunks":     {Type: "set"},
				},
			},
			"Interface": {
				Columns: map[string]ColumnSchema{
					"name":        {Type: "string"},
					"type":        {Type: "string"},
					"admin_state": {Type: "string"},
				},
			},
		},
	}

	data, _ := json.Marshal(schema)
	return data
}

// handleEcho handles echo method
func (s *mockOVSDBServer) handleEcho(params []interface{}) json.RawMessage {
	data, _ := json.Marshal(params)
	return data
}

// handleTransact handles transact method
func (s *mockOVSDBServer) handleTransact(params []interface{}) json.RawMessage {
	if len(params) == 0 {
		return json.RawMessage(`[]`)
	}

	dbName, ok := params[0].(string)
	if !ok {
		return json.RawMessage(`[]`)
	}

	s.mu.RLock()
	db, exists := s.databases[dbName]
	s.mu.RUnlock()

	if !exists {
		return json.RawMessage(`[{"error":"database not found"}]`)
	}

	results := make([]OperationResult, 0, len(params)-1)
	namedUUIDs := make(map[string]string)

	for i := 1; i < len(params); i++ {
		opData, _ := json.Marshal(params[i])
		var op Operation
		if err := json.Unmarshal(opData, &op); err != nil {
			results = append(results, OperationResult{
				Error:   "invalid operation",
				Details: err.Error(),
			})
			continue
		}

		result := s.executeOperation(db, &op, namedUUIDs)
		results = append(results, result)
	}

	data, _ := json.Marshal(results)
	return data
}

// executeOperation executes a single OVSDB operation
func (s *mockOVSDBServer) executeOperation(db *mockDatabase, op *Operation, namedUUIDs map[string]string) OperationResult {
	switch op.Op {
	case "select":
		return s.handleSelect(db, op)
	case "insert":
		return s.handleInsert(db, op, namedUUIDs)
	case "update":
		return s.handleUpdate(db, op, namedUUIDs)
	case "delete":
		return s.handleDelete(db, op, namedUUIDs)
	case "mutate":
		return s.handleMutate(db, op, namedUUIDs)
	default:
		return OperationResult{
			Error:   "unknown operation",
			Details: op.Op,
		}
	}
}

// handleSelect handles select operations
func (s *mockOVSDBServer) handleSelect(db *mockDatabase, op *Operation) OperationResult {
	db.mu.RLock()
	table, exists := db.tables[op.Table]
	db.mu.RUnlock()

	if !exists {
		return OperationResult{Error: "table not found"}
	}

	table.mu.RLock()
	defer table.mu.RUnlock()

	rows := make([]map[string]interface{}, 0)
	for _, row := range table.rows {
		if s.matchesWhere(row, op.Where) {
			filteredRow := s.filterColumns(row, op.Columns)
			rows = append(rows, filteredRow)
		}
	}

	return OperationResult{Rows: rows}
}

// handleInsert handles insert operations
func (s *mockOVSDBServer) handleInsert(db *mockDatabase, op *Operation, namedUUIDs map[string]string) OperationResult {
	db.mu.RLock()
	table, exists := db.tables[op.Table]
	db.mu.RUnlock()

	if !exists {
		return OperationResult{Error: "table not found"}
	}

	// Generate UUID for new row
	newUUID := uuid.New().String()
	if op.UUIDName != "" {
		namedUUIDs[op.UUIDName] = newUUID
	}

	// Resolve named-uuid references in row data
	row := s.resolveNamedUUIDs(op.Row, namedUUIDs)
	row["_uuid"] = []interface{}{"uuid", newUUID}

	table.mu.Lock()
	table.rows[newUUID] = row
	table.mu.Unlock()

	uuidObj := &UUID{UUID: newUUID}
	return OperationResult{UUID: uuidObj}
}

// handleUpdate handles update operations
func (s *mockOVSDBServer) handleUpdate(db *mockDatabase, op *Operation, namedUUIDs map[string]string) OperationResult {
	db.mu.RLock()
	table, exists := db.tables[op.Table]
	db.mu.RUnlock()

	if !exists {
		return OperationResult{Error: "table not found"}
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	count := 0
	for uuid, row := range table.rows {
		if s.matchesWhere(row, op.Where) {
			// Update row fields
			updatedRow := s.resolveNamedUUIDs(op.Row, namedUUIDs)
			for k, v := range updatedRow {
				row[k] = v
			}
			table.rows[uuid] = row
			count++
		}
	}

	return OperationResult{Count: &count}
}

// handleDelete handles delete operations
func (s *mockOVSDBServer) handleDelete(db *mockDatabase, op *Operation, namedUUIDs map[string]string) OperationResult {
	db.mu.RLock()
	table, exists := db.tables[op.Table]
	db.mu.RUnlock()

	if !exists {
		return OperationResult{Error: "table not found"}
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	count := 0
	for uuid, row := range table.rows {
		if s.matchesWhere(row, op.Where) {
			delete(table.rows, uuid)
			count++
		}
	}

	return OperationResult{Count: &count}
}

// handleMutate handles mutate operations
func (s *mockOVSDBServer) handleMutate(db *mockDatabase, op *Operation, namedUUIDs map[string]string) OperationResult {
	db.mu.RLock()
	table, exists := db.tables[op.Table]
	db.mu.RUnlock()

	if !exists {
		return OperationResult{Error: "table not found"}
	}

	table.mu.Lock()
	defer table.mu.Unlock()

	count := 0
	for uuid, row := range table.rows {
		if s.matchesWhere(row, op.Where) {
			// Apply mutations
			for _, mutation := range op.Mutations {
				if len(mutation) != 3 {
					continue
				}
				column, _ := mutation[0].(string)
				mutator, _ := mutation[1].(string)
				value := mutation[2]

				s.applyMutation(row, column, mutator, value, namedUUIDs)
			}
			table.rows[uuid] = row
			count++
		}
	}

	return OperationResult{Count: &count}
}

// matchesWhere checks if a row matches where conditions
func (s *mockOVSDBServer) matchesWhere(row map[string]interface{}, where *[][]interface{}) bool {
	if where == nil || len(*where) == 0 {
		return true
	}

	for _, cond := range *where {
		if len(cond) != 3 {
			continue
		}

		column, _ := cond[0].(string)
		function, _ := cond[1].(string)
		value := cond[2]

		rowVal, exists := row[column]
		if !exists {
			return false
		}

		if !s.evaluateCondition(rowVal, function, value) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition
func (s *mockOVSDBServer) evaluateCondition(rowVal interface{}, function string, expected interface{}) bool {
	switch function {
	case "==":
		return s.valuesEqual(rowVal, expected)
	case "!=":
		return !s.valuesEqual(rowVal, expected)
	default:
		return false
	}
}

// valuesEqual compares two values for equality
func (s *mockOVSDBServer) valuesEqual(a, b interface{}) bool {
	// Handle UUID comparisons
	aUUID := s.extractUUID(a)
	bUUID := s.extractUUID(b)
	if aUUID != "" && bUUID != "" {
		return aUUID == bUUID
	}

	// Direct comparison
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// extractUUID extracts UUID string from various formats
func (s *mockOVSDBServer) extractUUID(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) == 2 && v[0] == "uuid" {
			if uuid, ok := v[1].(string); ok {
				return uuid
			}
		}
	case map[string]interface{}:
		if uuid, ok := v["uuid"].(string); ok {
			return uuid
		}
	}
	return ""
}

// filterColumns filters row columns
func (s *mockOVSDBServer) filterColumns(row map[string]interface{}, columns []string) map[string]interface{} {
	if len(columns) == 0 {
		return row
	}

	filtered := make(map[string]interface{})
	for _, col := range columns {
		if val, ok := row[col]; ok {
			filtered[col] = val
		}
	}
	return filtered
}

// resolveNamedUUIDs resolves named-uuid references in a map
func (s *mockOVSDBServer) resolveNamedUUIDs(data map[string]interface{}, namedUUIDs map[string]string) map[string]interface{} {
	resolved := make(map[string]interface{})
	for k, v := range data {
		resolved[k] = s.resolveNamedUUIDValue(v, namedUUIDs)
	}
	return resolved
}

// resolveNamedUUIDValue resolves named-uuid references in a value
func (s *mockOVSDBServer) resolveNamedUUIDValue(val interface{}, namedUUIDs map[string]string) interface{} {
	switch v := val.(type) {
	case map[string]interface{}:
		if namedUUID, ok := v["named-uuid"].(string); ok {
			if uuid, exists := namedUUIDs[namedUUID]; exists {
				return []interface{}{"uuid", uuid}
			}
		}
		return s.resolveNamedUUIDs(v, namedUUIDs)
	case []interface{}:
		resolved := make([]interface{}, len(v))
		for i, item := range v {
			resolved[i] = s.resolveNamedUUIDValue(item, namedUUIDs)
		}
		return resolved
	default:
		return val
	}
}

// applyMutation applies a mutation to a row
func (s *mockOVSDBServer) applyMutation(row map[string]interface{}, column, mutator string, value interface{}, namedUUIDs map[string]string) {
	resolvedValue := s.resolveNamedUUIDValue(value, namedUUIDs)

	switch mutator {
	case "insert":
		// Insert into set
		current, exists := row[column]
		if !exists {
			row[column] = []interface{}{"set", []interface{}{resolvedValue}}
			return
		}

		// Parse current set
		set := s.parseSet(current)
		set = append(set, resolvedValue)
		row[column] = []interface{}{"set", set}

	case "delete":
		// Remove from set
		current, exists := row[column]
		if !exists {
			return
		}

		set := s.parseSet(current)
		newSet := make([]interface{}, 0)
		delUUID := s.extractUUID(resolvedValue)

		for _, item := range set {
			itemUUID := s.extractUUID(item)
			if itemUUID != delUUID {
				newSet = append(newSet, item)
			}
		}
		row[column] = []interface{}{"set", newSet}
	}
}

// parseSet parses a set value
func (s *mockOVSDBServer) parseSet(val interface{}) []interface{} {
	if arr, ok := val.([]interface{}); ok && len(arr) == 2 && arr[0] == "set" {
		if items, ok := arr[1].([]interface{}); ok {
			return items
		}
	}
	return []interface{}{}
}

// Close stops the server
func (s *mockOVSDBServer) Close() error {
	close(s.done)

	s.mu.Lock()
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			s.t.Logf("cleanup: server conn close: %v", err)
		}
	}
	s.mu.Unlock()

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.t.Logf("cleanup: listener close: %v", err)
		}
	}

	s.wg.Wait()
	return nil
}

// AddBridge adds a bridge to the mock database (for test setup)
func (s *mockOVSDBServer) AddBridge(name, uuidStr string) {
	s.mu.RLock()
	db := s.databases[DefaultDatabase]
	s.mu.RUnlock()

	bridgeTable := db.tables["Bridge"]
	portTable := db.tables["Port"]
	ifaceTable := db.tables["Interface"]

	// Add interface
	ifaceUUID := uuidStr + "-iface"
	ifaceTable.mu.Lock()
	ifaceTable.rows[ifaceUUID] = map[string]interface{}{
		"_uuid": []interface{}{"uuid", ifaceUUID},
		"name":  name,
		"type":  "internal",
	}
	ifaceTable.mu.Unlock()

	// Add port
	portUUID := uuidStr + "-port"
	portTable.mu.Lock()
	portTable.rows[portUUID] = map[string]interface{}{
		"_uuid":      []interface{}{"uuid", portUUID},
		"name":       name,
		"interfaces": []interface{}{"set", []interface{}{[]interface{}{"uuid", ifaceUUID}}},
		"tag":        []interface{}{"set", []interface{}{}},
		"trunks":     []interface{}{"set", []interface{}{}},
	}
	portTable.mu.Unlock()

	// Add bridge
	bridgeTable.mu.Lock()
	bridgeTable.rows[uuidStr] = map[string]interface{}{
		"_uuid":                 []interface{}{"uuid", uuidStr},
		"name":                  name,
		"datapath_type":         "",
		"ports":                 []interface{}{"set", []interface{}{[]interface{}{"uuid", portUUID}}},
		"fail_mode":             []interface{}{"set", []interface{}{}},
		"protocols":             []interface{}{"set", []interface{}{}},
		"external_ids":          []interface{}{"map", []interface{}{}},
		"other_config":          []interface{}{"map", []interface{}{}},
		"status":                []interface{}{"map", []interface{}{}},
		"stp_enable":            false,
		"rstp_enable":           false,
		"mcast_snooping_enable": false,
	}
	bridgeTable.mu.Unlock()

	// Add bridge to OVS table
	ovsTable := db.tables["Open_vSwitch"]
	ovsTable.mu.Lock()
	for uuid, row := range ovsTable.rows {
		if bridges, ok := row["bridges"]; ok {
			set := s.parseSet(bridges)
			set = append(set, []interface{}{"uuid", uuidStr})
			row["bridges"] = []interface{}{"set", set}
			ovsTable.rows[uuid] = row
		}
	}
	ovsTable.mu.Unlock()
}
