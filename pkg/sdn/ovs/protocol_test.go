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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJSONRPCRequest(t *testing.T) {
	t.Run("create request with params", func(t *testing.T) {
		params := []interface{}{"param1", 123}
		req := NewJSONRPCRequest("test_method", params)

		assert.NotNil(t, req)
		assert.Equal(t, "test_method", req.Method)
		assert.Equal(t, params, req.Params)
		assert.Greater(t, req.ID, uint64(0))
	})

	t.Run("create request without params", func(t *testing.T) {
		req := NewJSONRPCRequest("test_method", nil)

		assert.NotNil(t, req)
		assert.Equal(t, "test_method", req.Method)
		assert.Nil(t, req.Params)
	})

	t.Run("sequential IDs", func(t *testing.T) {
		req1 := NewJSONRPCRequest("method1", nil)
		req2 := NewJSONRPCRequest("method2", nil)

		assert.Less(t, req1.ID, req2.ID)
	})
}

func TestNewOperation(t *testing.T) {
	t.Run("create basic operation", func(t *testing.T) {
		op := NewOperation("select", "Bridge")

		assert.Equal(t, "select", op.Op)
		assert.Equal(t, "Bridge", op.Table)
	})
}

func TestNewSelectOperation(t *testing.T) {
	t.Run("select with where and columns", func(t *testing.T) {
		where := []Condition{
			NewCondition("name", "==", "br0"),
		}
		columns := []string{"_uuid", "name"}

		op := NewSelectOperation("Bridge", where, columns)

		assert.Equal(t, "select", op.Op)
		assert.Equal(t, "Bridge", op.Table)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 1)
		assert.Equal(t, columns, op.Columns)
	})

	t.Run("select without where", func(t *testing.T) {
		op := NewSelectOperation("Bridge", nil, nil)

		assert.Equal(t, "select", op.Op)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 0)
	})

	t.Run("select with empty where", func(t *testing.T) {
		op := NewSelectOperation("Bridge", []Condition{}, []string{"name"})

		assert.Equal(t, "select", op.Op)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 0)
	})
}

func TestNewInsertOperation(t *testing.T) {
	t.Run("insert with row and uuid name", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "br0",
			"type": "system",
		}
		op := NewInsertOperation("Bridge", row, "new_bridge")

		assert.Equal(t, "insert", op.Op)
		assert.Equal(t, "Bridge", op.Table)
		assert.Equal(t, row, op.Row)
		assert.Equal(t, "new_bridge", op.UUIDName)
	})

	t.Run("insert with empty uuid name", func(t *testing.T) {
		row := map[string]interface{}{"name": "br0"}
		op := NewInsertOperation("Bridge", row, "")

		assert.Equal(t, "insert", op.Op)
		assert.Empty(t, op.UUIDName)
	})
}

func TestNewUpdateOperation(t *testing.T) {
	t.Run("update with where and row", func(t *testing.T) {
		where := []Condition{
			NewCondition("_uuid", "==", []interface{}{"uuid", "test-uuid"}),
		}
		row := map[string]interface{}{
			"datapath_type": "netdev",
		}
		op := NewUpdateOperation("Bridge", where, row)

		assert.Equal(t, "update", op.Op)
		assert.Equal(t, "Bridge", op.Table)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 1)
		assert.Equal(t, row, op.Row)
	})

	t.Run("update with empty where", func(t *testing.T) {
		row := map[string]interface{}{"name": "updated"}
		op := NewUpdateOperation("Bridge", []Condition{}, row)

		assert.Equal(t, "update", op.Op)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 0)
	})
}

func TestNewDeleteOperation(t *testing.T) {
	t.Run("delete with where", func(t *testing.T) {
		where := []Condition{
			NewCondition("name", "==", "br0"),
		}
		op := NewDeleteOperation("Bridge", where)

		assert.Equal(t, "delete", op.Op)
		assert.Equal(t, "Bridge", op.Table)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 1)
	})

	t.Run("delete without where", func(t *testing.T) {
		op := NewDeleteOperation("Bridge", nil)

		assert.Equal(t, "delete", op.Op)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 0)
	})
}

func TestNewMutateOperation(t *testing.T) {
	t.Run("mutate with where and mutations", func(t *testing.T) {
		where := []Condition{
			NewCondition("_uuid", "==", []interface{}{"uuid", "test-uuid"}),
		}
		mutations := []Mutation{
			NewMutation("ports", "insert", []interface{}{"uuid", "port-uuid"}),
		}
		op := NewMutateOperation("Bridge", where, mutations)

		assert.Equal(t, "mutate", op.Op)
		assert.Equal(t, "Bridge", op.Table)
		assert.NotNil(t, op.Where)
		assert.Len(t, *op.Where, 1)
		assert.Len(t, op.Mutations, 1)
	})

	t.Run("mutate with multiple mutations", func(t *testing.T) {
		mutations := []Mutation{
			NewMutation("ports", "insert", []interface{}{"uuid", "port1"}),
			NewMutation("ports", "insert", []interface{}{"uuid", "port2"}),
		}
		op := NewMutateOperation("Bridge", nil, mutations)

		assert.Equal(t, "mutate", op.Op)
		assert.Len(t, op.Mutations, 2)
	})
}

func TestNewCondition(t *testing.T) {
	t.Run("create condition", func(t *testing.T) {
		cond := NewCondition("name", "==", "br0")

		assert.Equal(t, "name", cond.Column)
		assert.Equal(t, "==", cond.Function)
		assert.Equal(t, "br0", cond.Value)
	})

	t.Run("condition with complex value", func(t *testing.T) {
		value := []interface{}{"uuid", "test-uuid"}
		cond := NewCondition("_uuid", "==", value)

		assert.Equal(t, "_uuid", cond.Column)
		assert.Equal(t, value, cond.Value)
	})
}

func TestConditionMarshalJSON(t *testing.T) {
	t.Run("marshal simple condition", func(t *testing.T) {
		cond := NewCondition("name", "==", "br0")
		data, err := json.Marshal(cond)

		require.NoError(t, err)
		expected := `["name","==","br0"]`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("marshal condition with UUID", func(t *testing.T) {
		cond := NewCondition("_uuid", "==", []interface{}{"uuid", "test-uuid"})
		data, err := json.Marshal(cond)

		require.NoError(t, err)
		var result []interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Len(t, result, 3)
		assert.Equal(t, "_uuid", result[0])
		assert.Equal(t, "==", result[1])
	})

	t.Run("marshal condition with number", func(t *testing.T) {
		cond := NewCondition("tag", "!=", 100)
		data, err := json.Marshal(cond)

		require.NoError(t, err)
		expected := `["tag","!=",100]`
		assert.JSONEq(t, expected, string(data))
	})
}

func TestNewMutation(t *testing.T) {
	t.Run("create mutation", func(t *testing.T) {
		mut := NewMutation("ports", "insert", []interface{}{"uuid", "port-uuid"})

		assert.Equal(t, "ports", mut.Column)
		assert.Equal(t, "insert", mut.Mutator)
		assert.IsType(t, []interface{}{}, mut.Value)
	})

	t.Run("create delete mutation", func(t *testing.T) {
		mut := NewMutation("ports", "delete", []interface{}{"uuid", "port-uuid"})

		assert.Equal(t, "delete", mut.Mutator)
	})
}

func TestMutationMarshalJSON(t *testing.T) {
	t.Run("marshal insert mutation", func(t *testing.T) {
		mut := NewMutation("ports", "insert", []interface{}{"uuid", "port-uuid"})
		data, err := json.Marshal(mut)

		require.NoError(t, err)
		var result []interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Len(t, result, 3)
		assert.Equal(t, "ports", result[0])
		assert.Equal(t, "insert", result[1])
	})

	t.Run("marshal delete mutation", func(t *testing.T) {
		mut := NewMutation("ports", "delete", []interface{}{"uuid", "port-uuid"})
		data, err := json.Marshal(mut)

		require.NoError(t, err)
		expected := `["ports","delete",["uuid","port-uuid"]]`
		assert.JSONEq(t, expected, string(data))
	})
}

func TestOperationMarshalJSON(t *testing.T) {
	t.Run("marshal select operation", func(t *testing.T) {
		op := NewSelectOperation("Bridge", []Condition{
			NewCondition("name", "==", "br0"),
		}, []string{"_uuid", "name"})

		data, err := json.Marshal(op)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Equal(t, "select", result["op"])
		assert.Equal(t, "Bridge", result["table"])
		assert.NotNil(t, result["where"])
		assert.NotNil(t, result["columns"])
	})

	t.Run("marshal insert operation", func(t *testing.T) {
		op := NewInsertOperation("Bridge", map[string]interface{}{
			"name": "br0",
		}, "new_bridge")

		data, err := json.Marshal(op)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Equal(t, "insert", result["op"])
		assert.Equal(t, "new_bridge", result["uuid-name"])
	})

	t.Run("marshal operation without where field", func(t *testing.T) {
		op := Operation{
			Op:    "select",
			Table: "Bridge",
			Where: nil, // Should be omitted
		}

		data, err := json.Marshal(op)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		_, hasWhere := result["where"]
		assert.False(t, hasWhere, "where should be omitted when nil")
	})

	t.Run("marshal operation with empty where", func(t *testing.T) {
		emptyWhere := [][]interface{}{}
		op := Operation{
			Op:    "select",
			Table: "Bridge",
			Where: &emptyWhere, // Should be included as []
		}

		data, err := json.Marshal(op)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		where, hasWhere := result["where"]
		assert.True(t, hasWhere, "where should be included when non-nil")
		assert.IsType(t, []interface{}{}, where)
	})
}

func TestJSONRPCRequestMarshal(t *testing.T) {
	t.Run("marshal request", func(t *testing.T) {
		req := &JSONRPCRequest{
			Method: "echo",
			Params: []interface{}{"test"},
			ID:     123,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		require.NoError(t, err)
		assert.Equal(t, "echo", result["method"])
		assert.Equal(t, float64(123), result["id"])
	})
}

func TestJSONRPCResponseUnmarshal(t *testing.T) {
	t.Run("unmarshal success response", func(t *testing.T) {
		jsonData := `{"result":["Open_vSwitch"],"id":1}`

		var resp JSONRPCResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.Nil(t, resp.Error)
		assert.NotNil(t, resp.Result)
		assert.Equal(t, uint64(1), resp.ID)

		var result []string
		err = json.Unmarshal(resp.Result, &result)
		require.NoError(t, err)
		assert.Contains(t, result, "Open_vSwitch")
	})

	t.Run("unmarshal error response", func(t *testing.T) {
		jsonData := `{"error":{"code":-1,"message":"test error"},"id":2}`

		var resp JSONRPCResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, -1, resp.Error.Code)
		assert.Equal(t, "test error", resp.Error.Message)
		assert.Equal(t, uint64(2), resp.ID)
	})

	t.Run("unmarshal response with data", func(t *testing.T) {
		jsonData := `{"error":{"code":-1,"message":"error","data":"extra info"},"id":3}`

		var resp JSONRPCResponse
		err := json.Unmarshal([]byte(jsonData), &resp)
		require.NoError(t, err)

		assert.NotNil(t, resp.Error)
		assert.Equal(t, "extra info", resp.Error.Data)
	})
}

func TestOperationResultUnmarshal(t *testing.T) {
	t.Run("unmarshal select result", func(t *testing.T) {
		jsonData := `{"rows":[{"_uuid":["uuid","test-uuid"],"name":"br0"}]}`

		var result OperationResult
		err := json.Unmarshal([]byte(jsonData), &result)
		require.NoError(t, err)

		assert.Len(t, result.Rows, 1)
		assert.Contains(t, result.Rows[0], "_uuid")
		assert.Contains(t, result.Rows[0], "name")
	})

	t.Run("unmarshal insert result", func(t *testing.T) {
		jsonData := `{"uuid":["uuid","new-uuid"]}`

		var result OperationResult
		err := json.Unmarshal([]byte(jsonData), &result)
		require.NoError(t, err)

		assert.NotNil(t, result.UUID)
		assert.Equal(t, "new-uuid", result.UUID.UUID)
	})

	t.Run("unmarshal update result", func(t *testing.T) {
		jsonData := `{"count":2}`

		var result OperationResult
		err := json.Unmarshal([]byte(jsonData), &result)
		require.NoError(t, err)

		assert.NotNil(t, result.Count)
		assert.Equal(t, 2, *result.Count)
	})

	t.Run("unmarshal error result", func(t *testing.T) {
		jsonData := `{"error":"table not found","details":"Bridge does not exist"}`

		var result OperationResult
		err := json.Unmarshal([]byte(jsonData), &result)
		require.NoError(t, err)

		assert.Equal(t, "table not found", result.Error)
		assert.Equal(t, "Bridge does not exist", result.Details)
	})
}

func TestTransactResponseUnmarshal(t *testing.T) {
	t.Run("unmarshal multiple results", func(t *testing.T) {
		jsonData := `[{"uuid":["uuid","uuid1"]},{"count":1}]`

		var results TransactResponse
		err := json.Unmarshal([]byte(jsonData), &results)
		require.NoError(t, err)

		assert.Len(t, results, 2)
		assert.NotNil(t, results[0].UUID)
		assert.NotNil(t, results[1].Count)
	})
}

func TestGetSchemaResultUnmarshal(t *testing.T) {
	t.Run("unmarshal schema", func(t *testing.T) {
		jsonData := `{
			"name":"Open_vSwitch",
			"version":"8.0.0",
			"tables":{
				"Bridge":{
					"columns":{
						"name":{"type":"string"},
						"ports":{"type":"set"}
					}
				}
			}
		}`

		var schema GetSchemaResult
		err := json.Unmarshal([]byte(jsonData), &schema)
		require.NoError(t, err)

		assert.Equal(t, "Open_vSwitch", schema.Name)
		assert.Equal(t, "8.0.0", schema.Version)
		assert.Contains(t, schema.Tables, "Bridge")
		assert.Contains(t, schema.Tables["Bridge"].Columns, "name")
		assert.Contains(t, schema.Tables["Bridge"].Columns, "ports")
	})
}

func TestNextRequestID(t *testing.T) {
	t.Run("sequential request IDs", func(t *testing.T) {
		id1 := nextRequestID()
		id2 := nextRequestID()
		id3 := nextRequestID()

		assert.Less(t, id1, id2)
		assert.Less(t, id2, id3)
	})
}
