package mcpwire

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewCallToolResult(t *testing.T) {
	t.Run("encodes the output as one JSON text block", func(t *testing.T) {
		result, err := NewCallToolResult(map[string]interface{}{"name": "k1"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Content) != 1 {
			t.Fatalf("len(Content) = %d, want 1", len(result.Content))
		}
		block := result.Content[0]
		if block.Type != ContentTypeText || block.Text != `{"name":"k1"}` {
			t.Errorf("block = %+v, want a text block holding {\"name\":\"k1\"}", block)
		}
		if result.IsError {
			t.Error("IsError must be false for a tool output")
		}
	})

	t.Run("refuses an output JSON cannot encode", func(t *testing.T) {
		_, err := NewCallToolResult(make(chan int))
		var shapeErr *ErrToolResultShape
		if !errors.As(err, &shapeErr) {
			t.Errorf("err = %v, want ErrToolResultShape", err)
		}
	})
}

func TestToolOutput(t *testing.T) {
	t.Run("returns the output a CallToolResult carries", func(t *testing.T) {
		wrapped, err := NewCallToolResult(map[string]interface{}{"count": 2})
		if err != nil {
			t.Fatalf("NewCallToolResult: %v", err)
		}
		// The client sees the result decoded from JSON, not the struct.
		decoded := map[string]interface{}{"content": []interface{}{
			map[string]interface{}{"type": "text", "text": wrapped.Content[0].Text},
		}}
		output, err := ToolOutput(decoded)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		fields, ok := output.(map[string]interface{})
		if !ok || fields["count"] != float64(2) {
			t.Errorf("output = %v, want map with count 2", output)
		}
	})

	failures := []struct {
		name   string
		result interface{}
		check  func(t *testing.T, err error)
	}{
		{
			name: "isError is a tool failure",
			result: map[string]interface{}{"isError": true, "content": []interface{}{
				map[string]interface{}{"type": "text", "text": "refused"},
			}},
			check: func(t *testing.T, err error) {
				var toolErr *ErrToolFailed
				if !errors.As(err, &toolErr) || toolErr.Message != "refused" {
					t.Errorf("err = %v, want ErrToolFailed with message refused", err)
				}
			},
		},
		{
			name:   "a raw output has no text block",
			result: map[string]interface{}{"ok": true},
			check:  wantShapeError,
		},
		{
			name: "a text block that is not JSON",
			result: map[string]interface{}{"content": []interface{}{
				map[string]interface{}{"type": "text", "text": "plain words"},
			}},
			check: wantShapeError,
		},
		{
			name:   "a result that is not an object",
			result: "not a map",
			check:  wantShapeError,
		},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			output, err := ToolOutput(tt.result)
			if output != nil {
				t.Errorf("output = %v, want nil", output)
			}
			tt.check(t, err)
		})
	}
}

func TestDecodeToolOutput(t *testing.T) {
	t.Run("decodes the output into a typed value", func(t *testing.T) {
		wrapped, err := NewCallToolResult(map[string]interface{}{"name": "k1", "version": 3})
		if err != nil {
			t.Fatalf("NewCallToolResult: %v", err)
		}
		raw, err := json.Marshal(wrapped)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var out struct {
			Name    string `json:"name"`
			Version int    `json:"version"`
		}
		if err := DecodeToolOutput(raw, &out); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out.Name != "k1" || out.Version != 3 {
			t.Errorf("out = %+v, want name k1 version 3", out)
		}
	})

	failures := []struct {
		name  string
		raw   string
		check func(t *testing.T, err error)
	}{
		{
			name: "isError is a tool failure",
			raw:  `{"isError":true,"content":[{"type":"text","text":"refused"}]}`,
			check: func(t *testing.T, err error) {
				var toolErr *ErrToolFailed
				if !errors.As(err, &toolErr) || toolErr.Message != "refused" {
					t.Errorf("err = %v, want ErrToolFailed with message refused", err)
				}
			},
		},
		{name: "the bare output of the old wire", raw: `{"name":"k1"}`, check: wantShapeError},
		{name: "a text block that is not JSON", raw: `{"content":[{"type":"text","text":"plain"}]}`, check: wantShapeError},
		{name: "output of the wrong type", raw: `{"content":[{"type":"text","text":"[1]"}]}`, check: wantShapeError},
		{name: "not JSON at all", raw: `not json`, check: wantShapeError},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			var out struct {
				Name string `json:"name"`
			}
			tt.check(t, DecodeToolOutput([]byte(tt.raw), &out))
		})
	}
}

func TestToolOutputJSON(t *testing.T) {
	output, err := ToolOutputJSON([]byte(`{"content":[{"type":"image","data":"x"},{"type":"text","text":"{\"ok\":true}"}]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(output) != `{"ok":true}` {
		t.Errorf("output = %s, want the first text block", output)
	}

	_, err = ToolOutputJSON([]byte(`{"content":[]}`))
	wantShapeError(t, err)
}

func wantShapeError(t *testing.T, err error) {
	t.Helper()
	var shapeErr *ErrToolResultShape
	if !errors.As(err, &shapeErr) {
		t.Errorf("err = %v, want ErrToolResultShape", err)
	}
}
