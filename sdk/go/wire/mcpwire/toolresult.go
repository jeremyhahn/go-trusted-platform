package mcpwire

import (
	"encoding/json"
)

// ErrToolResultShape reports a tools/call result that is not a
// CallToolResult with a JSON text block.
type ErrToolResultShape struct {
	Reason string
}

// Error implements the error interface.
func (e *ErrToolResultShape) Error() string {
	return "mcp: tools/call result is not a CallToolResult: " + e.Reason
}

// ErrToolFailed reports a CallToolResult whose isError is set; Message is
// the text of its first text block.
type ErrToolFailed struct {
	Message string
}

// Error implements the error interface.
func (e *ErrToolFailed) Error() string {
	return "mcp: tool reported an error: " + e.Message
}

// NewCallToolResult wraps a tool's output in the CallToolResult tools/call
// answers: one text block holding the output's JSON encoding.
func NewCallToolResult(output interface{}) (*CallToolResult, error) {
	encoded, err := json.Marshal(output)
	if err != nil {
		return nil, &ErrToolResultShape{Reason: err.Error()}
	}
	return &CallToolResult{
		Content: []ContentBlock{{Type: ContentTypeText, Text: string(encoded)}},
	}, nil
}

// ToolOutput returns the tool output a decoded tools/call result carries:
// the JSON value its first text block encodes (see CallToolResult).
func ToolOutput(result interface{}) (interface{}, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, &ErrToolResultShape{Reason: err.Error()}
	}
	var output interface{}
	if err := DecodeToolOutput(encoded, &output); err != nil {
		return nil, err
	}
	return output, nil
}

// ToolOutputJSON returns the JSON tool output carried by the text block of
// raw, an encoded tools/call result. A result with isError set answers
// ErrToolFailed; a result that is not a CallToolResult, has no text block,
// or whose text is not JSON answers ErrToolResultShape.
func ToolOutputJSON(raw []byte) (json.RawMessage, error) {
	var call CallToolResult
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, &ErrToolResultShape{Reason: err.Error()}
	}
	text, found := firstText(call.Content)
	if call.IsError {
		return nil, &ErrToolFailed{Message: text}
	}
	if !found {
		return nil, &ErrToolResultShape{Reason: "no text content block"}
	}
	if !json.Valid([]byte(text)) {
		return nil, &ErrToolResultShape{Reason: "text content block is not JSON"}
	}
	return json.RawMessage(text), nil
}

// DecodeToolOutput decodes the tool output carried by raw, an encoded
// tools/call result, into out. It fails as ToolOutputJSON does.
func DecodeToolOutput(raw []byte, out interface{}) error {
	output, err := ToolOutputJSON(raw)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(output, out); err != nil {
		return &ErrToolResultShape{Reason: "tool output does not decode: " + err.Error()}
	}
	return nil
}

// firstText returns the text of the first text content block.
func firstText(blocks []ContentBlock) (string, bool) {
	for _, block := range blocks {
		if block.Type == ContentTypeText {
			return block.Text, true
		}
	}
	return "", false
}
