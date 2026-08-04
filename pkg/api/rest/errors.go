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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// =============================================================================
// Common REST Handler Types
// =============================================================================

// ErrorResponse is the standard error response format for REST API errors.
type ErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// Common Request Validation Errors
// =============================================================================

// ErrInvalidRequestBody is returned when the request body is invalid.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrMissingRequiredField is returned when a required field is missing.
type ErrMissingRequiredField struct {
	Field string
}

func (e ErrMissingRequiredField) Error() string {
	return fmt.Sprintf("missing required field: %s", e.Field)
}

// ErrInvalidContainerID is returned when a container ID is invalid or empty.
type ErrInvalidContainerID struct {
	ID string
}

func (e ErrInvalidContainerID) Error() string {
	if e.ID == "" {
		return "container ID is required"
	}
	return fmt.Sprintf("invalid container ID: %s", e.ID)
}

// =============================================================================
// Common Query Parameter Helpers
// =============================================================================

// ParseIntParam parses an integer query parameter with a default value.
func ParseIntParam(r *http.Request, param string, defaultVal int) int {
	val := r.URL.Query().Get(param)
	if val == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultVal
	}
	return i
}

// ParseBoolParam parses a boolean query parameter with a default value.
func ParseBoolParam(r *http.Request, param string, defaultVal bool) bool {
	val := r.URL.Query().Get(param)
	if val == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return b
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
