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

package prompt

import "fmt"

// PromptWriteError indicates a failure to write the prompt message.
type PromptWriteError struct {
	Message string
	Err     error
}

// Error returns the error message.
func (e *PromptWriteError) Error() string {
	return fmt.Sprintf("failed to write prompt message '%s': %v", e.Message, e.Err)
}

// Unwrap returns the underlying error.
func (e *PromptWriteError) Unwrap() error {
	return e.Err
}

// PromptReadError indicates a failure to read input from the prompt.
type PromptReadError struct {
	Err error
}

// Error returns the error message.
func (e *PromptReadError) Error() string {
	return fmt.Sprintf("failed to read prompt input: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *PromptReadError) Unwrap() error {
	return e.Err
}

// PasswordReadError indicates a failure to read password input.
type PasswordReadError struct {
	Err error
}

// Error returns the error message.
func (e *PasswordReadError) Error() string {
	return fmt.Sprintf("failed to read password: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *PasswordReadError) Unwrap() error {
	return e.Err
}
