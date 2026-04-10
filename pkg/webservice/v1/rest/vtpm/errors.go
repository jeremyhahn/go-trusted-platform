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

package vtpm

import "fmt"

// ErrMissingBundleID is returned when bundle ID is required but not provided.
type ErrMissingBundleID struct{}

func (e ErrMissingBundleID) Error() string {
	return "bundle ID is required"
}

// ErrMissingTemplateID is returned when template ID is required but not provided.
type ErrMissingTemplateID struct{}

func (e ErrMissingTemplateID) Error() string {
	return "template ID is required"
}

// ErrInvalidRequestBody is returned when the request body cannot be parsed.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrInvalidBundleMode is returned when the bundle mode is invalid.
type ErrInvalidBundleMode struct {
	Mode string
}

func (e ErrInvalidBundleMode) Error() string {
	return fmt.Sprintf("invalid bundle mode: %s", e.Mode)
}

// ErrInvalidEKAlgorithm is returned when the EK algorithm is invalid.
type ErrInvalidEKAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidEKAlgorithm) Error() string {
	return fmt.Sprintf("invalid EK algorithm: %s", e.Algorithm)
}

// ErrBundleNotFound is returned when a bundle is not found.
type ErrBundleNotFound struct {
	ID string
}

func (e ErrBundleNotFound) Error() string {
	return fmt.Sprintf("bundle not found: %s", e.ID)
}

// ErrTemplateNotFound is returned when a template is not found.
type ErrTemplateNotFound struct {
	ID string
}

func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("template not found: %s", e.ID)
}

// ErrExportFailed is returned when bundle export fails.
type ErrExportFailed struct {
	Reason string
}

func (e ErrExportFailed) Error() string {
	return fmt.Sprintf("bundle export failed: %s", e.Reason)
}

// ErrImportFailed is returned when bundle import fails.
type ErrImportFailed struct {
	Reason string
}

func (e ErrImportFailed) Error() string {
	return fmt.Sprintf("bundle import failed: %s", e.Reason)
}

// ErrValidationFailed is returned when bundle validation fails.
type ErrValidationFailed struct {
	Errors []string
}

func (e ErrValidationFailed) Error() string {
	return fmt.Sprintf("bundle validation failed: %v", e.Errors)
}

// ErrMissingHostname is returned when hostname is required but not provided.
type ErrMissingHostname struct{}

func (e ErrMissingHostname) Error() string {
	return "hostname is required for pre-assigned bundles"
}
