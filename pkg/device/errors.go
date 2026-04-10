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

package device

import "fmt"

// ErrProfileNotAssigned indicates the profile is not assigned to a device.
type ErrProfileNotAssigned struct {
	ID uint64
}

// Error returns the error message.
func (e ErrProfileNotAssigned) Error() string {
	return fmt.Sprintf("device: profile %d is not assigned to a device", e.ID)
}

// ErrDeviceIdentityRequired indicates at least one device identifier is required.
type ErrDeviceIdentityRequired struct{}

// Error returns the error message.
func (e ErrDeviceIdentityRequired) Error() string {
	return "device: at least one of ek_serial or mac_address is required"
}

// ErrNoMatchingConfig indicates no config was found for the device.
type ErrNoMatchingConfig struct {
	EKSerial string
	MAC      string
}

// Error returns the error message.
func (e ErrNoMatchingConfig) Error() string {
	return fmt.Sprintf("device: no matching config found for ek_serial=%q mac=%q", e.EKSerial, e.MAC)
}

// ErrInvalidTemplateID indicates an invalid or zero template ID was provided.
type ErrInvalidTemplateID struct{}

// Error returns the error message.
func (e ErrInvalidTemplateID) Error() string {
	return "device: invalid template ID"
}

// ErrTemplateNotFound indicates the requested template was not found.
type ErrTemplateNotFound struct {
	ID uint64
}

// Error returns the error message.
func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("device: template not found: %d", e.ID)
}

// ErrTemplateNameRequired indicates a template name is required.
type ErrTemplateNameRequired struct{}

// Error returns the error message.
func (e ErrTemplateNameRequired) Error() string {
	return "device: template name is required"
}

// ErrDuplicateTemplateName indicates a template with this name already exists.
type ErrDuplicateTemplateName struct {
	Name string
}

// Error returns the error message.
func (e ErrDuplicateTemplateName) Error() string {
	return fmt.Sprintf("device: duplicate template name: %s", e.Name)
}

// ErrNilTemplate indicates a nil template was provided.
type ErrNilTemplate struct{}

// Error returns the error message.
func (e ErrNilTemplate) Error() string {
	return "device: nil template"
}

// ErrTemplateConfigRequired indicates a template config is required for conversion.
type ErrTemplateConfigRequired struct{}

// Error returns the error message.
func (e ErrTemplateConfigRequired) Error() string {
	return "device: template config is required for profile conversion"
}
