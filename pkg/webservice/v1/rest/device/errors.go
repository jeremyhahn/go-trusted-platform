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

// ErrMissingRole indicates the role field is required but not provided.
type ErrMissingRole struct{}

func (e ErrMissingRole) Error() string {
	return "device: role is required"
}

// ErrMissingTemplate indicates the template field is required but not provided.
type ErrMissingTemplate struct{}

func (e ErrMissingTemplate) Error() string {
	return "device: template payload is required"
}

// ErrInvalidRequestBody indicates the request body could not be decoded.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	if e.Reason != "" {
		return "device: invalid request body: " + e.Reason
	}
	return "device: invalid request body"
}

// ErrInvalidTemplateID indicates the template ID in the URL is not valid.
type ErrInvalidTemplateID struct{}

func (e ErrInvalidTemplateID) Error() string {
	return "device: invalid template id"
}

// ErrTemplateSaveFailed indicates the template could not be saved.
type ErrTemplateSaveFailed struct {
	Cause error
}

func (e ErrTemplateSaveFailed) Error() string {
	if e.Cause != nil {
		return "device: failed to save template: " + e.Cause.Error()
	}
	return "device: failed to save template"
}

// ErrProfileCreateFailed indicates the profile could not be created from the template.
type ErrProfileCreateFailed struct {
	Cause error
}

func (e ErrProfileCreateFailed) Error() string {
	if e.Cause != nil {
		return "device: failed to create profile: " + e.Cause.Error()
	}
	return "device: failed to create profile"
}

// ErrProfileSaveFailed indicates the profile could not be saved.
type ErrProfileSaveFailed struct {
	Cause error
}

func (e ErrProfileSaveFailed) Error() string {
	if e.Cause != nil {
		return "device: failed to save profile: " + e.Cause.Error()
	}
	return "device: failed to save profile"
}

// ErrTemplateServiceNil indicates the template service is not initialized.
type ErrTemplateServiceNil struct{}

func (e ErrTemplateServiceNil) Error() string {
	return "device: template service not initialized"
}

// ErrProfileServiceNil indicates the profile service is not initialized.
type ErrProfileServiceNil struct{}

func (e ErrProfileServiceNil) Error() string {
	return "device: profile service not initialized"
}

// ErrMissingHostname indicates the hostname field is required but not provided.
type ErrMissingHostname struct{}

func (e ErrMissingHostname) Error() string {
	return "device: hostname is required"
}

// ErrInvalidProfileConfig indicates the create-profile request's config
// field is not a JSON object.
type ErrInvalidProfileConfig struct {
	Cause error
}

func (e ErrInvalidProfileConfig) Error() string {
	return "device: profile config must be a JSON object: " + e.Cause.Error()
}

func (e ErrInvalidProfileConfig) Unwrap() error {
	return e.Cause
}

// ErrProfileConfigNull indicates the create-profile request supplied an
// explicit JSON null for config, which is not an object.
type ErrProfileConfigNull struct{}

func (e ErrProfileConfigNull) Error() string {
	return "config is null"
}

// ErrEKCertNotAccepted indicates the create-profile request carried an
// ek_cert. The seeder route is unauthenticated, so it refuses to prestage
// hardware identity; EK binding belongs to the authenticated assign route.
type ErrEKCertNotAccepted struct{}

func (e ErrEKCertNotAccepted) Error() string {
	return "device: ek_cert is not accepted on the unauthenticated create-profile route; bind the EK via POST /api/v1/device/profiles/{id}/assign"
}

// ErrMissingDeviceIdentifier indicates that at least one of mac or serial query
// parameters is required.
type ErrMissingDeviceIdentifier struct{}

func (e ErrMissingDeviceIdentifier) Error() string {
	return "device: at least one of mac or serial query parameter is required"
}

// ErrProfileNotFound indicates that no profile was found matching the device
// identifier.
type ErrProfileNotFound struct {
	MAC    string
	Serial string
}

func (e ErrProfileNotFound) Error() string {
	return "device: no matching profile found for mac=" + e.MAC + " serial=" + e.Serial
}

// ErrProfileConfigEmpty indicates that the matched profile has no config.
type ErrProfileConfigEmpty struct {
	ProfileID uint64
}

func (e ErrProfileConfigEmpty) Error() string {
	return "device: profile has no config"
}

// ErrConfigMarshalFailed indicates YAML marshaling of the profile config failed.
type ErrConfigMarshalFailed struct {
	Cause error
}

func (e ErrConfigMarshalFailed) Error() string {
	if e.Cause != nil {
		return "device: failed to marshal config: " + e.Cause.Error()
	}
	return "device: failed to marshal config"
}
