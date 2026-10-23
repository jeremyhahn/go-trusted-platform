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

// Package restwire is the platform REST wire contract: the response envelope
// every /api/v1 handler writes. The daemon's response writer
// (pkg/webservice/v1/response) and the SDK REST clients import this one
// definition, so the two cannot drift.
package restwire

// WebServiceResponse is the JSON/YAML envelope around every REST response.
// Success responses carry the result in Payload; error responses carry the
// message in Error.
type WebServiceResponse struct {
	Code    int         `yaml:"code" json:"code"`
	Error   string      `yaml:"error" json:"error"`
	Success bool        `yaml:"success" json:"success"`
	Payload interface{} `yaml:"payload" json:"payload"`
}
