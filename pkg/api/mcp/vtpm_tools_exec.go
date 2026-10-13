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

package mcp

import (
	"context"
	"encoding/base64"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// ekAlgorithmArg reads the optional "algorithm" argument of the vTPM create
// tools as the canonical EK algorithm name. Absent is empty, so the service
// applies its configured default; anything but RSA or ECC (in any case) is
// InvalidArgument rather than an RSA EK.
func ekAlgorithmArg(args map[string]interface{}) (string, error) {
	alg, err := vtpm.ParseEKAlgorithm(getString(args, "algorithm"))
	if err != nil {
		return "", ErrInvalidArgument{Msg: "invalid algorithm", Cause: err}
	}
	return string(alg), nil
}

// =============================================================================
// vTPM Extended Tool Execution Functions
// =============================================================================

// executeVTPMGet retrieves a vTPM bundle by name.
func (r *ToolRegistry) executeVTPMGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMGet(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMValidate validates bundle integrity.
func (r *ToolRegistry) executeVTPMValidate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMValidate(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMExport exports a bundle to a base64-encoded archive.
func (r *ToolRegistry) executeVTPMExport(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMExport(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMImport imports a bundle from base64-encoded archive data.
func (r *ToolRegistry) executeVTPMImport(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	dataB64 := getString(args, "data")
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, ErrVTPMInvalidData
	}
	result, err := r.service.VTPMImport(ctx, data)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMTemplateCreate creates a new vTPM template.
func (r *ToolRegistry) executeVTPMTemplateCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	description := getString(args, "description")
	algorithm, err := ekAlgorithmArg(args)
	if err != nil {
		return nil, err
	}
	secureBoot := getBool(args, "secure_boot")

	result, err := r.service.VTPMCreateTemplate(ctx, id, description, algorithm, secureBoot)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMTemplateGet retrieves a template by ID.
func (r *ToolRegistry) executeVTPMTemplateGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	result, err := r.service.VTPMGetTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMTemplateDelete deletes a template.
func (r *ToolRegistry) executeVTPMTemplateDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	id := getString(args, "id")
	if err := r.service.VTPMDeleteTemplate(ctx, id); err != nil {
		return nil, err
	}
	return map[string]interface{}{"id": id, "deleted": true}, nil
}

// executeVTPMTemplateList lists all templates.
func (r *ToolRegistry) executeVTPMTemplateList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.VTPMListTemplates(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMTemplateClone clones a template to create a new bundle.
func (r *ToolRegistry) executeVTPMTemplateClone(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	templateID := getString(args, "template_id")
	hostname := getString(args, "hostname")
	labels := getStringMap(args, "labels")

	result, err := r.service.VTPMCloneTemplate(ctx, templateID, hostname, labels)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMGetBundlePath returns the filesystem path to a bundle.
func (r *ToolRegistry) executeVTPMGetBundlePath(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMGetBundlePath(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMGetTPMSocketPath returns the TPM socket path for a bundle.
func (r *ToolRegistry) executeVTPMGetTPMSocketPath(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMGetTPMSocketPath(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMGetNVRAMPath returns the OVMF NVRAM path for a bundle.
func (r *ToolRegistry) executeVTPMGetNVRAMPath(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMGetNVRAMPath(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeVTPMIsRunning checks if a vTPM bundle is running.
func (r *ToolRegistry) executeVTPMIsRunning(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	result, err := r.service.VTPMIsRunning(ctx, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
