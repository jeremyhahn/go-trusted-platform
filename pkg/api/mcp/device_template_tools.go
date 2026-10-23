// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// Device template tools are the MCP face of DeviceService.CreateTemplate
// and DeviceService.CreateProfileFromTemplate. They are unrelated to the
// vtpm_*_template_* tools, which manage vTPM templates.

// ErrDeviceTemplateNotConfigured indicates the device template backend is
// not wired into the MCP tool registry.
var ErrDeviceTemplateNotConfigured = &DeviceError{
	Code:    "DEVICE_TEMPLATE_NOT_CONFIGURED",
	Message: "device template service not configured",
}

// ErrTemplateNameRequired indicates a device template name is required.
var ErrTemplateNameRequired = &DeviceError{
	Code:    "TEMPLATE_NAME_REQUIRED",
	Message: "template name is required",
}

// ErrTemplateIDRequired indicates a device template ID is required.
var ErrTemplateIDRequired = &DeviceError{
	Code:    "TEMPLATE_ID_REQUIRED",
	Message: "template ID is required",
}

// DeviceTemplateProvider is the device template backend the template
// tools call. The daemon's MCP service provider implements it over the
// same device.DeviceTemplateService the REST template handlers use.
type DeviceTemplateProvider interface {
	// DeviceTemplateCreate persists a new device template, generating an
	// ID when the template carries none, and returns the stored template.
	DeviceTemplateCreate(ctx context.Context, template *entities.DeviceTemplate) (*entities.DeviceTemplate, error)

	// DeviceTemplateGet returns the stored template with the given ID.
	DeviceTemplateGet(ctx context.Context, id uint64) (*entities.DeviceTemplate, error)

	// DeviceTemplateList returns one page of templates and the total count.
	DeviceTemplateList(ctx context.Context, page, pageSize int) ([]*entities.DeviceTemplate, int, error)

	// DeviceTemplateUpdate replaces the stored template whose ID the
	// template carries and returns it.
	DeviceTemplateUpdate(ctx context.Context, template *entities.DeviceTemplate) (*entities.DeviceTemplate, error)

	// DeviceTemplateDelete removes the stored template with the given ID.
	DeviceTemplateDelete(ctx context.Context, id uint64) error

	// DeviceProfileFromTemplate builds a profile from a stored template,
	// applying the non-zero override fields, saves it and returns it.
	DeviceProfileFromTemplate(ctx context.Context, templateID uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error)
}

// deviceTemplateProvider returns the registry's service as a
// DeviceTemplateProvider, or nil when it does not implement one.
func (r *ToolRegistry) deviceTemplateProvider() DeviceTemplateProvider {
	if p, ok := r.service.(DeviceTemplateProvider); ok {
		return p
	}
	return nil
}

// deviceTemplateToolRequest is the device_template_create argument shape.
// Config is the template's platform configuration as YAML text.
type deviceTemplateToolRequest struct {
	TenantID    string                      `json:"tenant_id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
	Role        string                      `json:"role"`
	Config      string                      `json:"config"`
	MatchRules  *entities.ProfileMatchRules `json:"match_rules"`
}

// deviceProfileFromTemplateToolRequest is the profile_create_from_template
// argument shape. template_id is read separately so a string id survives.
type deviceProfileFromTemplateToolRequest struct {
	Overrides deviceProfileToolRequest `json:"overrides"`
}

func (r *ToolRegistry) executeDeviceTemplateCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceTemplateProvider()
	if p == nil {
		return nil, ErrDeviceTemplateNotConfigured
	}

	req, err := decodeToolArgs[deviceTemplateToolRequest](args)
	if err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, ErrTemplateNameRequired
	}

	created, err := p.DeviceTemplateCreate(ctx, req.toEntity())
	if err != nil {
		return nil, err
	}
	return deviceTemplateToolResult(created)
}

// toEntity builds the device template the request describes.
func (req *deviceTemplateToolRequest) toEntity() *entities.DeviceTemplate {
	template := &entities.DeviceTemplate{
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Role:        entities.DeviceRole(req.Role),
		MatchRules:  req.MatchRules,
	}
	if req.Config != "" {
		template.Config = []byte(req.Config)
	}
	return template
}

// executeDeviceTemplateGet handles the device_template_get tool.
func (r *ToolRegistry) executeDeviceTemplateGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceTemplateProvider()
	if p == nil {
		return nil, ErrDeviceTemplateNotConfigured
	}
	id := uint64(getInt64(args, "id"))
	if id == 0 {
		return nil, ErrTemplateIDRequired
	}
	template, err := p.DeviceTemplateGet(ctx, id)
	if err != nil {
		return nil, err
	}
	return deviceTemplateToolResult(template)
}

// executeDeviceTemplateList handles the device_template_list tool.
func (r *ToolRegistry) executeDeviceTemplateList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceTemplateProvider()
	if p == nil {
		return nil, ErrDeviceTemplateNotConfigured
	}

	page := getInt(args, "page")
	if page <= 0 {
		page = 1
	}
	pageSize := getInt(args, "page_size")
	if pageSize <= 0 {
		pageSize = 50
	}

	templates, total, err := p.DeviceTemplateList(ctx, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]interface{}, 0, len(templates))
	for _, template := range templates {
		result, err := deviceTemplateToolResult(template)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return map[string]interface{}{
		"templates": results,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	}, nil
}

// executeDeviceTemplateUpdate handles the device_template_update tool. The
// update replaces the stored template, as DeviceService.UpdateTemplate does:
// a field the arguments omit is cleared, not kept.
func (r *ToolRegistry) executeDeviceTemplateUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceTemplateProvider()
	if p == nil {
		return nil, ErrDeviceTemplateNotConfigured
	}
	id := uint64(getInt64(args, "id"))
	if id == 0 {
		return nil, ErrTemplateIDRequired
	}

	req, err := decodeToolArgs[deviceTemplateToolRequest](args)
	if err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, ErrTemplateNameRequired
	}

	template := req.toEntity()
	template.ID = id
	updated, err := p.DeviceTemplateUpdate(ctx, template)
	if err != nil {
		return nil, err
	}
	return deviceTemplateToolResult(updated)
}

// executeDeviceTemplateDelete handles the device_template_delete tool.
func (r *ToolRegistry) executeDeviceTemplateDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceTemplateProvider()
	if p == nil {
		return nil, ErrDeviceTemplateNotConfigured
	}
	id := uint64(getInt64(args, "id"))
	if id == 0 {
		return nil, ErrTemplateIDRequired
	}
	if err := p.DeviceTemplateDelete(ctx, id); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "id": formatUint64ID(id)}, nil
}

func (r *ToolRegistry) executeDeviceProfileFromTemplate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceTemplateProvider()
	if p == nil {
		return nil, ErrDeviceTemplateNotConfigured
	}

	templateID := uint64(getInt64(args, "template_id"))
	if templateID == 0 {
		return nil, ErrTemplateIDRequired
	}
	req, err := decodeToolArgs[deviceProfileFromTemplateToolRequest](args)
	if err != nil {
		return nil, err
	}
	overrides, err := req.Overrides.toEntity()
	if err != nil {
		return nil, err
	}

	profile, err := p.DeviceProfileFromTemplate(ctx, templateID, overrides)
	if err != nil {
		return nil, err
	}
	return deviceProfileToolResult(profile)
}

// deviceTemplateToolResult renders a template with its config as the
// YAML text the tool accepted, not the base64 a []byte marshals to.
func deviceTemplateToolResult(template *entities.DeviceTemplate) (interface{}, error) {
	result, err := entityToolResult(template, template.ID)
	if err != nil {
		return nil, err
	}
	if len(template.Config) > 0 {
		result["config"] = string(template.Config)
	}
	return result, nil
}

// registerDeviceTemplateTools registers the device template tools.
func (r *ToolRegistry) registerDeviceTemplateTools() {
	r.addTool(mcpwire.ToolDefinition{
		Name:        "device_template_create",
		Description: "Create a device template: a reusable platform configuration, role and match rules that device profiles are built from (DeviceService.CreateTemplate). Not a vTPM template.",
		InputSchema: deviceTemplateFieldsSchema(),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "device_template_get",
		Description: "Get a device template by ID (DeviceService.GetTemplate)",
		InputSchema: deviceTemplateIDSchema("Device template ID"),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "device_template_list",
		Description: "List device templates with pagination (DeviceService.ListTemplates)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "Page number (default 1)",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Templates per page (default 50)",
				},
			},
		},
	})

	updateSchema := deviceTemplateFieldsSchema()
	updateSchema["properties"].(map[string]interface{})["id"] = map[string]interface{}{
		"type":        "integer",
		"description": "ID of the device template to replace",
	}
	updateSchema["required"] = []string{"id", "name"}
	r.addTool(mcpwire.ToolDefinition{
		Name:        "device_template_update",
		Description: "Replace a stored device template (DeviceService.UpdateTemplate). Every field is replaced: an omitted field is cleared. The creation time is kept.",
		InputSchema: updateSchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "device_template_delete",
		Description: "Delete a device template by ID (DeviceService.DeleteTemplate)",
		InputSchema: deviceTemplateIDSchema("ID of the device template to delete"),
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "profile_create_from_template",
		Description: "Build a device profile from a stored device template and save it (DeviceService.CreateProfileFromTemplate). The profile inherits the template's tenant, role, config and match rules; non-empty override fields replace them.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"template_id": map[string]interface{}{
					"type":        "integer",
					"description": "Device template ID to build the profile from",
				},
				"overrides": map[string]interface{}{
					"type":        "object",
					"description": "Profile fields that replace the template's, using the profile_create argument names (name, ek_serial, ek_cert, mac_address, role, zone, ...)",
				},
			},
			"required": []string{"template_id"},
		},
	})
}

// deviceTemplateFieldsSchema returns the input schema of the template
// fields device_template_create takes and device_template_update replaces.
// Each call builds a new map, so a caller may extend it.
func deviceTemplateFieldsSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"tenant_id": map[string]interface{}{
				"type":        "string",
				"description": "Tenant that owns the template",
			},
			"name": map[string]interface{}{
				"type":        "string",
				"description": "Template name",
			},
			"description": map[string]interface{}{
				"type":        "string",
				"description": "Free-form description",
			},
			"role": map[string]interface{}{
				"type":        "string",
				"description": "Device role profiles built from this template take (e.g. server, edge, gateway)",
			},
			"config": map[string]interface{}{
				"type":        "string",
				"description": "Platform configuration as YAML text",
			},
			"match_rules": map[string]interface{}{
				"type":        "object",
				"description": "Rules that auto-assign profiles built from this template (mac_prefix, serial_prefix, model, ...)",
			},
		},
		"required": []string{"name"},
	}
}

// deviceTemplateIDSchema returns an input schema that takes only the
// template ID.
func deviceTemplateIDSchema(description string) map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"id": map[string]interface{}{
				"type":        "integer",
				"description": description,
			},
		},
		"required": []string{"id"},
	}
}
