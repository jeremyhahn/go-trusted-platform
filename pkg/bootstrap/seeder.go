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

package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// templateRequest is the JSON body for uploading a device template.
type templateRequest struct {
	Role     string          `json:"role"`
	Template json.RawMessage `json:"template"`
}

// templateResponse is the response after creating a device template.
type templateResponse struct {
	ID string `json:"id"`
}

// profileRequest is the JSON body for creating a device profile.
// The Config field carries the MERGED template + overrides so the
// control plane can deliver the complete configuration to the node
// on first boot via config fetch.
type profileRequest struct {
	MAC      string          `json:"mac"`
	Hostname string          `json:"hostname"`
	Role     string          `json:"role"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// SeederParams holds the dependencies for creating a Seeder.
type SeederParams struct {
	ControlPlaneAddr string
	Config           *BootstrapConfig
	Discovered       []DiscoveredNode
	Logger           *slog.Logger
}

// Seeder uploads device templates and creates per-node profiles on the control plane.
type Seeder struct {
	controlPlaneAddr string
	config           *BootstrapConfig
	discovered       []DiscoveredNode
	logger           *slog.Logger
	client           *http.Client
}

// NewSeeder creates a Seeder from the given parameters.
func NewSeeder(params SeederParams) *Seeder {
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// During bootstrap the CA is not yet trusted on the workstation running the
	// seeder. InsecureSkipVerify is required and a warning is logged.
	logger.Warn("bootstrap: seeder using insecure TLS (CA not yet trusted)")

	return &Seeder{
		controlPlaneAddr: params.ControlPlaneAddr,
		config:           params.Config,
		discovered:       params.Discovered,
		logger:           logger,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Force pure-Go DNS resolver to avoid SIGFPE in CGO's
				// getaddrinfo when running as a statically linked binary.
				DialContext: (&net.Dialer{
					Timeout:  10 * time.Second,
					Resolver: &net.Resolver{PreferGo: true},
				}).DialContext,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // Required during bootstrap before CA is trusted.
				},
			},
		},
	}
}

// Seed uploads templates for each role and creates profiles for all discovered nodes.
func (s *Seeder) Seed(ctx context.Context) error {
	if s.controlPlaneAddr == "" {
		return ErrMissingSeederAddr{}
	}

	// Step 1: Upload each template and collect role -> template ID.
	templateIDs, err := s.uploadTemplates(ctx)
	if err != nil {
		return ErrSeedFailed{Cause: err}
	}

	// Step 2: Create a profile for each discovered node with the merged
	// template + override config.
	if err := s.createProfiles(ctx, templateIDs); err != nil {
		return ErrSeedFailed{Cause: err}
	}

	s.logger.Info("bootstrap: template seeding complete",
		slog.Int("templates", len(templateIDs)),
		slog.Int("profiles", len(s.discovered)))

	return nil
}

// uploadTemplates reads each template file and POSTs it to the control plane.
// Returns a map of role -> template ID from the server response.
func (s *Seeder) uploadTemplates(ctx context.Context) (map[string]string, error) {
	templateIDs := make(map[string]string, len(s.config.Templates))

	for role, path := range s.config.Templates {
		s.logger.Info("bootstrap: uploading template",
			slog.String("role", role),
			slog.String("path", path))

		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrTemplateFileNotFound{Role: role, Path: path}
			}
			return nil, ErrTemplateUploadFailed{Role: role, Cause: err}
		}

		// Parse the YAML into a generic structure to strip comments and
		// produce clean data suitable for JSON marshaling. Raw YAML bytes
		// cannot be used as json.RawMessage because YAML comments (lines
		// starting with '#') are not valid JSON.
		templateJSON, err := yamlToJSON(data, role, path)
		if err != nil {
			return nil, err
		}

		body := templateRequest{
			Role:     role,
			Template: templateJSON,
		}

		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, ErrTemplateUploadFailed{Role: role, Cause: err}
		}

		url := "https://" + s.controlPlaneAddr + "/api/v1/devices/templates"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
		if err != nil {
			return nil, ErrTemplateUploadFailed{Role: role, Cause: err}
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, ErrTemplateUploadFailed{Role: role, Cause: err}
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return nil, ErrTemplateUploadFailed{
				Role:       role,
				StatusCode: resp.StatusCode,
			}
		}

		if readErr != nil {
			return nil, ErrTemplateUploadFailed{Role: role, Cause: readErr}
		}

		// The REST API wraps responses in {code, success, payload}.
		// Extract the payload to get the template ID.
		var envelope struct {
			Payload templateResponse `json:"payload"`
		}
		if err := json.Unmarshal(respBody, &envelope); err != nil {
			return nil, ErrTemplateUploadFailed{Role: role, Cause: err}
		}

		templateIDs[role] = envelope.Payload.ID
		s.logger.Info("bootstrap: template uploaded",
			slog.String("role", role),
			slog.String("template_id", envelope.Payload.ID))
	}

	return templateIDs, nil
}

// yamlToJSON parses raw YAML bytes into a generic structure and marshals the
// result to JSON. This strips YAML comments and produces valid JSON suitable
// for use as json.RawMessage. The role and path parameters are used only for
// error context.
func yamlToJSON(data []byte, role, path string) (json.RawMessage, error) {
	var parsed interface{}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, ErrTemplateYAMLParseFailed{Role: role, Path: path, Cause: err}
	}

	jsonBytes, err := json.Marshal(parsed)
	if err != nil {
		return nil, ErrTemplateJSONConvertFailed{Role: role, Cause: err}
	}

	return json.RawMessage(jsonBytes), nil
}

// createProfiles POSTs a profile creation request for each discovered node.
// For each node, the profile carries the MERGED template + override config
// so the control plane delivers the complete, per-node configuration on
// first-boot config fetch.
func (s *Seeder) createProfiles(ctx context.Context, templateIDs map[string]string) error {
	for i := range s.discovered {
		node := &s.discovered[i]

		templateID, ok := templateIDs[node.Role]
		if !ok {
			s.logger.Warn("bootstrap: no template uploaded for role, skipping profile",
				slog.String("hostname", node.Hostname),
				slog.String("role", node.Role))
			continue
		}

		s.logger.Info("bootstrap: creating profile",
			slog.String("hostname", node.Hostname),
			slog.String("template_id", templateID))

		// Build the merged config: load the base template YAML, deep-merge
		// the node's overrides, and serialize to JSON for the profile.
		mergedConfig, mergeErr := s.buildMergedConfig(node)
		if mergeErr != nil {
			return ErrProfileCreateFailed{Hostname: node.Hostname, Cause: mergeErr}
		}

		body := profileRequest{
			MAC:      primaryDiscoveredMAC(node),
			Hostname: node.Hostname,
			Role:     node.Role,
			Config:   mergedConfig,
		}

		encoded, err := json.Marshal(body)
		if err != nil {
			return ErrProfileCreateFailed{Hostname: node.Hostname, Cause: err}
		}

		url := "https://" + s.controlPlaneAddr + "/api/v1/devices/templates/" + templateID + "/create-profile"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
		if err != nil {
			return ErrProfileCreateFailed{Hostname: node.Hostname, Cause: err}
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.client.Do(req)
		if err != nil {
			return ErrProfileCreateFailed{Hostname: node.Hostname, Cause: err}
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return ErrProfileCreateFailed{
				Hostname:   node.Hostname,
				StatusCode: resp.StatusCode,
			}
		}

		s.logger.Info("bootstrap: profile created",
			slog.String("hostname", node.Hostname),
			slog.String("template_id", templateID))
	}

	return nil
}

// buildMergedConfig loads the base template YAML for a node's role,
// deep-merges the node's per-host overrides, applies global platform
// identity fields, and returns the result as JSON. Returns nil when
// no template is configured for the role (the profile will be created
// without an explicit config, falling back to the template default).
func (s *Seeder) buildMergedConfig(node *DiscoveredNode) (json.RawMessage, error) {
	templatePath, ok := s.config.Templates[node.Role]
	if !ok {
		return nil, nil
	}

	data, err := os.ReadFile(templatePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrTemplateFileNotFound{Role: node.Role, Path: templatePath}
		}
		return nil, ErrTemplateMergeFailed{Hostname: node.Hostname, Role: node.Role, Cause: err}
	}

	var templateMap map[string]interface{}
	if err := yaml.Unmarshal(data, &templateMap); err != nil {
		return nil, ErrTemplateMergeFailed{Hostname: node.Hostname, Role: node.Role, Cause: err}
	}

	// Apply per-node overrides via deep merge.
	if len(node.Overrides) > 0 {
		templateMap = deepMergeSeeder(templateMap, node.Overrides)
	}

	// Apply global identity from platform config.
	applyGlobalIdentitySeeder(templateMap, &s.config.Platform)

	jsonBytes, err := json.Marshal(templateMap)
	if err != nil {
		return nil, ErrTemplateMergeFailed{Hostname: node.Hostname, Role: node.Role, Cause: err}
	}

	return json.RawMessage(jsonBytes), nil
}

// deepMergeSeeder recursively merges src into dst. Values in src take
// precedence. Maps are merged recursively; all other types are overwritten.
func deepMergeSeeder(dst, src map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(dst))
	for k, v := range dst {
		result[k] = v
	}
	for k, v := range src {
		existing, exists := result[k]
		if !exists {
			result[k] = v
			continue
		}
		existingMap, existingIsMap := existing.(map[string]interface{})
		srcMap, srcIsMap := v.(map[string]interface{})
		if existingIsMap && srcIsMap {
			result[k] = deepMergeSeeder(existingMap, srcMap)
		} else {
			result[k] = v
		}
	}
	return result
}

// applyGlobalIdentitySeeder fills empty top-level identity fields from the
// platform global configuration. Mirrors the logic in
// orchestrator_dryrun.go::applyGlobalIdentity but operates on the seeder's
// platform config.
func applyGlobalIdentitySeeder(m map[string]interface{}, platform *PlatformGlobalConfig) {
	if platform == nil {
		return
	}
	setIfEmpty := func(key, value string) {
		if value == "" {
			return
		}
		if val, ok := m[key]; ok {
			if s, isStr := val.(string); isStr && s == "" {
				m[key] = value
			}
		}
	}
	setIfEmpty("domain", platform.Domain)
	setIfEmpty("hostmaster", platform.Hostmaster)
	setIfEmpty("tenant_id", platform.TenantID)
	setIfEmpty("environment", platform.Environment)
}

// primaryDiscoveredMAC returns the first discovered MAC for a node, or an
// empty string if none. The seeder profile API only accepts a single MAC; the
// first NIC is treated as canonical.
func primaryDiscoveredMAC(node *DiscoveredNode) string {
	if len(node.DiscoveredMACs) == 0 {
		return ""
	}
	return node.DiscoveredMACs[0]
}
