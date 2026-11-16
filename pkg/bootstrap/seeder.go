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
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
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
	// EKCert carries the optional PEM-encoded TPM Endorsement Key certificate
	// prestaged for this node so the control plane can bind EK-verified config
	// delivery to the device's hardware EK. Empty when none was prestaged.
	EKCert string `json:"ek_cert,omitempty"`
}

// profileIDResponse is the minimal shape of the create-profile 201 response
// payload used to capture the new profile's ID. The server serializes the
// ID as a JSON string (uint64 > 2^53 would lose precision in JS parsers).
type profileIDResponse struct {
	ID uint64 `json:"id,string"`
}

// SeederParams holds the dependencies for creating a Seeder.
type SeederParams struct {
	ControlPlaneAddr string
	Config           *BootstrapConfig
	Discovered       []DiscoveredNode
	Logger           *slog.Logger
	// CPCAPool is the verified control-plane CA pool obtained via
	// capture-then-verify in fetchControlPlaneCABundle. The seeder's HTTP
	// client verifies the CP TLS certificate against this pool and
	// nothing else: Seed refuses to run without it (ErrCABundleRequired).
	// There is no system-pool fallback and never InsecureSkipVerify.
	CPCAPool *x509.CertPool
	// ServerName is the DNS name the control plane's certificate is
	// issued for (controlPlaneTLSName); the seeder dials by address.
	ServerName string
	// ConfigDir is the directory holding the bootstrap YAML. Relative
	// paths in Config.Templates resolve against it, exactly as they do on
	// the orchestrator's own template reads, so the seeder and the rest of
	// the run agree on which file a role's template is. Empty leaves
	// configured paths as written.
	ConfigDir string
	// ClientCertificate is the firstboot admin bundle (admin@system) the
	// seeder presents to the control plane: the mTLS gate on the device
	// routes the seeder calls verifies it against the platform CA (#178).
	// Nil presents no client certificate.
	ClientCertificate *tls.Certificate
}

// Seeder uploads device templates and creates per-node profiles on the control plane.
type Seeder struct {
	controlPlaneAddr string
	config           *BootstrapConfig
	discovered       []DiscoveredNode
	logger           *slog.Logger
	client           *http.Client
	caPool           *x509.CertPool
	configDir        string
	// profileIDs maps hostname → profile ID, populated by createProfiles.
	profileIDs map[string]uint64
}

// NewSeeder creates a Seeder from the given parameters.
//
// The HTTP client verifies the control plane's TLS certificate against
// CPCAPool (the capture-then-verify result from fetchControlPlaneCABundle)
// for ServerName. A nil pool is not a fallback to system roots: Seed
// returns ErrCABundleRequired. InsecureSkipVerify is never set.
func NewSeeder(params SeederParams) *Seeder {
	logger := params.Logger
	if logger == nil {
		logger = slog.Default()
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    params.CPCAPool,
		ServerName: params.ServerName,
	}
	if params.ClientCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*params.ClientCertificate}
	}

	return &Seeder{
		controlPlaneAddr: params.ControlPlaneAddr,
		config:           params.Config,
		discovered:       params.Discovered,
		logger:           logger,
		caPool:           params.CPCAPool,
		configDir:        params.ConfigDir,
		profileIDs:       make(map[string]uint64),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				// Force pure-Go DNS resolver to avoid SIGFPE in CGO's
				// getaddrinfo when running as a statically linked binary.
				DialContext: (&net.Dialer{
					Timeout:  10 * time.Second,
					Resolver: &net.Resolver{PreferGo: true},
				}).DialContext,
				TLSClientConfig: tlsConfig,
			},
		},
	}
}

// ProfileIDs returns a copy of the hostname-to-profile-ID map populated by
// a successful Seed call. Callers must call Seed before consulting this map.
func (s *Seeder) ProfileIDs() map[string]uint64 {
	result := make(map[string]uint64, len(s.profileIDs))
	for k, v := range s.profileIDs {
		result[k] = v
	}
	return result
}

// Seed uploads templates for each role and creates profiles for all discovered nodes.
func (s *Seeder) Seed(ctx context.Context) error {
	if s.controlPlaneAddr == "" {
		return ErrMissingSeederAddr{}
	}
	if s.caPool == nil {
		return ErrCABundleRequired{Operation: "template seeding"}
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

	for role := range s.config.Templates {
		path, _ := s.config.TemplatePath(role, s.configDir)

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

// createProfiles POSTs a profile creation request for each discovered node
// and records the resulting profile ID per hostname in s.profileIDs.
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
			EKCert:   node.EKCert,
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

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			return ErrProfileCreateFailed{
				Hostname:   node.Hostname,
				StatusCode: resp.StatusCode,
			}
		}

		if readErr != nil {
			return ErrProfileCreateFailed{Hostname: node.Hostname, Cause: readErr}
		}

		// Parse the profile ID from the 201 response. The REST API wraps
		// responses in {code, success, payload}; the payload carries
		// ProfileFullResponse whose "id" field is a JSON string (uint64).
		profileID, parseErr := parseProfileIDFromResponse(respBody)
		if parseErr != nil {
			return ErrProfileIDParseFailed{Hostname: node.Hostname, Cause: parseErr}
		}

		s.profileIDs[node.Hostname] = profileID

		s.logger.Info("bootstrap: profile created",
			slog.String("hostname", node.Hostname),
			slog.String("template_id", templateID),
			slog.Uint64("profile_id", profileID))
	}

	return nil
}

// parseProfileIDFromResponse extracts the profile ID from a create-profile
// response body. The server wraps the response in {code, success, payload}
// and the payload's "id" field is a JSON string encoding of a uint64.
func parseProfileIDFromResponse(body []byte) (uint64, error) {
	var envelope struct {
		Payload struct {
			ID string `json:"id"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return 0, err
	}
	if envelope.Payload.ID == "" {
		// Tolerate direct (non-enveloped) response shape: {id: "1234"}.
		var direct profileIDResponse
		if err := json.Unmarshal(body, &direct); err != nil {
			return 0, err
		}
		if direct.ID == 0 {
			return 0, ErrProfileIDParseFailed{Cause: errEmptyProfileID{}}
		}
		return direct.ID, nil
	}
	id, err := strconv.ParseUint(envelope.Payload.ID, 10, 64)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// errEmptyProfileID is an internal sentinel for an empty ID field in the
// create-profile response.
type errEmptyProfileID struct{}

func (errEmptyProfileID) Error() string {
	return "profile ID is empty in create-profile response"
}

// buildMergedConfig loads the base template YAML for a node's role,
// deep-merges the node's per-host overrides, applies global platform
// identity fields, and returns the result as JSON. Returns nil when
// no template is configured for the role (the profile will be created
// without an explicit config, falling back to the template default).
func (s *Seeder) buildMergedConfig(node *DiscoveredNode) (json.RawMessage, error) {
	templatePath, ok := s.config.TemplatePath(node.Role, s.configDir)
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

	// Apply global identity from the platform config BEFORE the node
	// overrides so the precedence chain is: template -> platform global
	// identity -> per-node overrides -> ApplyNodeIdentity. Templates ship
	// non-empty example placeholders (e.g. domain: gw.example.com), so the
	// platform values must overwrite them; a per-node override that
	// differs from the platform global still wins because overrides merge
	// after.
	applyGlobalIdentitySeeder(templateMap, &s.config.Platform)

	// The seeded profile is the config the control plane delivers on first
	// boot, so it must carry the same hardware identity as the per-MAC
	// installer.yaml the orchestrator stages — otherwise which quirk entry
	// a node installs against would depend on which delivery path won.
	// Same slot as the globals, so a per-node override still wins.
	applyHardwareIdentity(templateMap, node.HardwareIdentity)

	// Apply per-node overrides via deep merge.
	if len(node.Overrides) > 0 {
		templateMap = deepMergeSeeder(templateMap, node.Overrides)
	}

	// Inject the node's authoritative first-class fields (hostname, BMC
	// block, static interfaces). Overwrites unconditionally — validation
	// guarantees overrides never carry these keys.
	if err := ApplyNodeIdentity(templateMap, &node.NodeConfig); err != nil {
		return nil, ErrTemplateMergeFailed{Hostname: node.Hostname, Role: node.Role, Cause: err}
	}

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

// applyGlobalIdentitySeeder overwrites the top-level identity keys with the
// non-empty platform global values. The overwrite is unconditional because
// role templates ship non-empty example placeholders — a fill-if-empty
// policy would leave those placeholders in seeded profiles. It runs BEFORE
// the per-node override merge, so a per-node identity override still wins.
// Mirrors orchestrator_dryrun.go::applyGlobalIdentity.
func applyGlobalIdentitySeeder(m map[string]interface{}, platform *PlatformGlobalConfig) {
	if platform == nil {
		return
	}
	setGlobal := func(key, value string) {
		if value == "" {
			return
		}
		m[key] = value
	}
	setGlobal("domain", platform.Domain)
	setGlobal("hostmaster", platform.Hostmaster)
	setGlobal("tenant-id", platform.TenantID)
	setGlobal("environment", platform.Environment)
	applySPIFFETrustDomain(m, platform)
}

// applySPIFFETrustDomain overwrites quicbaas.spiffe-trust-domain with the
// deployment's internal domain. The trust domain IS deployment identity —
// role templates ship the example.internal placeholder, and the top-level
// identity substitution above does not descend into nested sections, so
// without this the embedded server's IAM (and every SPIFFE SAN it issues)
// would carry the placeholder domain. Overwrite policy mirrors setGlobal:
// unconditional when the platform value is non-empty, and the per-node
// override merge still runs afterwards and wins. A template with no
// quicbaas: section gets one: platformd loads such a config as the
// embedded server, which refuses to start without a trust domain.
func applySPIFFETrustDomain(m map[string]interface{}, platform *PlatformGlobalConfig) {
	if platform.InternalDomain == "" {
		return
	}
	section, ok := m["quicbaas"].(map[string]interface{})
	if !ok {
		section = map[string]interface{}{}
		m["quicbaas"] = section
	}
	section["spiffe-trust-domain"] = platform.InternalDomain
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
