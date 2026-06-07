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

package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// ConfigSource describes where the daemon's runtime configuration was
// loaded from. Today we only honor one config file at a time (Viper's
// single-source-of-truth model), but the slice future-proofs the API
// for explicit overlay layering.
type ConfigSource struct {
	Path   string `json:"path"`
	Format string `json:"format"`
}

// ConfigTree is the structured response shape consumed by the platform
// REST API and the WebUI. The Tree is the merged config (defaults +
// overrides + env), as a map; secrets are replaced with the sentinel
// "••••" when RedactSecrets is true.
type ConfigTree struct {
	Sources       []ConfigSource         `json:"sources"`
	Tree          map[string]interface{} `json:"tree"`
	GeneratedAt   time.Time              `json:"generated_at"`
	RedactedKeys  []string               `json:"redacted_keys,omitempty"`
	SecretsHidden bool                   `json:"secrets_hidden"`
}

// secretRedacted is the value substituted for any redacted leaf in
// the JSON config tree returned to the WebUI / non-privileged callers.
const secretRedacted = "••••"

// secretKeyHints are case-insensitive substrings that, when present in
// a YAML / map key name, mark the corresponding leaf value as secret.
// This is a deliberately conservative heuristic — it errs on the side
// of hiding more than necessary, which is the right tradeoff for
// admin / operator surfaces.
var secretKeyHints = []string{
	"password",
	"passwd",
	"secret",
	"pin",
	"token",
	"apikey",
	"api_key",
	"private",
	"cert_pem",
	"private_key",
	"signing_key",
	"client_secret",
	"shared_key",
	"hmac",
	"hash_key",
	"jwt_secret",
}

// LoadConfigTree resolves the live configuration from Viper, redacts
// secrets if requested, and returns the structured tree plus the
// source files used. Callers obtain this via REST
// (/api/v1/platform/config) or via Service.GetConfigTree for transport
// callers (gRPC / QUIC / MCP / Unix) once protos are extended.
func LoadConfigTree(redactSecrets bool) ConfigTree {
	settings := viper.AllSettings()
	redactedKeys := []string{}
	if redactSecrets {
		redactInPlace(settings, "", &redactedKeys)
		sort.Strings(redactedKeys)
	}
	sources := []ConfigSource{}
	if p := viper.ConfigFileUsed(); p != "" {
		sources = append(sources, ConfigSource{Path: p, Format: viperFormat()})
	}
	return ConfigTree{
		Sources:       sources,
		Tree:          settings,
		GeneratedAt:   time.Now().UTC(),
		RedactedKeys:  redactedKeys,
		SecretsHidden: redactSecrets,
	}
}

// ValidateConfigYAML parses the supplied YAML body and returns the
// list of structural / semantic errors found. An empty error slice
// means the document is valid YAML and decodes to a map structure;
// stronger schema checks (referenced files exist, ports are sane,
// etc.) are not performed today — adding those is a follow-up gated
// on first real "I tried to apply this" surface.
func ValidateConfigYAML(yamlBody []byte) []string {
	if len(yamlBody) == 0 {
		return []string{"empty config body"}
	}
	var root map[string]interface{}
	if err := yaml.Unmarshal(yamlBody, &root); err != nil {
		return []string{fmt.Sprintf("yaml unmarshal: %v", err)}
	}
	if len(root) == 0 {
		return []string{"config root is empty"}
	}
	return nil
}

// ReloadFromDisk re-reads the active Viper configuration file and
// optionally re-runs viper.Unmarshal against the supplied target.
// Returns the list of top-level sections present in the reloaded
// settings so callers can broadcast a CONFIG_CHANGED event with
// section granularity.
//
// target may be nil if the caller only wants Viper's internal cache
// refreshed (the WebUI reads viper.AllSettings, not the bound struct).
//
// The decode hooks must mirror app.initConfig — TextUnmarshallerHook
// for custom types like quicbaas.ConsistencyLevel and the
// platform-environment string, the duration hook for time.Duration
// fields, and the slice hook for comma-separated lists. Without
// these the *app.App rejects the reload with cryptic "cannot parse
// value as ..." errors.
func ReloadFromDisk(target interface{}) ([]string, error) {
	if err := viper.ReadInConfig(); err != nil {
		return nil, ErrReloadFailed{Cause: err}
	}
	if target != nil {
		hook := viper.DecodeHook(
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.TextUnmarshallerHookFunc(),
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
		)
		if err := viper.Unmarshal(target, hook); err != nil {
			return nil, ErrReloadFailed{Cause: err}
		}
	}
	settings := viper.AllSettings()
	out := make([]string, 0, len(settings))
	for k := range settings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// ReloadFromDiskWithSnapshot is ReloadFromDisk wrapped with an
// automatic pre-reload snapshot capture. If store is non-nil and the
// snapshot succeeds, the snapshot ID is returned alongside the
// reloaded section list so the daemon can stamp the audit log with
// the rollback handle. Snapshot failures are non-fatal — the reload
// proceeds even if the snapshot couldn't be persisted, with the
// error returned via the snapErr return value so callers can decide
// whether to surface it.
func ReloadFromDiskWithSnapshot(store SnapshotStore, target interface{}, actor string) (sections []string, snapshotID string, snapErr error, reloadErr error) {
	if store != nil {
		snap, err := CaptureCurrent(store, "pre-reload", actor)
		if err != nil {
			snapErr = err
		} else {
			snapshotID = snap.ID
		}
	}
	sections, reloadErr = ReloadFromDisk(target)
	return
}

// ErrReloadFailed wraps a failure during runtime reload of the
// platformd configuration from disk. The cause exposes the underlying
// viper / unmarshal error for log analysis.
type ErrReloadFailed struct {
	Cause error
}

func (e ErrReloadFailed) Error() string {
	return fmt.Sprintf("config: reload failed: %v", e.Cause)
}

func (e ErrReloadFailed) Unwrap() error {
	return e.Cause
}

// redactInPlace walks v depth-first and replaces any leaf whose
// parent key matches a secret hint with secretRedacted. Modified
// keys are recorded into out with their full dotted path for the
// response envelope.
func redactInPlace(v interface{}, prefix string, out *[]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			if isSecretKey(k) {
				if !isEmptyLeaf(child) {
					*out = append(*out, fullKey)
					t[k] = secretRedacted
				}
				continue
			}
			redactInPlace(child, fullKey, out)
		}
	case []interface{}:
		for i, child := range t {
			redactInPlace(child, prefix+"["+strconv.Itoa(i)+"]", out)
		}
	}
}

// isSecretKey reports whether the supplied key name matches any of
// the secretKeyHints substrings (case-insensitive).
func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, hint := range secretKeyHints {
		if strings.Contains(lk, hint) {
			return true
		}
	}
	return false
}

// isEmptyLeaf reports whether the value at a (potentially-secret)
// leaf is effectively empty. We avoid emitting redacted_keys entries
// for keys whose value is empty/nil since there's nothing to hide.
func isEmptyLeaf(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []interface{}:
		return len(t) == 0
	case map[string]interface{}:
		return len(t) == 0
	}
	return false
}

// viperFormat returns the canonical Viper config-type string for the
// active config file. Defaults to "yaml" when Viper has not been
// initialized.
func viperFormat() string {
	if ext := viper.GetString("config-type"); ext != "" {
		return ext
	}
	if p := viper.ConfigFileUsed(); p != "" {
		switch {
		case strings.HasSuffix(p, ".yaml"), strings.HasSuffix(p, ".yml"):
			return "yaml"
		case strings.HasSuffix(p, ".json"):
			return "json"
		case strings.HasSuffix(p, ".toml"):
			return "toml"
		}
	}
	return "yaml"
}
