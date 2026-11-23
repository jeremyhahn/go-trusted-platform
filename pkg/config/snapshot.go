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
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

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
		if err := unmarshalWithHooks(target); err != nil {
			return nil, ErrReloadFailed{Cause: err}
		}
	}
	return sortedTopLevelSections(), nil
}

// unmarshalWithHooks runs viper.Unmarshal against target with DecodeHook, the
// same decode app.initConfig uses, so a reloaded configuration decodes exactly
// as the one platformd started with.
func unmarshalWithHooks(target interface{}) error {
	return viper.Unmarshal(target, DecodeHook())
}

// sortedTopLevelSections returns the sorted list of top-level keys
// present in the live viper settings so callers can broadcast a
// CONFIG_CHANGED event with section granularity.
func sortedTopLevelSections() []string {
	settings := viper.AllSettings()
	out := make([]string, 0, len(settings))
	for k := range settings {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ApplySection applies a set of key/value values under a named
// configuration section to the live viper state and, when target is
// non-nil, re-decodes the whole configuration into target so the
// running daemon observes the change immediately.
//
// The update is validated first: the values are applied to a candidate
// copy of the current configuration, which is decoded into a fresh
// value of target's type. A value that does not decode returns
// ErrInvalidSectionValue (wrapped in ErrApplySectionFailed) before the
// live state or the config file changes.
//
// The values are merged into Viper's config layer (MergeConfigMap), not
// set as viper.Set overrides, so ReloadFromDisk and RollbackTo, which
// re-read the file into that layer, undo an unpersisted update, while
// startup overrides and flags keep their values.
//
// When persist is true the active config file is rewritten with its own
// contents plus the section values; startup flags, environment values
// and defaults are not written to it. The live state then re-reads the
// file before the re-decode, making the change durable across restarts.
// When persist is false the change lives in memory until the next
// ReloadFromDisk.
//
// section must be non-empty; each entry in values is applied under the
// dotted key "<section>.<key>". Returns the sorted top-level section
// list after the apply.
func ApplySection(target interface{}, section string, values map[string]string, persist bool) ([]string, error) {
	if section == "" {
		return nil, ErrApplySectionFailed{Cause: errEmptySection}
	}
	for k := range values {
		if k == "" {
			return nil, ErrApplySectionFailed{Cause: errEmptyKey}
		}
	}
	if persist && viper.ConfigFileUsed() == "" {
		return nil, ErrApplySectionFailed{Cause: errNoConfigFile}
	}

	// Validate a candidate configuration before touching live state.
	if rt := reflect.TypeOf(target); rt != nil && rt.Kind() == reflect.Ptr {
		cand := viper.New()
		if err := cand.MergeConfigMap(viper.AllSettings()); err != nil {
			return nil, ErrApplySectionFailed{Cause: err}
		}
		for k, v := range values {
			cand.Set(section+"."+k, v)
		}
		probe := reflect.New(rt.Elem()).Interface()
		if err := cand.Unmarshal(probe, DecodeHook()); err != nil {
			return nil, ErrApplySectionFailed{Cause: ErrInvalidSectionValue{Section: section, cause: err}}
		}
	}

	if err := viper.MergeConfigMap(nestSectionValues(section, values)); err != nil {
		return nil, ErrApplySectionFailed{Cause: err}
	}

	if persist {
		if err := persistSectionToFile(section, values); err != nil {
			// Drop the merged values: the file is the source of truth.
			_ = viper.ReadInConfig()
			return nil, ErrApplySectionFailed{Cause: err}
		}
		if err := viper.ReadInConfig(); err != nil {
			return nil, ErrApplySectionFailed{Cause: err}
		}
	}

	if target != nil {
		if err := unmarshalWithHooks(target); err != nil {
			return nil, ErrApplySectionFailed{Cause: err}
		}
	}
	return sortedTopLevelSections(), nil
}

// nestSectionValues turns the dotted keys "<section>.<key>" into the
// nested map shape MergeConfigMap expects.
// persistSectionToFile rewrites the active config file with the file's
// own contents plus the section values. It works on a file-layer Viper,
// not the global one, whose WriteConfig would marshal AllSettings and so
// write every bound flag, default and environment value into the file.
func persistSectionToFile(section string, values map[string]string) error {
	fv := viper.New()
	fv.SetConfigFile(viper.ConfigFileUsed())
	fv.SetConfigType(viperFormat())
	if err := fv.ReadInConfig(); err != nil {
		return err
	}
	if err := fv.MergeConfigMap(nestSectionValues(section, values)); err != nil {
		return err
	}
	return fv.WriteConfig()
}

func nestSectionValues(section string, values map[string]string) map[string]interface{} {
	root := map[string]interface{}{}
	for k, v := range values {
		path := append(strings.Split(section, "."), strings.Split(k, ".")...)
		node := root
		for _, p := range path[:len(path)-1] {
			child, ok := node[p].(map[string]interface{})
			if !ok {
				child = map[string]interface{}{}
				node[p] = child
			}
			node = child
		}
		node[path[len(path)-1]] = v
	}
	return root
}

// ErrApplySectionFailed wraps a failure while applying a config section
// override at runtime.
type ErrApplySectionFailed struct {
	Cause error
}

func (e ErrApplySectionFailed) Error() string {
	return fmt.Sprintf("config: apply section failed: %v", e.Cause)
}

func (e ErrApplySectionFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidSectionValue is returned (wrapped in ErrApplySectionFailed)
// when a section update does not decode into the configuration. Its
// message names the section only: the decoder's message quotes the
// rejected value, which can be a secret, so it is reachable only
// through Unwrap.
type ErrInvalidSectionValue struct {
	Section string
	cause   error
}

func (e ErrInvalidSectionValue) Error() string {
	return fmt.Sprintf("config: section %q has a value that does not decode into the configuration", e.Section)
}

func (e ErrInvalidSectionValue) Unwrap() error {
	return e.cause
}

var (
	errEmptySection = errors.New("section is required")
	errEmptyKey     = errors.New("config key is required")
	errNoConfigFile = errors.New("no active config file to persist to")
)

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
