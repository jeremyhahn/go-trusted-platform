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

package app

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// ErrBootstrapSecretResolution is returned when resolving a bootstrap secret fails.
type ErrBootstrapSecretResolution struct {
	Path  string
	URI   string
	Cause error
}

func (e ErrBootstrapSecretResolution) Error() string {
	if e.Cause != nil {
		return "bootstrap secret resolution failed for " + e.Path + ": " + e.Cause.Error()
	}
	return "bootstrap secret resolution failed for " + e.Path
}

func (e ErrBootstrapSecretResolution) Unwrap() error {
	return e.Cause
}

// ErrSecretsServiceNotAvailableButKMSRequired is returned when the
// config contains kms:// URIs but the QuicBaaS SecretsService isn't
// reachable at bootstrap time. Leaving the URIs unresolved is never
// safe — downstream code (TPM hierarchy auth, CA init, etc) would pass
// the raw URI string through as a password and fail with cryptic
// errors like TPM_RC_SIZE. This is fatal; callers must not continue.
type ErrSecretsServiceNotAvailableButKMSRequired struct {
	URICount int
}

func (e ErrSecretsServiceNotAvailableButKMSRequired) Error() string {
	return fmt.Sprintf("bootstrap: QuicBaaS SecretsService not available — "+
		"%d kms:// URI(s) in config cannot be resolved and leaving them as "+
		"raw strings would corrupt downstream services (TPM auth, KMS keys, CA PINs)",
		e.URICount)
}

// BootstrapSecretsResult contains the results of bootstrap secret resolution.
type BootstrapSecretsResult struct {
	// Resolved contains the config paths that had URIs resolved.
	Resolved []string

	// Errors contains non-fatal errors encountered during resolution.
	Errors []error
}

// ResolvedCount returns the number of resolved secrets.
func (r *BootstrapSecretsResult) ResolvedCount() int {
	return len(r.Resolved)
}

// ErrorCount returns the number of errors encountered.
func (r *BootstrapSecretsResult) ErrorCount() int {
	return len(r.Errors)
}

// resolveKMSSecrets resolves kms:// URIs in the App struct before platform
// services consume configuration values. Persistence is provided by the
// QuicBaaS SecretsService (EnsureSecret): the first call at a given path
// generates the secret per spec (length + encoding) and stores it; every
// subsequent call returns the same stable bytes under a distributed lock.
//
// Must be called after initStores() so the SecretsService is available,
// and before ParsePINs() and InitTPM() so the PINs used for TPM hierarchy
// auth are the stable, persisted values.
//
// autogen:// is no longer supported — use kms://path?ensure=true&len=N&enc=E
// for persistent auto-generation.
func (app *App) resolveKMSSecrets(ctx context.Context) (*BootstrapSecretsResult, error) {
	logger := app.Logger.Slog()

	result := &BootstrapSecretsResult{
		Resolved: make([]string, 0),
		Errors:   make([]error, 0),
	}

	// Pre-scan: count kms:// URIs in the config so we can distinguish
	// "no URIs — nothing to resolve" from "URIs present but service not
	// reachable". Only the latter is fatal; the former lets us skip
	// cleanly on minimal deployments that don't use KMS.
	val := reflect.ValueOf(app).Elem()
	uriCount := countKMSURIs(val)

	secretsSvc := app.Secrets()
	if secretsSvc == nil {
		if uriCount == 0 {
			logger.Debug("bootstrap: no kms:// URIs in config, SecretsService not required")
			return result, nil
		}
		return result, ErrSecretsServiceNotAvailableButKMSRequired{URICount: uriCount}
	}

	if uriCount == 0 {
		return result, nil
	}

	resolver := NewLocalSecretsResolver(secretsSvc, logger).
		WithIdentity(app.TenantID, app.Hostname)

	resolveStructKMS(ctx, resolver, val, "", result, logger)

	logger.Info("bootstrap secret resolution complete",
		slog.Int("total_uris", uriCount),
		slog.Int("resolved", result.ResolvedCount()),
		slog.Int("errors", result.ErrorCount()))

	return result, nil
}

// countKMSURIs walks the struct and returns the number of string fields
// holding a kms:// URI. Used by resolveKMSSecrets to decide whether
// unavailable-service is a fatal error (has URIs) or a no-op (none).
func countKMSURIs(val reflect.Value) int {
	if !val.IsValid() {
		return 0
	}
	total := 0
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		if !field.CanInterface() {
			continue
		}
		if bootstrapFieldPath("", fieldType) == "" {
			continue
		}
		switch field.Kind() {
		case reflect.String:
			if strings.HasPrefix(strings.ToLower(field.String()), bootstrap.SchemeKMS) {
				total++
			}
		case reflect.Ptr:
			if !field.IsNil() && field.Elem().Kind() == reflect.Struct {
				total += countKMSURIs(field.Elem())
			}
		case reflect.Struct:
			total += countKMSURIs(field)
		case reflect.Slice:
			for j := 0; j < field.Len(); j++ {
				elem := field.Index(j)
				switch elem.Kind() {
				case reflect.Struct:
					total += countKMSURIs(elem)
				case reflect.Ptr:
					if !elem.IsNil() && elem.Elem().Kind() == reflect.Struct {
						total += countKMSURIs(elem.Elem())
					}
				case reflect.String:
					if strings.HasPrefix(strings.ToLower(elem.String()), bootstrap.SchemeKMS) {
						total++
					}
				}
			}
		case reflect.Map:
			iter := field.MapRange()
			for iter.Next() {
				v := iter.Value()
				if v.Kind() == reflect.Ptr && !v.IsNil() && v.Elem().Kind() == reflect.Struct {
					total += countKMSURIs(v.Elem())
				}
			}
		}
	}
	return total
}

// assertNoUnresolvedKMSURI returns a non-nil error if v still contains a
// raw kms:// URI. Used as a defensive check at security-sensitive
// boundaries (TPM hierarchy auth, CA init, BMC creds) so a stale or
// unresolved URI fails the service start with a clear message instead
// of reaching TPM2_HierarchyChangeAuth as a 48-byte literal password.
func assertNoUnresolvedKMSURI(fieldName, v string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(v), bootstrap.SchemeKMS) {
		return fmt.Errorf(
			"refusing to start: %s still holds an unresolved kms:// URI "+
				"(%q) — bootstrap resolver must run to completion before any "+
				"security field is consumed", fieldName, v)
	}
	return nil
}

// bootstrapFieldPath constructs the dot-notation path for a struct field
// using yaml, json, or mapstructure tags.
func bootstrapFieldPath(parentPath string, field reflect.StructField) string {
	name := field.Tag.Get("yaml")
	if name == "" {
		name = field.Tag.Get("json")
	}
	if name == "" {
		name = field.Tag.Get("mapstructure")
	}

	// Handle tag options (e.g., "name,omitempty")
	if idx := strings.Index(name, ","); idx != -1 {
		name = name[:idx]
	}

	if name == "" {
		name = strings.ToLower(field.Name)
	}

	// Skip fields tagged with "-"
	if name == "-" {
		return ""
	}

	if parentPath == "" {
		return name
	}
	return parentPath + "." + name
}

// resolveStructKMS recursively walks a struct value and resolves kms:// URIs
// in string fields, setting the resolved values back into the struct.
func resolveStructKMS(ctx context.Context, resolver *LocalSecretsResolver, val reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	if !val.IsValid() {
		return
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		if !field.CanSet() {
			continue
		}

		fieldPath := bootstrapFieldPath(path, fieldType)
		if fieldPath == "" {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			resolveStringFieldKMS(ctx, resolver, field, fieldPath, result, logger)

		case reflect.Ptr:
			if !field.IsNil() && field.Elem().Kind() == reflect.Struct {
				resolveStructKMS(ctx, resolver, field.Elem(), fieldPath, result, logger)
			}

		case reflect.Struct:
			resolveStructKMS(ctx, resolver, field, fieldPath, result, logger)

		case reflect.Slice:
			resolveSliceKMS(ctx, resolver, field, fieldPath, result, logger)

		case reflect.Map:
			resolveMapKMS(ctx, resolver, field, fieldPath, result, logger)
		}
	}
}

// resolveStringFieldKMS resolves a single string field if it contains a kms:// URI.
func resolveStringFieldKMS(ctx context.Context, resolver *LocalSecretsResolver, field reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	uri := field.String()
	if uri == "" {
		return
	}

	if !strings.HasPrefix(strings.ToLower(uri), bootstrap.SchemeKMS) {
		return
	}

	secretValue, err := resolver.Resolve(ctx, uri)
	if err != nil {
		result.Errors = append(result.Errors, ErrBootstrapSecretResolution{
			Path:  path,
			URI:   uri,
			Cause: err,
		})
		// Clear the field so downstream code cannot accidentally use the
		// raw kms:// URI as a literal password/key/etc. Leaving the URI
		// here is how we previously ended up passing 48-byte strings to
		// TPM2_HierarchyChangeAuth and getting cryptic TPM_RC_SIZE.
		// Callers treat a populated result.Errors as fatal.
		field.SetString("")
		logger.Warn("failed to resolve kms secret",
			slog.String("path", path),
			slog.String("error", err.Error()))
		return
	}

	field.SetString(string(secretValue))
	result.Resolved = append(result.Resolved, path)

	logger.Debug("resolved kms secret",
		slog.String("path", path),
		slog.Int("length", len(secretValue)))
}

// resolveSliceKMS walks slice elements for kms:// URIs.
func resolveSliceKMS(ctx context.Context, resolver *LocalSecretsResolver, field reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	for i := 0; i < field.Len(); i++ {
		elem := field.Index(i)
		elemPath := fmt.Sprintf("%s[%d]", path, i)

		switch elem.Kind() {
		case reflect.Struct:
			resolveStructKMS(ctx, resolver, elem, elemPath, result, logger)
		case reflect.Ptr:
			if !elem.IsNil() && elem.Elem().Kind() == reflect.Struct {
				resolveStructKMS(ctx, resolver, elem.Elem(), elemPath, result, logger)
			}
		case reflect.String:
			resolveStringFieldKMS(ctx, resolver, elem, elemPath, result, logger)
		}
	}
}

// resolveMapKMS walks map values for kms:// URIs in struct values.
// Note: map string values cannot be set directly via reflection, so only
// struct values within maps are processed.
func resolveMapKMS(ctx context.Context, resolver *LocalSecretsResolver, field reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	iter := field.MapRange()
	for iter.Next() {
		key := iter.Key()
		val := iter.Value()

		var keyStr string
		if key.Kind() == reflect.String {
			keyStr = key.String()
		} else {
			keyStr = fmt.Sprintf("%v", key.Interface())
		}
		elemPath := path + "." + keyStr

		switch val.Kind() {
		case reflect.Ptr:
			if !val.IsNil() && val.Elem().Kind() == reflect.Struct {
				resolveStructKMS(ctx, resolver, val.Elem(), elemPath, result, logger)
			}
		}
	}
}
