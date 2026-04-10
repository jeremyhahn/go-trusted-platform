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

// resolveAutoGenSecrets resolves autogen:// URIs in the App struct fields before
// platform services are initialized. This enables non-interactive bootstrap by
// generating random PINs, passwords, and keys specified in the config file.
//
// Unlike ProcessSecrets which requires the full QuicBaaS stack for KMS migration,
// this method only needs the AutoGenResolver and operates purely on the in-memory
// config struct. It walks the App struct recursively, finds string fields containing
// autogen:// URIs, resolves them to random values, and sets the resolved values
// back into the struct fields.
//
// This method is called during Init() after config loading but before ParsePINs()
// and InitTPM(), ensuring that autogen:// URIs in fields like platform.so-pin and
// platform.user-pin are resolved to actual values before they are consumed.
func (app *App) resolveAutoGenSecrets(ctx context.Context) (*BootstrapSecretsResult, error) {
	logger := app.Logger.Slog()
	resolver := NewAutoGenResolver(logger)

	result := &BootstrapSecretsResult{
		Resolved: make([]string, 0),
		Errors:   make([]error, 0),
	}

	val := reflect.ValueOf(app).Elem()
	resolveStructAutoGen(ctx, resolver, val, "", result, logger)

	if len(result.Resolved) > 0 {
		logger.Info("bootstrap secret resolution complete",
			slog.Int("resolved", result.ResolvedCount()),
			slog.Int("errors", result.ErrorCount()))
	}

	return result, nil
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

// resolveStructAutoGen recursively walks a struct value and resolves autogen:// URIs
// in string fields, setting the resolved values back into the struct.
func resolveStructAutoGen(ctx context.Context, resolver *AutoGenResolver, val reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	if !val.IsValid() {
		return
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		// Skip unexported fields
		if !field.CanSet() {
			continue
		}

		fieldPath := bootstrapFieldPath(path, fieldType)
		if fieldPath == "" {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			resolveStringFieldAutoGen(ctx, resolver, field, fieldPath, result, logger)

		case reflect.Ptr:
			if !field.IsNil() && field.Elem().Kind() == reflect.Struct {
				resolveStructAutoGen(ctx, resolver, field.Elem(), fieldPath, result, logger)
			}

		case reflect.Struct:
			resolveStructAutoGen(ctx, resolver, field, fieldPath, result, logger)

		case reflect.Slice:
			resolveSliceAutoGen(ctx, resolver, field, fieldPath, result, logger)

		case reflect.Map:
			resolveMapAutoGen(ctx, resolver, field, fieldPath, result, logger)
		}
	}
}

// resolveStringFieldAutoGen resolves a single string field if it contains an autogen:// URI.
func resolveStringFieldAutoGen(ctx context.Context, resolver *AutoGenResolver, field reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	uri := field.String()
	if uri == "" {
		return
	}

	if !strings.HasPrefix(strings.ToLower(uri), bootstrap.SchemeAutoGen) {
		return
	}

	secretValue, err := resolver.Resolve(ctx, uri)
	if err != nil {
		result.Errors = append(result.Errors, ErrBootstrapSecretResolution{
			Path:  path,
			URI:   uri,
			Cause: err,
		})
		logger.Warn("failed to resolve autogen secret",
			slog.String("path", path),
			slog.String("error", err.Error()))
		return
	}

	field.SetString(string(secretValue))
	result.Resolved = append(result.Resolved, path)

	logger.Debug("resolved autogen secret",
		slog.String("path", path),
		slog.Int("length", len(secretValue)))
}

// resolveSliceAutoGen walks slice elements for autogen:// URIs.
func resolveSliceAutoGen(ctx context.Context, resolver *AutoGenResolver, field reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
	for i := 0; i < field.Len(); i++ {
		elem := field.Index(i)
		elemPath := fmt.Sprintf("%s[%d]", path, i)

		switch elem.Kind() {
		case reflect.Struct:
			resolveStructAutoGen(ctx, resolver, elem, elemPath, result, logger)
		case reflect.Ptr:
			if !elem.IsNil() && elem.Elem().Kind() == reflect.Struct {
				resolveStructAutoGen(ctx, resolver, elem.Elem(), elemPath, result, logger)
			}
		case reflect.String:
			resolveStringFieldAutoGen(ctx, resolver, elem, elemPath, result, logger)
		}
	}
}

// resolveMapAutoGen walks map values for autogen:// URIs in struct values.
// Note: map string values cannot be set directly via reflection, so only struct
// values within maps are processed.
func resolveMapAutoGen(ctx context.Context, resolver *AutoGenResolver, field reflect.Value, path string, result *BootstrapSecretsResult, logger *slog.Logger) {
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
				resolveStructAutoGen(ctx, resolver, val.Elem(), elemPath, result, logger)
			}
		}
	}
}
