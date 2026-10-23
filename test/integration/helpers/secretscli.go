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

//go:build integration

package helpers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// CLIRunFunc runs platformctl with args, under the adapter's own config and
// JSON output, and returns what it printed on stdout.
type CLIRunFunc func(ctx context.Context, args ...string) ([]byte, error)

// SecretsCLI drives the platformctl kms secrets verbs the way they ship
// (docs/kms/cli.md §7) for the CLI adapters of the secrets and kms suites.
// Each method builds the documented arguments, runs them through Run and
// decodes the JSON the verb prints. A verb the go-quicbaas SDK does not serve
// fails with ErrCLIUpstreamGap naming SecretsSDKGapIssue.
type SecretsCLI struct {
	Run CLIRunFunc
}

// ErrSecretsCLIOutput is returned when a kms secrets verb printed output that
// is not the JSON it documents.
type ErrSecretsCLIOutput struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrSecretsCLIOutput) Error() string {
	return fmt.Sprintf("platformctl kms secrets %s printed unparseable output %q: %v", e.Operation, e.Output, e.Err)
}

func (e ErrSecretsCLIOutput) Unwrap() error {
	return e.Err
}

// SecretsCLIStored is the output of kms secrets store.
type SecretsCLIStored struct {
	Name    string `json:"name"`
	Version uint64 `json:"version"`
}

// SecretsCLISecret is the output of kms secrets get and version, and one entry
// of prefix list --include-data. Value is base64 in the JSON.
type SecretsCLISecret struct {
	Name        string            `json:"name"`
	Version     uint64            `json:"version"`
	Value       []byte            `json:"value"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	CreatedBy   string            `json:"created_by,omitempty"`
}

// SecretsCLIList is the output of kms secrets list and prefix list.
type SecretsCLIList struct {
	Prefix  string             `json:"prefix,omitempty"`
	Secrets []string           `json:"secrets"`
	Data    []SecretsCLISecret `json:"data,omitempty"`
	HasMore bool               `json:"has_more"`
}

// SecretsCLIDeleted is the output of kms secrets delete.
type SecretsCLIDeleted struct {
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

// SecretsCLIRotated is the output of kms secrets rotate.
type SecretsCLIRotated struct {
	Name       string `json:"name"`
	OldVersion uint64 `json:"old_version"`
	NewVersion uint64 `json:"new_version"`
}

// SecretsCLIVersions is the output of kms secrets versions.
type SecretsCLIVersions struct {
	Name     string              `json:"name"`
	Versions []SecretsCLIVersion `json:"versions"`
}

// SecretsCLIVersion is one entry of kms secrets versions; it carries no value.
type SecretsCLIVersion struct {
	Version   uint64            `json:"version"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by,omitempty"`
}

// SecretsCLIRolledBack is the output of kms secrets rollback.
type SecretsCLIRolledBack struct {
	Name       string `json:"name"`
	NewVersion uint64 `json:"new_version"`
}

// SecretsCLIStatus is the output of kms secrets status enable|disable.
type SecretsCLIStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// SecretsCLIPolicy is the output of kms secrets policy get and policy set.
type SecretsCLIPolicy struct {
	Name            string    `json:"name"`
	Enabled         bool      `json:"enabled"`
	IntervalSeconds int64     `json:"interval_seconds"`
	NextRotation    time.Time `json:"next_rotation"`
	RetainVersions  int32     `json:"retain_versions"`
	RotationLambda  string    `json:"rotation_lambda,omitempty"`
}

// SecretsCLIPolicyOptions are the kms secrets policy set flags. A zero
// IntervalSeconds, RetainVersions or RotationLambda leaves its flag out.
type SecretsCLIPolicyOptions struct {
	Enabled         bool
	IntervalSeconds int64
	RetainVersions  int32
	RotationLambda  string
}

// Store runs kms secrets store with the value as base64 and one --tag per tag.
func (s SecretsCLI) Store(ctx context.Context, name string, value []byte, description string, tags map[string]string) (*SecretsCLIStored, error) {
	args := []string{"store", name, "--value", base64.StdEncoding.EncodeToString(value), "--base64"}
	if description != "" {
		args = append(args, "--description", description)
	}
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--tag", key+"="+tags[key])
	}
	return runSecretsCLI[SecretsCLIStored](ctx, s, "store", args...)
}

// Get runs kms secrets get for the current version.
func (s SecretsCLI) Get(ctx context.Context, name string) (*SecretsCLISecret, error) {
	return runSecretsCLI[SecretsCLISecret](ctx, s, "get", "get", name)
}

// List runs kms secrets list; a limit of 0 keeps the verb's default.
func (s SecretsCLI) List(ctx context.Context, limit int32) (*SecretsCLIList, error) {
	args := []string{"list"}
	if limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(limit), 10))
	}
	return runSecretsCLI[SecretsCLIList](ctx, s, "list", args...)
}

// Delete runs kms secrets delete, which removes every version.
func (s SecretsCLI) Delete(ctx context.Context, name string) (*SecretsCLIDeleted, error) {
	return runSecretsCLI[SecretsCLIDeleted](ctx, s, "delete", "delete", name)
}

// Rotate runs kms secrets rotate with the new value as base64.
func (s SecretsCLI) Rotate(ctx context.Context, name string, value []byte) (*SecretsCLIRotated, error) {
	return runSecretsCLI[SecretsCLIRotated](ctx, s, "rotate",
		"rotate", name, "--value", base64.StdEncoding.EncodeToString(value), "--base64")
}

// Version runs kms secrets version for one version.
func (s SecretsCLI) Version(ctx context.Context, name string, version uint64) (*SecretsCLISecret, error) {
	return runSecretsCLI[SecretsCLISecret](ctx, s, "version", "version", name, strconv.FormatUint(version, 10))
}

// Versions runs kms secrets versions.
func (s SecretsCLI) Versions(ctx context.Context, name string) (*SecretsCLIVersions, error) {
	return runSecretsCLI[SecretsCLIVersions](ctx, s, "versions", "versions", name)
}

// Rollback runs kms secrets rollback to version.
func (s SecretsCLI) Rollback(ctx context.Context, name string, version uint64) (*SecretsCLIRolledBack, error) {
	return runSecretsCLI[SecretsCLIRolledBack](ctx, s, "rollback", "rollback", name, strconv.FormatUint(version, 10))
}

// SetStatus runs kms secrets status enable or status disable.
func (s SecretsCLI) SetStatus(ctx context.Context, name string, enabled bool) (*SecretsCLIStatus, error) {
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	return runSecretsCLI[SecretsCLIStatus](ctx, s, "status "+verb, "status", verb, name)
}

// Policy runs kms secrets policy get.
func (s SecretsCLI) Policy(ctx context.Context, name string) (*SecretsCLIPolicy, error) {
	return runSecretsCLI[SecretsCLIPolicy](ctx, s, "policy get", "policy", "get", name)
}

// SetPolicy runs kms secrets policy set; the interval goes as a duration in
// seconds (--interval <N>s).
func (s SecretsCLI) SetPolicy(ctx context.Context, name string, opts SecretsCLIPolicyOptions) (*SecretsCLIPolicy, error) {
	args := []string{"policy", "set", name, "--enabled=" + strconv.FormatBool(opts.Enabled)}
	if opts.IntervalSeconds > 0 {
		args = append(args, "--interval", strconv.FormatInt(opts.IntervalSeconds, 10)+"s")
	}
	if opts.RetainVersions > 0 {
		args = append(args, "--retain-versions", strconv.FormatInt(int64(opts.RetainVersions), 10))
	}
	if opts.RotationLambda != "" {
		args = append(args, "--rotation-lambda", opts.RotationLambda)
	}
	return runSecretsCLI[SecretsCLIPolicy](ctx, s, "policy set", args...)
}

// PrefixList runs kms secrets prefix list, with every value when includeData
// is set.
func (s SecretsCLI) PrefixList(ctx context.Context, prefix string, includeData bool) (*SecretsCLIList, error) {
	args := []string{"prefix", "list", prefix}
	if includeData {
		args = append(args, "--include-data")
	}
	return runSecretsCLI[SecretsCLIList](ctx, s, "prefix list", args...)
}

// runSecretsCLI runs platformctl kms secrets args and decodes its JSON into T.
func runSecretsCLI[T any](ctx context.Context, s SecretsCLI, operation string, args ...string) (*T, error) {
	output, err := s.Run(ctx, append([]string{"kms", "secrets"}, args...)...)
	if err != nil {
		return nil, CLIUpstreamGap("kms secrets "+operation, SecretsSDKGapIssue, err)
	}
	var out T
	if err := json.Unmarshal(output, &out); err != nil {
		return nil, ErrSecretsCLIOutput{Operation: operation, Output: string(output), Err: err}
	}
	return &out, nil
}
