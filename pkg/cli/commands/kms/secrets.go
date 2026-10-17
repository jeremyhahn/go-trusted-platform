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

package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Keys of the secret data map. The value is stored base64-encoded, the
// same encoding the platform REST API gives its []byte value, so a secret
// written by either surface reads back through the other.
const (
	secretValueKey       = "value"
	secretDescriptionKey = "description"
)

// ErrSecretsOperationFailed wraps an SDK error from a `kms secrets` verb.
type ErrSecretsOperationFailed struct {
	Operation string
	Name      string
	Err       error
}

func (e ErrSecretsOperationFailed) Error() string {
	if e.Name == "" {
		return fmt.Sprintf("secrets %s failed: %v", e.Operation, e.Err)
	}
	return fmt.Sprintf("secrets %s failed for %s: %v", e.Operation, e.Name, e.Err)
}

func (e ErrSecretsOperationFailed) Unwrap() error {
	return e.Err
}

// ErrSecretsEmptyResponse is returned when the SDK reports success but
// returns nothing.
type ErrSecretsEmptyResponse struct {
	Operation string
	Name      string
}

func (e ErrSecretsEmptyResponse) Error() string {
	return fmt.Sprintf("secrets %s returned no result for %s", e.Operation, e.Name)
}

// ErrSecretValueRequired is returned when a secret value is not provided
type ErrSecretValueRequired struct{}

func (e ErrSecretValueRequired) Error() string {
	return "secret value is required (use --value)"
}

// ErrSecretValueInvalidBase64 is returned when --base64 is set and --value
// does not decode.
type ErrSecretValueInvalidBase64 struct {
	Err error
}

func (e ErrSecretValueInvalidBase64) Error() string {
	return fmt.Sprintf("--value is not valid base64: %v", e.Err)
}

func (e ErrSecretValueInvalidBase64) Unwrap() error {
	return e.Err
}

// ErrSecretDataMalformed is returned when a stored secret carries no
// readable base64 value.
type ErrSecretDataMalformed struct {
	Name   string
	Reason string
}

func (e ErrSecretDataMalformed) Error() string {
	return fmt.Sprintf("secret %s has malformed data: %s", e.Name, e.Reason)
}

// ErrInvalidSecretVersion is returned when a version argument is not a
// positive integer.
type ErrInvalidSecretVersion struct {
	Value string
}

func (e ErrInvalidSecretVersion) Error() string {
	return fmt.Sprintf("invalid secret version %q: must be a positive integer", e.Value)
}

// ErrSecretStatusFlagRequired is returned when `secrets status` is not given
// exactly one of --enable and --disable.
type ErrSecretStatusFlagRequired struct{}

func (e ErrSecretStatusFlagRequired) Error() string {
	return "exactly one of --enable or --disable is required"
}

// secretStoreOutput is the result of `secrets store`.
type secretStoreOutput struct {
	SecretID string `json:"secret_id" yaml:"secret_id"`
	Version  int    `json:"version" yaml:"version"`
}

// secretOutput is one secret value: `secrets get` and `secrets version`.
// Data is the raw value; JSON carries it base64-encoded.
type secretOutput struct {
	SecretID    string            `json:"secret_id" yaml:"secret_id"`
	Version     int               `json:"version" yaml:"version"`
	Data        []byte            `json:"data" yaml:"data"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	CreatedAt   int64             `json:"created_at" yaml:"created_at"`
	CreatedBy   string            `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// secretSummary is one entry of `secrets list`.
type secretSummary struct {
	Name string `json:"name" yaml:"name"`
}

// secretListOutput is the result of `secrets list` and `secrets prefix list`.
type secretListOutput struct {
	Secrets    []secretSummary `json:"secrets" yaml:"secrets"`
	TotalCount int             `json:"total_count" yaml:"total_count"`
	HasMore    bool            `json:"has_more" yaml:"has_more"`
}

// secretDeleteOutput is the result of `secrets delete`.
type secretDeleteOutput struct {
	SecretID string `json:"secret_id" yaml:"secret_id"`
	Deleted  bool   `json:"deleted" yaml:"deleted"`
}

// secretRotateOutput is the result of `secrets rotate`.
type secretRotateOutput struct {
	SecretID   string `json:"secret_id" yaml:"secret_id"`
	OldVersion int    `json:"old_version" yaml:"old_version"`
	NewVersion int    `json:"new_version" yaml:"new_version"`
}

// secretVersionSummary is one entry of `secrets versions`.
type secretVersionSummary struct {
	Version   int    `json:"version" yaml:"version"`
	CreatedAt int64  `json:"created_at" yaml:"created_at"`
	CreatedBy string `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// secretVersionsOutput is the result of `secrets versions`.
type secretVersionsOutput struct {
	SecretID string                 `json:"secret_id" yaml:"secret_id"`
	Versions []secretVersionSummary `json:"versions" yaml:"versions"`
	HasMore  bool                   `json:"has_more" yaml:"has_more"`
}

// secretRollbackOutput is the result of `secrets rollback`.
type secretRollbackOutput struct {
	SecretID   string `json:"secret_id" yaml:"secret_id"`
	NewVersion int    `json:"new_version" yaml:"new_version"`
}

// secretStatusOutput is the result of `secrets status`.
type secretStatusOutput struct {
	SecretID string `json:"secret_id" yaml:"secret_id"`
	Status   string `json:"status" yaml:"status"`
}

// secretPolicyOutput is the result of `secrets policy get` and `policy set`.
type secretPolicyOutput struct {
	SecretID        string `json:"secret_id" yaml:"secret_id"`
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	IntervalSeconds int64  `json:"interval_seconds" yaml:"interval_seconds"`
	NextRotation    int64  `json:"next_rotation" yaml:"next_rotation"`
	RetainVersions  int    `json:"retain_versions" yaml:"retain_versions"`
	Method          string `json:"method,omitempty" yaml:"method,omitempty"`
}

// secretValueFlags are the value flags shared by `store` and `rotate`.
type secretValueFlags struct {
	value    string
	isBase64 bool
}

func (f *secretValueFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.value, "value", "", "secret value")
	cmd.Flags().BoolVar(&f.isBase64, "base64", false, "--value is base64-encoded binary data")
}

// raw returns the secret bytes the flags describe.
func (f *secretValueFlags) raw() ([]byte, error) {
	if f.value == "" {
		return nil, ErrSecretValueRequired{}
	}
	if !f.isBase64 {
		return []byte(f.value), nil
	}
	raw, err := base64.StdEncoding.DecodeString(f.value)
	if err != nil {
		return nil, ErrSecretValueInvalidBase64{Err: err}
	}
	return raw, nil
}

// encodeSecretData builds the secret data map for raw.
func encodeSecretData(raw []byte, description string) map[string]interface{} {
	data := map[string]interface{}{
		secretValueKey: base64.StdEncoding.EncodeToString(raw),
	}
	if description != "" {
		data[secretDescriptionKey] = description
	}
	return data
}

// decodeSecretValue reads the raw value back out of a secret data map.
func decodeSecretValue(name string, data map[string]interface{}) ([]byte, error) {
	encoded, ok := data[secretValueKey].(string)
	if !ok {
		return nil, ErrSecretDataMalformed{Name: name, Reason: "no string value"}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrSecretDataMalformed{Name: name, Reason: "value is not base64"}
	}
	return raw, nil
}

// decodeSecretVersionData reads the raw value out of a version's data,
// which the SDK returns as the JSON encoding of the data map.
func decodeSecretVersionData(name string, data []byte) ([]byte, error) {
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, ErrSecretDataMalformed{Name: name, Reason: "version data is not a JSON object"}
	}
	return decodeSecretValue(name, decoded)
}

// parseSecretVersion parses a positive version argument.
func parseSecretVersion(value string) (int, error) {
	version, err := strconv.Atoi(value)
	if err != nil || version <= 0 {
		return 0, ErrInvalidSecretVersion{Value: value}
	}
	return version, nil
}

// secretsAction is the body of one `kms secrets` verb once the client is open.
type secretsAction func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error

// runSecrets opens the SDK secrets client from the CLI flags and runs action.
func runSecrets(flags *cli.CommonFlags, action secretsAction) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openSecretsClient(base)
	if err != nil {
		return err
	}
	return action(base.Context(), client, base.Printer())
}

// NewSecretsCommand creates the secrets management command
func NewSecretsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Secrets management operations",
		Long: `Store, retrieve, rotate, and manage secrets.

Secrets provide secure storage for sensitive data like API keys, passwords, and
certificates. They support versioning, rollback, and automatic rotation
policies. Every verb calls the go-quicbaas SDK secrets client.

Examples:
  # Store a new secret
  platformctl kms secrets store my-api-key --value "secret123"

  # Store binary data
  platformctl kms secrets store tls/key --value "$(base64 -w0 key.der)" --base64

  # Get a secret value
  platformctl kms secrets get my-api-key

  # List secrets with a prefix
  platformctl kms secrets list --prefix database/

  # Rotate a secret
  platformctl kms secrets rotate my-api-key --value "newsecret456"

  # Delete a secret
  platformctl kms secrets delete my-api-key`,
	}

	cmd.AddCommand(newSecretsStoreCommand(getFlags))
	cmd.AddCommand(newSecretsGetCommand(getFlags))
	cmd.AddCommand(newSecretsListCommand(getFlags))
	cmd.AddCommand(newSecretsDeleteCommand(getFlags))
	cmd.AddCommand(newSecretsRotateCommand(getFlags))
	cmd.AddCommand(newSecretsVersionCommand(getFlags))
	cmd.AddCommand(newSecretsVersionsCommand(getFlags))
	cmd.AddCommand(newSecretsRollbackCommand(getFlags))
	cmd.AddCommand(newSecretsStatusCommand(getFlags))
	cmd.AddCommand(newSecretsPolicyCommand(getFlags))
	cmd.AddCommand(newSecretsPrefixCommand(getFlags))

	return cmd
}

func newSecretsStoreCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var value secretValueFlags
	var description string
	cmd := &cobra.Command{
		Use:   "store <name>",
		Short: "Store a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := value.raw()
			if err != nil {
				return err
			}
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsStore(ctx, client, printer, args[0], raw, description)
			})
		},
	}
	value.register(cmd)
	cmd.Flags().StringVar(&description, "description", "", "secret description")
	return cmd
}

func executeSecretsStore(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, raw []byte, description string) error {
	resp, err := client.Store(ctx, &secrets.StoreSecretRequest{
		Path: name,
		Data: encodeSecretData(raw, description),
	})
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "store", Name: name, Err: err}
	}
	if resp == nil {
		return ErrSecretsEmptyResponse{Operation: "store", Name: name}
	}
	return printer.Print(secretStoreOutput{SecretID: name, Version: resp.Version})
}

func newSecretsGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var version int
	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Get a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsGet(ctx, client, printer, args[0], version)
			})
		},
	}
	cmd.Flags().IntVar(&version, "version", 0, "secret version (0 = current)")
	return cmd
}

func executeSecretsGet(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, version int) error {
	var opts []secrets.GetOption
	if version > 0 {
		opts = append(opts, secrets.WithVersion(version))
	}
	secret, err := client.Get(ctx, name, opts...)
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "get", Name: name, Err: err}
	}
	if secret == nil {
		return ErrSecretsEmptyResponse{Operation: "get", Name: name}
	}
	raw, err := decodeSecretValue(name, secret.Data)
	if err != nil {
		return err
	}
	description, _ := secret.Data[secretDescriptionKey].(string)
	return printer.Print(secretOutput{
		SecretID:    name,
		Version:     secret.Version,
		Data:        raw,
		Description: description,
		Metadata:    secret.Metadata,
		CreatedAt:   unixOrZero(secret.CreatedAt),
	})
}

func newSecretsListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var prefix string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsList(ctx, client, printer, prefix, limit)
			})
		},
	}
	cmd.Flags().StringVar(&prefix, "prefix", "", "filter by name prefix")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum number of results (0 = all)")
	return cmd
}

// executeSecretsList lists the secrets under prefix. The SDK returns every
// match, so limit is applied here and has_more reports the remainder.
func executeSecretsList(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, prefix string, limit int) error {
	resp, err := client.List(ctx, prefix)
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "list", Name: prefix, Err: err}
	}
	if resp == nil {
		return ErrSecretsEmptyResponse{Operation: "list", Name: prefix}
	}
	paths := resp.Paths
	out := secretListOutput{TotalCount: len(paths)}
	if limit > 0 && len(paths) > limit {
		paths = paths[:limit]
		out.HasMore = true
	}
	out.Secrets = make([]secretSummary, 0, len(paths))
	for _, path := range paths {
		out.Secrets = append(out.Secrets, secretSummary{Name: path})
	}
	return printer.Print(out)
}

func newSecretsDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a secret and all its versions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsDelete(ctx, client, printer, args[0])
			})
		},
	}
}

func executeSecretsDelete(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string) error {
	if err := client.Delete(ctx, name); err != nil {
		return ErrSecretsOperationFailed{Operation: "delete", Name: name, Err: err}
	}
	return printer.Print(secretDeleteOutput{SecretID: name, Deleted: true})
}

func newSecretsRotateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var value secretValueFlags
	cmd := &cobra.Command{
		Use:   "rotate <name>",
		Short: "Rotate a secret to a new value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := value.raw()
			if err != nil {
				return err
			}
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsRotate(ctx, client, printer, args[0], raw)
			})
		},
	}
	value.register(cmd)
	return cmd
}

// executeSecretsRotate rotates name to raw. The SDK takes rotated data as
// bytes and stores them as the version's data, so they are the JSON
// encoding of the same data map `store` writes.
func executeSecretsRotate(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, raw []byte) error {
	newData, err := json.Marshal(encodeSecretData(raw, ""))
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "rotate", Name: name, Err: err}
	}
	resp, err := client.Rotate(ctx, &secrets.RotateSecretRequest{SecretID: name, NewData: newData})
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "rotate", Name: name, Err: err}
	}
	if resp == nil {
		return ErrSecretsEmptyResponse{Operation: "rotate", Name: name}
	}
	return printer.Print(secretRotateOutput{SecretID: name, OldVersion: resp.OldVersion, NewVersion: resp.NewVersion})
}

func newSecretsVersionCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "version <name> <version>",
		Short: "Get one version of a secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, err := parseSecretVersion(args[1])
			if err != nil {
				return err
			}
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsVersion(ctx, client, printer, args[0], version)
			})
		},
	}
}

func executeSecretsVersion(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, version int) error {
	info, err := client.GetVersion(ctx, &secrets.GetSecretVersionRequest{SecretID: name, Version: version})
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "version", Name: name, Err: err}
	}
	if info == nil {
		return ErrSecretsEmptyResponse{Operation: "version", Name: name}
	}
	raw, err := decodeSecretVersionData(name, info.Data)
	if err != nil {
		return err
	}
	return printer.Print(secretOutput{
		SecretID:  name,
		Version:   info.Version,
		Data:      raw,
		Metadata:  info.Metadata,
		CreatedAt: unixOrZero(info.CreatedAt),
		CreatedBy: info.CreatedBy,
	})
}

func newSecretsVersionsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "versions <name>",
		Short: "List the versions of a secret",
		Long: `List the versions of a secret, oldest first, with the time and
principal that created each. The SDK returns every version, so --limit is
applied by the CLI and has_more reports whether versions were left out.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsVersions(ctx, client, printer, args[0], limit)
			})
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "l", 100, "maximum number of results (0 = all)")
	return cmd
}

// executeSecretsVersions lists the versions of name. The SDK returns every
// version, so limit is applied here and has_more reports the remainder.
func executeSecretsVersions(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, limit int) error {
	resp, err := client.ListVersions(ctx, name)
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "versions", Name: name, Err: err}
	}
	if resp == nil {
		return ErrSecretsEmptyResponse{Operation: "versions", Name: name}
	}
	versions := resp.Versions
	out := secretVersionsOutput{SecretID: name}
	if limit > 0 && len(versions) > limit {
		versions = versions[:limit]
		out.HasMore = true
	}
	out.Versions = make([]secretVersionSummary, 0, len(versions))
	for _, v := range versions {
		out.Versions = append(out.Versions, secretVersionSummary{
			Version:   v.Version,
			CreatedAt: unixOrZero(v.CreatedAt),
			CreatedBy: v.CreatedBy,
		})
	}
	return printer.Print(out)
}

func newSecretsRollbackCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "rollback <name> <version>",
		Short: "Make an earlier version of a secret current again",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, err := parseSecretVersion(args[1])
			if err != nil {
				return err
			}
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsRollback(ctx, client, printer, args[0], version)
			})
		},
	}
}

func executeSecretsRollback(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, version int) error {
	resp, err := client.Rollback(ctx, &secrets.RollbackSecretRequest{SecretID: name, TargetVersion: version})
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "rollback", Name: name, Err: err}
	}
	if resp == nil {
		return ErrSecretsEmptyResponse{Operation: "rollback", Name: name}
	}
	return printer.Print(secretRollbackOutput{SecretID: name, NewVersion: resp.NewVersion})
}

func newSecretsStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var enable, disable bool
	cmd := &cobra.Command{
		Use:   "status <name>",
		Short: "Enable or disable a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if enable == disable {
				return ErrSecretStatusFlagRequired{}
			}
			status := secrets.SecretStatusDisabled
			if enable {
				status = secrets.SecretStatusEnabled
			}
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsStatus(ctx, client, printer, args[0], status)
			})
		},
	}
	cmd.Flags().BoolVar(&enable, "enable", false, "enable the secret")
	cmd.Flags().BoolVar(&disable, "disable", false, "disable the secret")
	return cmd
}

func executeSecretsStatus(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, status secrets.SecretStatus) error {
	if err := client.UpdateStatus(ctx, &secrets.UpdateSecretStatusRequest{SecretID: name, Status: status}); err != nil {
		return ErrSecretsOperationFailed{Operation: "status", Name: name, Err: err}
	}
	return printer.Print(secretStatusOutput{SecretID: name, Status: strings.ToUpper(string(status))})
}

func newSecretsPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Automatic rotation policy operations",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get <name>",
		Short: "Get the rotation policy of a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsPolicyGet(ctx, client, printer, args[0])
			})
		},
	})
	cmd.AddCommand(newSecretsPolicySetCommand(getFlags))
	return cmd
}

func newSecretsPolicySetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	policy := secrets.RotationPolicy{}
	cmd := &cobra.Command{
		Use:   "set <name>",
		Short: "Set the rotation policy of a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsPolicySet(ctx, client, printer, args[0], policy)
			})
		},
	}
	cmd.Flags().BoolVar(&policy.Enabled, "enabled", true, "enable automatic rotation")
	cmd.Flags().DurationVar(&policy.Interval, "interval", 0, "rotation interval, e.g. 720h")
	cmd.Flags().IntVar(&policy.RetainVersions, "retain-versions", 0, "versions to keep (0 = server default)")
	cmd.Flags().StringVar(&policy.RotationLambda, "method", "", "rotation method")
	return cmd
}

func secretPolicyToOutput(name string, policy *secrets.RotationPolicy) secretPolicyOutput {
	return secretPolicyOutput{
		SecretID:        name,
		Enabled:         policy.Enabled,
		IntervalSeconds: int64(policy.Interval / time.Second),
		NextRotation:    unixOrZero(policy.NextRotation),
		RetainVersions:  policy.RetainVersions,
		Method:          policy.RotationLambda,
	}
}

func executeSecretsPolicyGet(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string) error {
	policy, err := client.GetRotationPolicy(ctx, name)
	if err != nil {
		return ErrSecretsOperationFailed{Operation: "policy get", Name: name, Err: err}
	}
	if policy == nil {
		return ErrSecretsEmptyResponse{Operation: "policy get", Name: name}
	}
	return printer.Print(secretPolicyToOutput(name, policy))
}

func executeSecretsPolicySet(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, name string, policy secrets.RotationPolicy) error {
	if err := client.SetRotationPolicy(ctx, &secrets.SetRotationPolicyRequest{SecretID: name, Policy: &policy}); err != nil {
		return ErrSecretsOperationFailed{Operation: "policy set", Name: name, Err: err}
	}
	return printer.Print(secretPolicyToOutput(name, &policy))
}

func newSecretsPrefixCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prefix",
		Short: "Prefix operations",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list <prefix>",
		Short: "List every secret under a prefix",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer) error {
				return executeSecretsList(ctx, client, printer, args[0], 0)
			})
		},
	})
	return cmd
}
