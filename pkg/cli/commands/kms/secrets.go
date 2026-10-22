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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	secretsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

// ErrSecretNameRequired is returned when a secret name is empty.
type ErrSecretNameRequired struct{}

func (e ErrSecretNameRequired) Error() string {
	return "secret name is required"
}

// ErrSecretValueRequired is returned when a secret value is not provided.
type ErrSecretValueRequired struct{}

func (e ErrSecretValueRequired) Error() string {
	return "secret value is required (use --value)"
}

// ErrInvalidSecretValue is returned when --base64 is set and --value does
// not decode.
type ErrInvalidSecretValue struct {
	Err error
}

func (e ErrInvalidSecretValue) Error() string {
	return fmt.Sprintf("--value is not valid base64: %v", e.Err)
}

func (e ErrInvalidSecretValue) Unwrap() error {
	return e.Err
}

// ErrInvalidSecretVersion is returned when a version argument is not a
// positive integer.
type ErrInvalidSecretVersion struct {
	Value string
}

func (e ErrInvalidSecretVersion) Error() string {
	return fmt.Sprintf("invalid secret version %q: must be a positive integer", e.Value)
}

// ErrSecretOperationFailed wraps an error the SDK secrets client returned.
type ErrSecretOperationFailed struct {
	Operation string
	Name      string
	Err       error
}

func (e ErrSecretOperationFailed) Error() string {
	return fmt.Sprintf("secret %s %s failed: %v", e.Operation, e.Name, e.Err)
}

func (e ErrSecretOperationFailed) Unwrap() error {
	return e.Err
}

// ErrSecretsSDKGap is returned by a verb the go-quicbaas SDK does not serve:
// the SDK secrets client has no call for it (Err is nil), or the transport
// the CLI reached platformd over refused the call as unimplemented (Err is
// that refusal). It names the SDK method; the gap is closed upstream, never
// worked around here.
type ErrSecretsSDKGap struct {
	Verb   string
	Method string
	Err    error
}

func (e ErrSecretsSDKGap) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("kms secrets %s: the go-quicbaas SDK does not serve %s", e.Verb, e.Method)
	}
	return fmt.Sprintf("kms secrets %s: the go-quicbaas SDK does not serve %s: %v", e.Verb, e.Method, e.Err)
}

func (e ErrSecretsSDKGap) Unwrap() error {
	return e.Err
}

// secretsSDKMethods names the SDK secrets client method behind each verb
// that reaches platformd, for ErrSecretsSDKGap.
var secretsSDKMethods = map[string]string{
	"store":      "SecretsClient.Store",
	"get":        "SecretsClient.Get",
	"list":       "SecretsClient.List",
	"delete":     "SecretsClient.Delete",
	"rotate":     "SecretsClient.Rotate",
	"version":    "SecretsClient.GetVersion",
	"versions":   "SecretsClient.ListVersions",
	"rollback":   "SecretsClient.Rollback",
	"status":     "SecretsClient.UpdateStatus",
	"policy get": "SecretsClient.GetRotationPolicy",
	"policy set": "SecretsClient.SetRotationPolicy",
}

// secretOperationError maps a secrets client failure for operation on name.
// A call the transport refused as unimplemented is the SDK gap
// ErrSecretsSDKGap; any other failure is ErrSecretOperationFailed.
func secretOperationError(operation, name string, err error) error {
	if sdkerrors.IsUnimplemented(err) {
		return ErrSecretsSDKGap{Verb: operation, Method: secretsSDKMethods[operation], Err: err}
	}
	return ErrSecretOperationFailed{Operation: operation, Name: name, Err: err}
}

// secretsRunFunc runs one `kms secrets` verb against an open SDK client.
type secretsRunFunc func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error

// secretStoreOptions are the inputs of `kms secrets store`.
type secretStoreOptions struct {
	Value       string
	Base64      bool
	Description string
	Tags        []string
}

// secretPolicyOptions are the inputs of `kms secrets policy set`.
type secretPolicyOptions struct {
	Enabled        bool
	Interval       time.Duration
	RetainVersions int
	RotationLambda string
}

// secretStoreOutput is the result of `kms secrets store`.
type secretStoreOutput struct {
	Name    string `json:"name" yaml:"name"`
	Version int    `json:"version" yaml:"version"`
}

// secretOutput is a secret value as `get`, `version` and `prefix list
// --include-data` print it. Value is base64 in JSON and YAML.
type secretOutput struct {
	Name        string            `json:"name" yaml:"name"`
	Version     int               `json:"version" yaml:"version"`
	Value       []byte            `json:"value" yaml:"value"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	CreatedBy   string            `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// secretListOutput is the result of `kms secrets list` and `prefix list`.
type secretListOutput struct {
	Prefix  string         `json:"prefix,omitempty" yaml:"prefix,omitempty"`
	Secrets []string       `json:"secrets" yaml:"secrets"`
	Data    []secretOutput `json:"data,omitempty" yaml:"data,omitempty"`
	HasMore bool           `json:"has_more" yaml:"has_more"`
}

// secretDeleteOutput is the result of `kms secrets delete`.
type secretDeleteOutput struct {
	Name    string `json:"name" yaml:"name"`
	Deleted bool   `json:"deleted" yaml:"deleted"`
}

// secretRotateOutput is the result of `kms secrets rotate`.
type secretRotateOutput struct {
	Name       string `json:"name" yaml:"name"`
	OldVersion int    `json:"old_version" yaml:"old_version"`
	NewVersion int    `json:"new_version" yaml:"new_version"`
}

// secretVersionsOutput is the result of `kms secrets versions`.
type secretVersionsOutput struct {
	Name     string                `json:"name" yaml:"name"`
	Versions []secretVersionOutput `json:"versions" yaml:"versions"`
}

// secretVersionOutput is one entry of `kms secrets versions`; it carries no
// value.
type secretVersionOutput struct {
	Version   int               `json:"version" yaml:"version"`
	Metadata  map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	CreatedAt time.Time         `json:"created_at" yaml:"created_at"`
	CreatedBy string            `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// secretRollbackOutput is the result of `kms secrets rollback`.
type secretRollbackOutput struct {
	Name       string `json:"name" yaml:"name"`
	NewVersion int    `json:"new_version" yaml:"new_version"`
}

// secretStatusOutput is the result of `kms secrets status enable|disable`.
type secretStatusOutput struct {
	Name   string `json:"name" yaml:"name"`
	Status string `json:"status" yaml:"status"`
}

// secretPolicyOutput is the result of `kms secrets policy get|set`.
type secretPolicyOutput struct {
	Name            string    `json:"name" yaml:"name"`
	Enabled         bool      `json:"enabled" yaml:"enabled"`
	IntervalSeconds int64     `json:"interval_seconds" yaml:"interval_seconds"`
	NextRotation    time.Time `json:"next_rotation" yaml:"next_rotation"`
	RetainVersions  int       `json:"retain_versions" yaml:"retain_versions"`
	RotationLambda  string    `json:"rotation_lambda,omitempty" yaml:"rotation_lambda,omitempty"`
}

// NewSecretsCommand creates the secrets management command
func NewSecretsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Secrets management operations",
		Long: `Store, retrieve, version, rotate and manage secrets through the
go-quicbaas SDK secrets service platformd serves.

Examples:
  # Store a new secret
  platformctl kms secrets store my-api-key --value "secret123"

  # Store binary data
  platformctl kms secrets store my-cert-key --value "AAEC/w==" --base64

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
	cmd.AddCommand(newSecretsWatchCommand())

	return cmd
}

// runSecrets opens the SDK secrets client and runs one verb against it.
func runSecrets(flags *cli.CommonFlags, run secretsRunFunc) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openSecretsClient(base)
	if err != nil {
		return err
	}
	return run(base.Context(), client, base.Printer(), flags.OutputFormat)
}

// printSecrets prints out as JSON or YAML, or runs table for the table format.
func printSecrets(printer *cli.Printer, format cli.OutputFormat, out any, table func()) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(out)
	case cli.OutputFormatTable:
		table()
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// secretValueBytes returns the bytes of --value, base64-decoded when
// isBase64 is set.
func secretValueBytes(value string, isBase64 bool) ([]byte, error) {
	if value == "" {
		return nil, ErrSecretValueRequired{}
	}
	if !isBase64 {
		return []byte(value), nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidSecretValue{Err: err}
	}
	return decoded, nil
}

// parseSecretVersion parses a positive version argument.
func parseSecretVersion(arg string) (int, error) {
	version, err := strconv.Atoi(arg)
	if err != nil || version < 1 {
		return 0, ErrInvalidSecretVersion{Value: arg}
	}
	return version, nil
}

// secretOutputFrom converts an SDK secret. The value and description sit in
// the secret's data map under the keys the REST surface writes them to. The
// output is named by the name the caller asked for: the gRPC transport fills
// Path with the server's secret ID, which need not be that name.
func secretOutputFrom(name string, s *secretsclient.Secret) (secretOutput, error) {
	value, err := common.DecodeSecretValue(s.Data["value"])
	if err != nil {
		return secretOutput{}, ErrSecretOperationFailed{Operation: "get", Name: name, Err: err}
	}
	out := secretOutput{
		Name:      name,
		Version:   s.Version,
		Value:     value,
		Metadata:  s.Metadata,
		CreatedAt: s.CreatedAt,
	}
	if description, ok := s.Data["description"].(string); ok {
		out.Description = description
	}
	return out, nil
}

func newSecretsStoreCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts secretStoreOptions

	cmd := &cobra.Command{
		Use:   "store <name>",
		Short: "Store a secret",
		Long: `Store a secret value under a name. Storing an existing name adds a version.

Examples:
  platformctl kms secrets store db/password --value "s3cret" --tag env=prod`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsStore(ctx, client, printer, format, args[0], opts)
			})
		},
	}

	cmd.Flags().StringVar(&opts.Value, "value", "", "secret value (required)")
	cmd.Flags().BoolVar(&opts.Base64, "base64", false, "--value is base64; the decoded bytes are stored")
	cmd.Flags().StringVar(&opts.Description, "description", "", "description")
	cmd.Flags().StringArrayVar(&opts.Tags, "tag", nil, "metadata tag key=value (repeatable)")
	return cmd
}

// executeSecretsStore stores a secret the way the REST surface does: the
// value and description in the data map, tags as the secret's metadata.
func executeSecretsStore(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string, opts secretStoreOptions) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	value, err := secretValueBytes(opts.Value, opts.Base64)
	if err != nil {
		return err
	}
	tags, err := parseTagPairs(opts.Tags)
	if err != nil {
		return err
	}
	data := map[string]interface{}{"value": value}
	if opts.Description != "" {
		data["description"] = opts.Description
	}

	resp, err := client.Store(ctx, &secretsclient.StoreSecretRequest{Path: name, Data: data, Metadata: tags})
	if err != nil {
		return secretOperationError("store", name, err)
	}

	out := secretStoreOutput{Name: name, Version: resp.Version}
	return printSecrets(printer, format, out, func() {
		printer.PrintSuccess(fmt.Sprintf("Secret %s stored (version %d)", out.Name, out.Version))
	})
}

func newSecretsGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var version int

	cmd := &cobra.Command{
		Use:   "get <name>",
		Short: "Get a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsGet(ctx, client, printer, format, args[0], version)
			})
		},
	}

	cmd.Flags().IntVar(&version, "version", 0, "specific version (0 for the current one)")
	return cmd
}

// executeSecretsGet reads a secret, or one version of it when version is
// not 0.
func executeSecretsGet(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string, version int) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	if version < 0 {
		return ErrInvalidSecretVersion{Value: strconv.Itoa(version)}
	}
	var opts []secretsclient.GetOption
	if version > 0 {
		opts = append(opts, secretsclient.WithVersion(version))
	}

	secret, err := client.Get(ctx, name, opts...)
	if err != nil {
		return secretOperationError("get", name, err)
	}

	out, err := secretOutputFrom(name, secret)
	if err != nil {
		return err
	}
	return printSecrets(printer, format, out, func() { printSecretTable(printer, out) })
}

// printSecretTable prints one secret as key/value lines.
func printSecretTable(printer *cli.Printer, out secretOutput) {
	printer.PrintKeyValue("Name", out.Name)
	printer.PrintKeyValue("Version", strconv.Itoa(out.Version))
	printer.PrintKeyValue("Value", string(out.Value))
	if out.Description != "" {
		printer.PrintKeyValue("Description", out.Description)
	}
	for k, v := range out.Metadata {
		printer.PrintKeyValue("Tag "+k, v)
	}
	if !out.CreatedAt.IsZero() {
		printer.PrintKeyValue("Created At", out.CreatedAt.Format(time.RFC3339))
	}
	if out.CreatedBy != "" {
		printer.PrintKeyValue("Created By", out.CreatedBy)
	}
}

func newSecretsListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var prefix string
	var limit int

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret names",
		Long: `List secret names, optionally under a prefix.

The SDK returns every name in one answer; --limit caps how many are printed
and has_more reports that more exist.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsList(ctx, client, printer, format, prefix, limit, false)
			})
		},
	}

	cmd.Flags().StringVar(&prefix, "prefix", "", "filter by prefix")
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum names to print (0 for all)")
	return cmd
}

// executeSecretsList lists the names under prefix, at most limit of them
// when limit is above 0, and reads each secret when includeData is set.
// secretPathsUnder keeps the names that sit under prefix, in their listed
// order. The SDK gRPC transport does not carry the prefix to the server
// (quicbaas pkg/api/grpc Client.ListSecrets drops it), so List can answer with
// every secret in the tenant; the CLI's contract is the names under the prefix.
func secretPathsUnder(paths []string, prefix string) []string {
	under := make([]string, 0, len(paths))
	for _, path := range paths {
		if strings.HasPrefix(path, prefix) {
			under = append(under, path)
		}
	}
	return under
}

func executeSecretsList(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, prefix string, limit int, includeData bool) error {
	resp, err := client.List(ctx, prefix)
	if err != nil {
		return secretOperationError("list", prefix, err)
	}

	out := secretListOutput{Prefix: prefix, Secrets: secretPathsUnder(resp.Paths, prefix)}
	if limit > 0 && len(out.Secrets) > limit {
		out.Secrets = out.Secrets[:limit]
		out.HasMore = true
	}
	if includeData {
		for _, name := range out.Secrets {
			secret, err := client.Get(ctx, name)
			if err != nil {
				return secretOperationError("get", name, err)
			}
			data, err := secretOutputFrom(name, secret)
			if err != nil {
				return err
			}
			out.Data = append(out.Data, data)
		}
	}

	return printSecrets(printer, format, out, func() {
		if len(out.Data) > 0 {
			for _, secret := range out.Data {
				printSecretTable(printer, secret)
			}
			return
		}
		printer.PrintKeyValue("Secrets", strings.Join(out.Secrets, ", "))
		if out.HasMore {
			printer.PrintKeyValue("Has More", "true")
		}
	})
}

func newSecretsDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a secret and every version of it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsDelete(ctx, client, printer, format, args[0])
			})
		},
	}
}

// executeSecretsDelete deletes a secret.
func executeSecretsDelete(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	if err := client.Delete(ctx, name); err != nil {
		return secretOperationError("delete", name, err)
	}

	out := secretDeleteOutput{Name: name, Deleted: true}
	return printSecrets(printer, format, out, func() {
		printer.PrintSuccess(fmt.Sprintf("Secret %s deleted", name))
	})
}

func newSecretsRotateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var value string
	var isBase64 bool

	cmd := &cobra.Command{
		Use:   "rotate <name>",
		Short: "Rotate a secret to a new value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsRotate(ctx, client, printer, format, args[0], value, isBase64)
			})
		},
	}

	cmd.Flags().StringVar(&value, "value", "", "new value (required)")
	cmd.Flags().BoolVar(&isBase64, "base64", false, "--value is base64; the decoded bytes are stored")
	return cmd
}

// executeSecretsRotate stores a new version of a secret. The new value is sent
// as the same encoded data map a store writes, so a get after the rotation
// reads it back; the new version carries the value only.
func executeSecretsRotate(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name, value string, isBase64 bool) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	newValue, err := secretValueBytes(value, isBase64)
	if err != nil {
		return err
	}
	data, err := common.EncodeSecretData(map[string]interface{}{"value": newValue})
	if err != nil {
		return ErrSecretOperationFailed{Operation: "rotate", Name: name, Err: err}
	}

	resp, err := client.Rotate(ctx, &secretsclient.RotateSecretRequest{SecretID: name, NewData: data})
	if err != nil {
		return secretOperationError("rotate", name, err)
	}

	out := secretRotateOutput{Name: name, OldVersion: resp.OldVersion, NewVersion: resp.NewVersion}
	return printSecrets(printer, format, out, func() {
		printer.PrintSuccess(fmt.Sprintf("Secret %s rotated: version %d -> %d", name, out.OldVersion, out.NewVersion))
	})
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
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsVersion(ctx, client, printer, format, args[0], version)
			})
		},
	}
}

// executeSecretsVersion reads one version of a secret.
func executeSecretsVersion(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string, version int) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	info, err := client.GetVersion(ctx, &secretsclient.GetSecretVersionRequest{SecretID: name, Version: version})
	if err != nil {
		return secretOperationError("version", name, err)
	}

	out := secretOutput{
		Name:      name,
		Version:   info.Version,
		Value:     info.Data,
		Metadata:  info.Metadata,
		CreatedAt: info.CreatedAt,
		CreatedBy: info.CreatedBy,
	}
	return printSecrets(printer, format, out, func() { printSecretTable(printer, out) })
}

func newSecretsVersionsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "versions <name>",
		Short: "List every version of a secret",
		Long: `List every version of a secret with its metadata, without values.

Examples:
  platformctl kms secrets versions my-api-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsVersions(ctx, client, printer, format, args[0])
			})
		},
	}
}

// executeSecretsVersions lists the versions of a secret.
func executeSecretsVersions(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	resp, err := client.ListVersions(ctx, name)
	if err != nil {
		return secretOperationError("versions", name, err)
	}

	out := secretVersionsOutput{Name: name, Versions: make([]secretVersionOutput, 0, len(resp.Versions))}
	for _, v := range resp.Versions {
		out.Versions = append(out.Versions, secretVersionOutput{
			Version:   v.Version,
			Metadata:  v.Metadata,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy,
		})
	}
	return printSecrets(printer, format, out, func() {
		for _, v := range out.Versions {
			printer.PrintKeyValue(fmt.Sprintf("Version %d", v.Version), v.CreatedAt.Format(time.RFC3339))
		}
	})
}

func newSecretsRollbackCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "rollback <name> <version>",
		Short: "Make an earlier version the current one",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, err := parseSecretVersion(args[1])
			if err != nil {
				return err
			}
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsRollback(ctx, client, printer, format, args[0], version)
			})
		},
	}
}

// executeSecretsRollback rolls a secret back to targetVersion.
func executeSecretsRollback(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string, targetVersion int) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	resp, err := client.Rollback(ctx, &secretsclient.RollbackSecretRequest{SecretID: name, TargetVersion: targetVersion})
	if err != nil {
		return secretOperationError("rollback", name, err)
	}

	out := secretRollbackOutput{Name: name, NewVersion: resp.NewVersion}
	return printSecrets(printer, format, out, func() {
		printer.PrintSuccess(fmt.Sprintf("Secret %s rolled back to version %d (now version %d)", name, targetVersion, out.NewVersion))
	})
}

func newSecretsStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Enable or disable a secret",
	}
	for verb, status := range map[string]secretsclient.SecretStatus{
		"enable":  secretsclient.SecretStatusEnabled,
		"disable": secretsclient.SecretStatusDisabled,
	} {
		cmd.AddCommand(&cobra.Command{
			Use:   verb + " <name>",
			Short: "Set a secret's status to " + string(status),
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
					return executeSecretsStatus(ctx, client, printer, format, args[0], status)
				})
			},
		})
	}
	return cmd
}

// executeSecretsStatus enables or disables a secret.
func executeSecretsStatus(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string, status secretsclient.SecretStatus) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	if err := client.UpdateStatus(ctx, &secretsclient.UpdateSecretStatusRequest{SecretID: name, Status: status}); err != nil {
		return secretOperationError("status", name, err)
	}

	out := secretStatusOutput{Name: name, Status: string(status)}
	return printSecrets(printer, format, out, func() {
		printer.PrintSuccess(fmt.Sprintf("Secret %s is now %s", name, out.Status))
	})
}

func newSecretsPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts secretPolicyOptions

	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Automatic rotation policy",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "get <name>",
		Short: "Get a secret's rotation policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsPolicyGet(ctx, client, printer, format, args[0])
			})
		},
	})

	set := &cobra.Command{
		Use:   "set <name>",
		Short: "Set a secret's rotation policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsPolicySet(ctx, client, printer, format, args[0], opts)
			})
		},
	}
	set.Flags().BoolVar(&opts.Enabled, "enabled", true, "rotate automatically")
	set.Flags().DurationVar(&opts.Interval, "interval", 0, "rotation interval, e.g. 720h")
	set.Flags().IntVar(&opts.RetainVersions, "retain-versions", 0, "versions to keep (0 keeps every version)")
	set.Flags().StringVar(&opts.RotationLambda, "rotation-lambda", "", "lambda that generates the new value")
	cmd.AddCommand(set)

	return cmd
}

// policyOutputFrom converts an SDK rotation policy.
func policyOutputFrom(name string, p *secretsclient.RotationPolicy) secretPolicyOutput {
	return secretPolicyOutput{
		Name:            name,
		Enabled:         p.Enabled,
		IntervalSeconds: int64(p.Interval / time.Second),
		NextRotation:    p.NextRotation,
		RetainVersions:  p.RetainVersions,
		RotationLambda:  p.RotationLambda,
	}
}

// printPolicyTable prints a rotation policy as key/value lines.
func printPolicyTable(printer *cli.Printer, out secretPolicyOutput) {
	printer.PrintKeyValue("Name", out.Name)
	printer.PrintKeyValue("Enabled", strconv.FormatBool(out.Enabled))
	printer.PrintKeyValue("Interval", (time.Duration(out.IntervalSeconds) * time.Second).String())
	printer.PrintKeyValue("Retain Versions", strconv.Itoa(out.RetainVersions))
	if out.RotationLambda != "" {
		printer.PrintKeyValue("Rotation Lambda", out.RotationLambda)
	}
}

// executeSecretsPolicyGet reads a secret's rotation policy.
func executeSecretsPolicyGet(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	policy, err := client.GetRotationPolicy(ctx, name)
	if err != nil {
		return secretOperationError("policy get", name, err)
	}

	out := policyOutputFrom(name, policy)
	return printSecrets(printer, format, out, func() { printPolicyTable(printer, out) })
}

// executeSecretsPolicySet sets a secret's rotation policy and prints it.
func executeSecretsPolicySet(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat, name string, opts secretPolicyOptions) error {
	if name == "" {
		return ErrSecretNameRequired{}
	}
	policy := &secretsclient.RotationPolicy{
		Enabled:        opts.Enabled,
		Interval:       opts.Interval,
		RetainVersions: opts.RetainVersions,
		RotationLambda: opts.RotationLambda,
	}
	if err := client.SetRotationPolicy(ctx, &secretsclient.SetRotationPolicyRequest{SecretID: name, Policy: policy}); err != nil {
		return secretOperationError("policy set", name, err)
	}

	out := policyOutputFrom(name, policy)
	return printSecrets(printer, format, out, func() { printPolicyTable(printer, out) })
}

func newSecretsPrefixCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var includeData bool

	cmd := &cobra.Command{
		Use:   "prefix",
		Short: "Prefix operations",
	}
	list := &cobra.Command{
		Use:   "list <prefix>",
		Short: "List every secret under a prefix",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecrets(getFlags(), func(ctx context.Context, client quicbaassdk.SecretsClient, printer *cli.Printer, format cli.OutputFormat) error {
				return executeSecretsList(ctx, client, printer, format, args[0], 0, includeData)
			})
		},
	}
	list.Flags().BoolVar(&includeData, "include-data", false, "read and print every secret's value")
	cmd.AddCommand(list)
	return cmd
}

// newSecretsWatchCommand creates `kms secrets watch`, which the SDK secrets
// client cannot serve: it has no change stream.
func newSecretsWatchCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "watch <name>",
		Short: "Watch a secret for changes (SDK gap: no SecretsClient.Watch)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrSecretsSDKGap{Verb: "watch", Method: "SecretsClient.Watch"}
		},
	}
}
