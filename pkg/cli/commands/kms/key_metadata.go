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
	"fmt"
	"time"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrGetKeyMetadataFailed is returned when getting key metadata fails
type ErrGetKeyMetadataFailed struct {
	KeyID string
	Err   error
}

func (e ErrGetKeyMetadataFailed) Error() string {
	return fmt.Sprintf("failed to get metadata for key %s: %v", e.KeyID, e.Err)
}

func (e ErrGetKeyMetadataFailed) Unwrap() error {
	return e.Err
}

// ErrUpdateKeyMetadataFailed is returned when updating key metadata fails
type ErrUpdateKeyMetadataFailed struct {
	KeyID string
	Err   error
}

func (e ErrUpdateKeyMetadataFailed) Error() string {
	return fmt.Sprintf("failed to update metadata for key %s: %v", e.KeyID, e.Err)
}

func (e ErrUpdateKeyMetadataFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidTagFormat is returned when a tag has an invalid format
type ErrInvalidTagFormat struct {
	Tag string
}

func (e ErrInvalidTagFormat) Error() string {
	return fmt.Sprintf("invalid tag format: %s (expected key=value)", e.Tag)
}

// keyMetadataOutput is the CLI presentation of key metadata.
type keyMetadataOutput struct {
	KeyID              string            `json:"key_id"`
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	Algorithm          string            `json:"algorithm"`
	Status             string            `json:"status"`
	Usage              []string          `json:"usage,omitempty"`
	Version            int               `json:"version"`
	Exportable         bool              `json:"exportable"`
	DeletionProtection bool              `json:"deletion_protection"`
	CreatedAt          string            `json:"created_at,omitempty"`
	UpdatedAt          string            `json:"updated_at,omitempty"`
	LastUsedAt         string            `json:"last_used_at,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Owner              string            `json:"owner,omitempty"`
}

// newKeyMetadataOutput converts the SDK metadata response for display.
func newKeyMetadataOutput(meta *kms.KeyMetadataResponse) *keyMetadataOutput {
	out := &keyMetadataOutput{
		KeyID:              meta.KeyID,
		Name:               meta.Name,
		Description:        meta.Description,
		Algorithm:          meta.Algorithm.String(),
		Status:             meta.Status.String(),
		Usage:              keyUsageStrings(meta.Usage),
		Version:            meta.Version,
		Exportable:         meta.Exportable,
		DeletionProtection: meta.DeletionProtection,
		Tags:               meta.Tags,
		Owner:              meta.Owner,
	}
	out.CreatedAt = formatTimeOrEmpty(meta.CreatedAt)
	out.UpdatedAt = formatTimeOrEmpty(meta.UpdatedAt)
	out.LastUsedAt = formatTimeOrEmpty(meta.LastUsedAt)
	return out
}

// formatTimeOrEmpty renders t in RFC 3339 UTC, or "" when unset.
func formatTimeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// newKeyMetadataCommand creates the key metadata subcommand group
func newKeyMetadataCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Manage key metadata",
		Long: `Get or update metadata for a cryptographic key.

Key metadata includes name, description, tags, and other non-sensitive
information about the key. This does not expose key material.`,
	}

	cmd.AddCommand(newKeyMetadataGetCommand(getFlags))
	cmd.AddCommand(newKeyMetadataUpdateCommand(getFlags))

	return cmd
}

// newKeyMetadataGetCommand creates the metadata get subcommand
func newKeyMetadataGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <key-id>",
		Short: "Get key metadata",
		Long: `Retrieve metadata for a cryptographic key without exposing key material.

Examples:
  # Get metadata for a key
  platformctl kms key metadata get my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyMetadataGet(getFlags(), args[0])
		},
	}

	return cmd
}

// runKeyMetadataGet opens the SDK connection and delegates to executeKeyMetadataGet.
func runKeyMetadataGet(flags *cli.CommonFlags, keyID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyMetadataGet(base.Context(), client, base.Printer(), keyID)
}

// executeKeyMetadataGet retrieves and prints key metadata.
func executeKeyMetadataGet(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, keyID string) error {
	meta, err := client.GetKeyMetadata(ctx, keyID)
	if err != nil {
		return ErrGetKeyMetadataFailed{KeyID: keyID, Err: err}
	}
	return printer.Print(newKeyMetadataOutput(meta))
}

// newKeyMetadataUpdateCommand creates the metadata update subcommand
func newKeyMetadataUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var name string
	var description string
	var tags []string
	var removeTags []string

	cmd := &cobra.Command{
		Use:   "update <key-id>",
		Short: "Update key metadata",
		Long: `Update mutable metadata fields for a cryptographic key.

Tags are specified as key=value pairs. You can add new tags, update
existing tags, or remove tags.

Examples:
  # Update name and description
  platformctl kms key metadata update my-key --name "Production API Key" --description "Key for API authentication"

  # Add tags and remove an obsolete tag
  platformctl kms key metadata update my-key --tag env=prod --remove-tag temp`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyMetadataUpdate(getFlags(), args[0], name, description, tags, removeTags)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "new key name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "new key description")
	cmd.Flags().StringArrayVarP(&tags, "tag", "t", nil, "add or update tag (format: key=value)")
	cmd.Flags().StringArrayVar(&removeTags, "remove-tag", nil, "remove tag by key")

	return cmd
}

// runKeyMetadataUpdate opens the SDK connection and delegates to executeKeyMetadataUpdate.
func runKeyMetadataUpdate(flags *cli.CommonFlags, keyID, name, description string, tags, removeTags []string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyMetadataUpdate(base.Context(), client, base.Printer(), keyID, name, description, tags, removeTags)
}

// executeKeyMetadataUpdate updates key metadata via the quicbaas SDK KMS client.
func executeKeyMetadataUpdate(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, keyID, name, description string, tags, removeTags []string) error {
	tagMap, err := parseTagPairs(tags)
	if err != nil {
		return err
	}

	meta, err := client.UpdateKeyMetadata(ctx, &kms.UpdateKeyMetadataRequest{
		KeyID:       keyID,
		Name:        name,
		Description: description,
		Tags:        tagMap,
		RemoveTags:  removeTags,
	})
	if err != nil {
		return ErrUpdateKeyMetadataFailed{KeyID: keyID, Err: err}
	}

	printer.PrintSuccess(fmt.Sprintf("Key %s metadata updated", keyID))
	return printer.Print(newKeyMetadataOutput(meta))
}
