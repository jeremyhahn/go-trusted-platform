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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// ErrListKeyVersionsFailed is returned when listing key versions fails
type ErrListKeyVersionsFailed struct {
	KeyID string
	Err   error
}

func (e ErrListKeyVersionsFailed) Error() string {
	return fmt.Sprintf("failed to list versions for key %s: %v", e.KeyID, e.Err)
}

func (e ErrListKeyVersionsFailed) Unwrap() error {
	return e.Err
}

// keyVersionsClient is the part of the platform KMS client that lists key
// versions.
type keyVersionsClient interface {
	GetKeyVersions(ctx context.Context, keyID string, limit int32, cursor string) (*platformv1.GetKeyVersionsResponse, error)
}

// keyVersionOutput is one key version as `kms key versions` prints it.
type keyVersionOutput struct {
	Version    uint64 `json:"version" yaml:"version"`
	Algorithm  string `json:"algorithm" yaml:"algorithm"`
	Status     string `json:"status" yaml:"status"`
	CreatedAt  int64  `json:"created_at" yaml:"created_at"`
	DisabledAt int64  `json:"disabled_at" yaml:"disabled_at"`
}

// keyVersionsOutput is one page of key versions as `kms key versions` prints it.
type keyVersionsOutput struct {
	KeyID      string             `json:"key_id" yaml:"key_id"`
	Versions   []keyVersionOutput `json:"versions" yaml:"versions"`
	HasMore    bool               `json:"has_more" yaml:"has_more"`
	NextCursor string             `json:"next_cursor" yaml:"next_cursor"`
}

// newKeyVersionsCommand creates the key versions subcommand
func newKeyVersionsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var limit int32
	var cursor string

	cmd := &cobra.Command{
		Use:   "versions <key-id>",
		Short: "List all versions of a key",
		Long: `List all versions of a cryptographic key with their status and metadata.

Each key can have multiple versions created through rotation. This command
displays all versions with their creation time, status, and algorithm.
Use the --limit flag to control pagination and pass the printed next cursor
to --cursor for the next page.

Examples:
  platformctl kms key versions my-key
  platformctl kms key versions my-key --limit 10 --cursor <next-cursor>`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyVersions(getFlags(), args[0], limit, cursor)
		},
	}

	cmd.Flags().Int32VarP(&limit, "limit", "l", 50, "maximum number of versions to return")
	cmd.Flags().StringVar(&cursor, "cursor", "", "pagination cursor for next page")

	return cmd
}

// runKeyVersions lists a key's versions through platformd's KMS service.
func runKeyVersions(flags *cli.CommonFlags, keyID string, limit int32, cursor string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := kmssvc.NewClientFromGRPC(base.Client().KMS())
	out, err := listKeyVersions(base.Context(), client, keyID, limit, cursor)
	if err != nil {
		return err
	}
	return printKeyVersions(base.Printer(), flags.OutputFormat, out)
}

// listKeyVersions fetches one page of a key's versions.
func listKeyVersions(ctx context.Context, client keyVersionsClient, keyID string, limit int32, cursor string) (*keyVersionsOutput, error) {
	resp, err := client.GetKeyVersions(ctx, keyID, limit, cursor)
	if err != nil {
		return nil, ErrListKeyVersionsFailed{KeyID: keyID, Err: err}
	}

	out := &keyVersionsOutput{
		KeyID:      resp.GetKeyId(),
		Versions:   make([]keyVersionOutput, 0, len(resp.GetVersions())),
		HasMore:    resp.GetHasMore(),
		NextCursor: resp.GetNextCursor(),
	}
	for _, v := range resp.GetVersions() {
		out.Versions = append(out.Versions, keyVersionOutput{
			Version:    v.GetVersion(),
			Algorithm:  v.GetAlgorithm().String(),
			Status:     v.GetStatus().String(),
			CreatedAt:  v.GetCreatedAt(),
			DisabledAt: v.GetDisabledAt(),
		})
	}
	return out, nil
}

// printKeyVersions prints a page of key versions in the selected format.
func printKeyVersions(printer *cli.Printer, format cli.OutputFormat, out *keyVersionsOutput) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(out)

	case cli.OutputFormatTable:
		table := cli.TableData{Headers: []string{"VERSION", "ALGORITHM", "STATUS", "CREATED", "DISABLED"}}
		for _, v := range out.Versions {
			table.Rows = append(table.Rows, []string{
				fmt.Sprintf("%d", v.Version),
				v.Algorithm,
				v.Status,
				formatKeyTimestamp(v.CreatedAt),
				formatKeyTimestamp(v.DisabledAt),
			})
		}
		if err := printer.Print(table); err != nil {
			return err
		}
		if out.HasMore {
			printer.PrintKeyValue("Next Cursor", out.NextCursor)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}
