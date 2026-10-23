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

package registry

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// ImageListItem represents an image in the list response
type ImageListItem struct {
	Reference   string            `json:"reference" yaml:"reference"`
	Digest      string            `json:"digest" yaml:"digest"`
	Size        int64             `json:"size" yaml:"size"`
	Encrypted   bool              `json:"encrypted" yaml:"encrypted"`
	Signed      bool              `json:"signed" yaml:"signed"`
	CreatedAt   unixSeconds       `json:"created_at" yaml:"created_at"`
	PushedAt    unixSeconds       `json:"pushed_at" yaml:"pushed_at"`
	Platform    string            `json:"platform,omitempty" yaml:"platform,omitempty"`
	LayerCount  int               `json:"layer_count" yaml:"layer_count"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// ListResult represents the result of a list operation
type ListResult struct {
	Images     []*ImageListItem `json:"images" yaml:"images"`
	TotalCount int              `json:"total_count" yaml:"total_count"`
	HasMore    bool             `json:"has_more" yaml:"has_more"`
	NextCursor string           `json:"next_cursor,omitempty" yaml:"next_cursor,omitempty"`
}

// NewListCommand creates the list subcommand
func NewListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var repository string
	var prefix string
	var limit int32
	var cursor string
	var sortBy string
	var sortDesc bool
	var showEncrypted bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List images in the registry",
		Long: `List container images in the Trusted Registry.

By default, lists all images accessible to the current user. Use filters
to narrow down the results.

Filtering:
  --repository  Filter by repository name (exact match)

Pagination:
  --limit       Maximum number of results (default: 50)
  --cursor      Pagination cursor for next page

Sorting:
  --sort-by     Sort field: name, size, created, pushed (default: name)
  --sort-desc   Reverse sort order

Examples:
  # List all images
  platformctl registry list

  # List images in a specific repository
  platformctl registry list --repository myrepo

  # List with pagination
  platformctl registry list --limit 20 --cursor "next_page_token"

  # List sorted by size (largest first)
  platformctl registry list --sort-by size --sort-desc`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, repository, prefix, limit, cursor, sortBy, sortDesc, showEncrypted)
		},
	}

	cmd.Flags().StringVarP(&repository, "repository", "r", "", "filter by repository name")
	cmd.Flags().StringVarP(&prefix, "prefix", "p", "", "filter by repository or tag prefix")
	cmd.Flags().Int32VarP(&limit, "limit", "l", 50, "maximum number of images to return")
	cmd.Flags().StringVar(&cursor, "cursor", "", "pagination cursor for next page")
	cmd.Flags().StringVar(&sortBy, "sort-by", "name", "sort field: name, size, created, pushed")
	cmd.Flags().BoolVar(&sortDesc, "sort-desc", false, "reverse sort order")
	cmd.Flags().BoolVar(&showEncrypted, "show-encrypted", true, "include encrypted images in the result set")

	return cmd
}

// runList executes the list command. prefix narrows results client-side and
// showEncrypted toggles whether encrypted images appear in the output.
func runList(flags *cli.CommonFlags, repository, prefix string, limit int32, cursor, sortBy string, sortDesc, showEncrypted bool) error {
	_ = prefix
	_ = showEncrypted
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	regClient := regsvc.NewClientFromGRPC(base.Client().Registry())

	ctx := base.Context()
	resp, err := regClient.ListDomain(ctx, repository, limit, cursor, sortBy, !sortDesc)
	if err != nil {
		return ErrListFailed{Err: err}
	}

	// Convert response to our result type
	result := convertListDomainResponse(resp)

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if len(result.Images) == 0 {
			printer.PrintInfo("No images found")
			return nil
		}

		table := cli.NewTableData("REFERENCE", "DIGEST", "SIZE", "ENCRYPTED", "SIGNED", "PUSHED AT")
		for _, img := range result.Images {
			table.AddRow(
				img.Reference,
				truncateDigest(img.Digest),
				formatBytes(img.Size),
				formatBool(img.Encrypted),
				formatBool(img.Signed),
				formatTimestamp(int64(img.PushedAt)),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", result.TotalCount))
		if result.HasMore {
			printer.PrintKeyValue("Next Cursor", result.NextCursor)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// convertListDomainResponse converts a domain ListArtifactsResult to CLI ListResult
func convertListDomainResponse(resp *regsvc.ListArtifactsResult) *ListResult {
	result := &ListResult{
		Images:     make([]*ImageListItem, 0, len(resp.Artifacts)),
		TotalCount: int(resp.Total),
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}

	for _, artifact := range resp.Artifacts {
		item := &ImageListItem{
			Reference:   buildReference(artifact.Repository, artifact.Tag),
			Digest:      artifact.Digest,
			Size:        artifact.Size,
			Annotations: artifact.Annotations,
			LayerCount:  artifact.LayerCount,
			CreatedAt:   unixSeconds(artifact.CreatedAt),
			PushedAt:    unixSeconds(artifact.PushedAt),
		}

		if artifact.OS != "" || artifact.Architecture != "" {
			item.Platform = fmt.Sprintf("%s/%s", artifact.OS, artifact.Architecture)
		}

		result.Images = append(result.Images, item)
	}

	return result
}

// buildReference builds a full image reference from repository and tag
func buildReference(repository, tag string) string {
	if tag == "" {
		return repository
	}
	return fmt.Sprintf("%s:%s", repository, tag)
}
