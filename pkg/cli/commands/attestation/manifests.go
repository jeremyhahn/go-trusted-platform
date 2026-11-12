// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package attestation

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newManifestsCommand groups the verbs over the node's stored host
// attestation manifests (#1686).
func newManifestsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifests",
		Short: "Stored host attestation manifests",
		Long: `List, show and delete the host attestation manifests a node has stored.

A manifest binds the host's TPM quote, its VMs' and containers' attestations
and a Merkle root over all of them under one AK signature. These verbs read
and remove stored manifests; they never build or verify one.`,
	}
	cmd.AddCommand(newManifestsListCommand(getFlags))
	cmd.AddCommand(newManifestsGetCommand(getFlags))
	cmd.AddCommand(newManifestsDeleteCommand(getFlags))
	return cmd
}

// manifestsListOptions carries the list filters onto the request.
type manifestsListOptions struct {
	HostID string
	Limit  uint32
	Offset uint32
}

func newManifestsListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts manifestsListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored attestation manifests",
		Long: `List the stored host attestation manifests, optionally for one host
and one page.

Examples:
  platformctl attestation manifests list
  platformctl attestation manifests list --host-id host-a --limit 20
  platformctl attestation manifests list -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.listManifests(opts)
		},
	}
	cmd.Flags().StringVar(&opts.HostID, "host-id", "", "only manifests of this host")
	cmd.Flags().Uint32Var(&opts.Limit, "limit", 0, "maximum number of manifests to return (0: the server's default)")
	cmd.Flags().Uint32Var(&opts.Offset, "offset", 0, "number of manifests to skip")
	return cmd
}

func newManifestsGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <manifest-id>",
		Short: "Show one stored attestation manifest",
		Long: `Show one stored host attestation manifest: its host, when it was
generated, the format version, the signature algorithm, the Merkle root and
how many VM and container attestations it carries.

Examples:
  platformctl attestation manifests get m-123
  platformctl attestation manifests get m-123 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseManifestID(args[0])
			if err != nil {
				return err
			}
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.getManifest(id)
		},
	}
}

func newManifestsDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <manifest-id>",
		Short: "Delete one stored attestation manifest",
		Long: `Delete one stored host attestation manifest.

Examples:
  platformctl attestation manifests delete m-123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseManifestID(args[0])
			if err != nil {
				return err
			}
			r, closer, err := connect(getFlags())
			if err != nil {
				return err
			}
			defer closer.Close()
			return r.deleteManifest(id)
		},
	}
}

// parseManifestID refuses an empty or whitespace-only id before a connection
// is made.
func parseManifestID(arg string) (string, error) {
	id := strings.TrimSpace(arg)
	if id == "" {
		return "", ErrInvalidManifestID{ID: arg}
	}
	return id, nil
}

// manifestView is the output shape of one manifest. It names the manifest's
// identity and how much it carries; the quote and per-workload evidence stay
// in the wire message.
type manifestView struct {
	ID                 string `json:"id" yaml:"id"`
	HostID             string `json:"host_id" yaml:"host_id"`
	Timestamp          string `json:"timestamp" yaml:"timestamp"`
	Version            string `json:"version" yaml:"version"`
	SignatureAlgorithm string `json:"signature_algorithm" yaml:"signature_algorithm"`
	MerkleRoot         string `json:"merkle_root" yaml:"merkle_root"`
	VMs                int    `json:"vms" yaml:"vms"`
	Containers         int    `json:"containers" yaml:"containers"`
}

// manifestsOutput is the output shape of a listing; Total is the server's
// count of every matching manifest, Count the number on this page.
type manifestsOutput struct {
	Manifests []manifestView `json:"manifests" yaml:"manifests"`
	Count     int            `json:"count" yaml:"count"`
	Total     uint32         `json:"total" yaml:"total"`
}

// manifestDeleteOutput is the output shape of a deletion.
type manifestDeleteOutput struct {
	ID      string `json:"id" yaml:"id"`
	Deleted bool   `json:"deleted" yaml:"deleted"`
}

func manifestViewFromProto(m *platformv1.HostManifest) manifestView {
	v := manifestView{
		ID:                 m.GetId(),
		HostID:             m.GetHostId(),
		Version:            m.GetVersion(),
		SignatureAlgorithm: m.GetSignatureAlgorithm(),
		MerkleRoot:         hex.EncodeToString(m.GetMerkleRoot()),
		VMs:                len(m.GetVms()),
		Containers:         len(m.GetContainers()),
	}
	if ts := m.GetTimestamp(); ts != nil {
		v.Timestamp = ts.AsTime().UTC().Format(time.RFC3339)
	}
	return v
}

func (r *runner) listManifests(opts manifestsListOptions) error {
	manifests, total, err := r.client.ListManifests(r.ctx, &platformv1.ListManifestsRequest{
		HostId: opts.HostID,
		Limit:  opts.Limit,
		Offset: opts.Offset,
	})
	if err != nil {
		return ErrListManifestsFailed{Reason: err.Error()}
	}
	views := make([]manifestView, 0, len(manifests))
	for _, m := range manifests {
		views = append(views, manifestViewFromProto(m))
	}
	if r.format == cli.OutputFormatTable {
		printManifestsTable(r.printer, views)
		return nil
	}
	return r.output(manifestsOutput{Manifests: views, Count: len(views), Total: total})
}

func (r *runner) getManifest(id string) error {
	m, err := r.client.GetManifest(r.ctx, id)
	if err != nil {
		return ErrGetManifestFailed{ID: id, Reason: err.Error()}
	}
	if r.format == cli.OutputFormatTable {
		printManifestDetails(r.printer, manifestViewFromProto(m))
		return nil
	}
	// JSON and YAML carry the stored manifest whole (nonce, signature,
	// metadata, host/VM/container evidence), not the table summary.
	raw, err := manifestJSON.Marshal(m)
	if err != nil {
		return ErrManifestEncodeFailed{ID: id, Reason: err.Error()}
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ErrManifestEncodeFailed{ID: id, Reason: err.Error()}
	}
	return r.output(doc)
}

// manifestJSON renders a stored manifest with its proto field names, the
// names the dns and appsvc commands print.
var manifestJSON = protojson.MarshalOptions{UseProtoNames: true}

func (r *runner) deleteManifest(id string) error {
	if err := r.client.DeleteManifest(r.ctx, id); err != nil {
		return ErrDeleteManifestFailed{ID: id, Reason: err.Error()}
	}
	out := manifestDeleteOutput{ID: id, Deleted: true}
	if r.format == cli.OutputFormatTable {
		r.printer.PrintKeyValue("Manifest", out.ID)
		r.printer.PrintKeyValue("Deleted", yesNo(out.Deleted))
		return nil
	}
	return r.output(out)
}

func printManifestsTable(printer *cli.Printer, views []manifestView) {
	if len(views) == 0 {
		printer.PrintInfo("No attestation manifests are stored")
		return
	}
	table := cli.TableData{
		Headers: []string{"ID", "Host", "Timestamp", "Version", "Signature", "VMs", "Containers"},
	}
	for _, v := range views {
		table.Rows = append(table.Rows, []string{
			v.ID, orDash(v.HostID), orDash(v.Timestamp), orDash(v.Version),
			orDash(v.SignatureAlgorithm), strconv.Itoa(v.VMs), strconv.Itoa(v.Containers),
		})
	}
	_ = printer.Print(table)
}

func printManifestDetails(printer *cli.Printer, v manifestView) {
	printer.PrintKeyValue("ID", v.ID)
	printer.PrintKeyValue("Host", orDash(v.HostID))
	printer.PrintKeyValue("Timestamp", orDash(v.Timestamp))
	printer.PrintKeyValue("Version", orDash(v.Version))
	printer.PrintKeyValue("Signature", orDash(v.SignatureAlgorithm))
	printer.PrintKeyValue("Merkle root", orDash(v.MerkleRoot))
	printer.PrintKeyValue("VMs", strconv.Itoa(v.VMs))
	printer.PrintKeyValue("Containers", strconv.Itoa(v.Containers))
}
