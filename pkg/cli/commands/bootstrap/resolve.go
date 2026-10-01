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

package bootstrap

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newResolveCommand creates the resolve subcommand, which prints or writes
// each node's resolved platform config without contacting anything.
func newResolveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		configPath string
		nodes      []string
		dumpDir    string
	)

	cmd := &cobra.Command{
		Use:   "resolve",
		Short: "Resolve each node's platform config",
		Long: `Resolve each node's platform config the way bootstrap writes it: the
role template, merged with the platform identity, the node's overrides
and its node identity.

Nothing is contacted and no netboot media build is needed, so the
command works on any host that can read the config and its templates.
The hardware keys a real run reads from each node's BMC are absent.

Without --dump the configs are printed to stdout as one YAML stream,
one document per node. With --dump each node's config is written to
<dir>/<hostname>.yaml, which is the form to diff between two versions
of a deployment or of the templates.

Examples:
  # Print every node's config
  platformctl bootstrap resolve --config bootstrap.yaml

  # Print two nodes
  platformctl bootstrap resolve --config bootstrap.yaml --node cp-01 --node gw-01

  # Write every node's config for a diff
  platformctl bootstrap resolve --config bootstrap.yaml --dump /tmp/resolved`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runResolve(configPath, nodes, dumpDir, getFlags(), cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bootstrap YAML configuration (required)")
	cmd.Flags().StringArrayVar(&nodes, "node", nil, "resolve only this hostname (repeatable)")
	cmd.Flags().StringVar(&dumpDir, "dump", "", "write each node's config to <dir>/<hostname>.yaml instead of stdout")

	return cmd
}

// runResolve loads and checks the bootstrap config, resolves the requested
// nodes' configs and prints them to out or writes them under dumpDir.
func runResolve(configPath string, nodes []string, dumpDir string, commonFlags *cli.CommonFlags, out io.Writer) error {
	if configPath == "" {
		return ErrPXEConfigRequired{}
	}
	config, err := bootstrap.LoadBootstrapConfig(configPath)
	if err != nil {
		return ErrPXEConfigLoadFailed{Path: configPath, Cause: err}
	}
	if err := config.ValidateDefinition(); err != nil {
		return ErrPXEConfigValidationFailed{Cause: err}
	}

	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr).Slog()

	// No deployer, and the BMC factory is never used: resolving reads
	// templates and overrides only.
	orch, err := bootstrap.NewOrchestrator(bootstrap.OrchestratorParams{
		Config:     config,
		ConfigPath: configPath,
		BMCFactory: bmc.NewDefaultClientFactory(logger),
		Logger:     logger,
	})
	if err != nil {
		return ErrOrchestratorCreationFailed{Cause: err}
	}

	resolved, err := orch.ResolveNodeConfigs(nodes...)
	if err != nil {
		return err
	}

	if dumpDir == "" {
		for i, r := range resolved {
			if i > 0 {
				fmt.Fprintln(out, "---")
			}
			fmt.Fprintf(out, "# %s (%s)\n%s", r.Hostname, r.Role, r.Config)
		}
		return nil
	}

	if err := os.MkdirAll(dumpDir, 0o700); err != nil {
		return ErrResolveDumpFailed{Path: dumpDir, Cause: err}
	}
	for _, r := range resolved {
		path := filepath.Join(dumpDir, r.Hostname+".yaml")
		// The configs carry the deployment's credential references.
		if err := os.WriteFile(path, []byte(r.Config), 0o600); err != nil {
			return ErrResolveDumpFailed{Path: path, Cause: err}
		}
		fmt.Fprintln(out, path)
	}
	return nil
}
