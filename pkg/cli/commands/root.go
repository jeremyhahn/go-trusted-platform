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

package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/acme"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/barrier"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/db"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/fido2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/firstboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/install"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/profile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/provision"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/registry"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/tpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/vtpm"
)

var (
	// Global flags
	configPath       string
	contextName      string
	outputFormat     string
	protocolOverride string
	serverOverride   string
	verbose          bool
	noColor          bool

	// Config
	config *cli.Config
)

// envDefault returns the first non-empty value among the env vars in order,
// falling back to fallback if all are empty.
func envDefault(fallback string, keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return fallback
}

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "platformctl",
	Short: "Command-line interface for Trusted Platform",
	Long: `platformctl is a command-line interface for managing and interacting with
the Trusted Platform. It can connect to platformd via Unix socket (local)
or HTTPS with mTLS (remote).`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		config, err = cli.LoadConfig(configPath)
		if err != nil {
			// Only fail if config was explicitly specified
			if configPath != "" {
				return fmt.Errorf("failed to load config: %w", err)
			}
			// Use default config if no config file specified
			config = cli.DefaultConfig()
		}

		// Validate output format
		format := cli.OutputFormat(outputFormat)
		if !format.IsValid() {
			return cli.ErrInvalidOutputFormat{Format: outputFormat}
		}

		// Validate protocol override early (empty = use context default)
		if protocolOverride != "" {
			if _, ok := cli.ValidProtocols[protocolOverride]; !ok {
				return fmt.Errorf("invalid --protocol %q: must be one of unix, grpc, rest, quic, mcp, embedded", protocolOverride)
			}
		}

		return nil
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags. Defaults are pulled from env vars (kubectl-style precedence:
	// flag > env > config file > built-in default).
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c",
		envDefault("", "PLATFORMCTL_CONFIG"),
		fmt.Sprintf("config file (env PLATFORMCTL_CONFIG, default: %s)", cli.DefaultConfigPath()))
	rootCmd.PersistentFlags().StringVar(&contextName, "context",
		envDefault("", "PLATFORMCTL_CONTEXT"),
		"context to use, overrides current-context (env PLATFORMCTL_CONTEXT)")
	rootCmd.PersistentFlags().StringVar(&protocolOverride, "protocol",
		envDefault("", "PLATFORMCTL_PROTOCOL"),
		"transport protocol override: unix, grpc, rest, quic, mcp, embedded (env PLATFORMCTL_PROTOCOL)")
	rootCmd.PersistentFlags().StringVar(&serverOverride, "server",
		envDefault("", "PLATFORMCTL_SERVER"),
		"server address override, implies remote context (env PLATFORMCTL_SERVER)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o",
		envDefault("table", "PLATFORMCTL_OUTPUT"),
		"output format: table, json, yaml (env PLATFORMCTL_OUTPUT)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"verbose output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false,
		"disable colored output (env NO_COLOR)")
	if os.Getenv("NO_COLOR") != "" {
		noColor = true
	}

	// Add subcommands
	rootCmd.AddCommand(NewStatusCommand(getCommonFlags))
	rootCmd.AddCommand(NewHealthCommand(getCommonFlags))
	rootCmd.AddCommand(NewVersionCommand(getCommonFlags))
	rootCmd.AddCommand(NewServiceCommand(getCommonFlags))
	rootCmd.AddCommand(NewConfigCommand(getCommonFlags))
	rootCmd.AddCommand(NewContextCommand(getConfig))
	rootCmd.AddCommand(NewCompletionCommand())
	rootCmd.AddCommand(NewWipeCommand(getCommonFlags))
	rootCmd.AddCommand(acme.NewCommand(getCommonFlags))
	rootCmd.AddCommand(authenticode.NewCommand(getCommonFlags))
	rootCmd.AddCommand(barrier.NewCommand(getCommonFlags))
	rootCmd.AddCommand(bmc.NewCommand(getCommonFlags))
	rootCmd.AddCommand(bootstrap.NewCommand(getCommonFlags))
	rootCmd.AddCommand(ca.NewCommand(getCommonFlags))
	rootCmd.AddCommand(compute.NewCommand(getCommonFlags))
	rootCmd.AddCommand(container.NewCommand(getCommonFlags))
	rootCmd.AddCommand(db.NewCommand(getCommonFlags))
	rootCmd.AddCommand(device.NewCommand(getCommonFlags))
	rootCmd.AddCommand(fido2.NewCommand(getCommonFlags))
	rootCmd.AddCommand(firstboot.NewCommand(getCommonFlags))
	rootCmd.AddCommand(iam.NewCommand(getCommonFlags))
	rootCmd.AddCommand(install.NewCommand(getCommonFlags))
	rootCmd.AddCommand(iso.NewCommand(getCommonFlags))
	rootCmd.AddCommand(kms.NewCommand(getCommonFlags))
	rootCmd.AddCommand(profile.NewCommand(getCommonFlags))
	rootCmd.AddCommand(provision.NewCommand(getCommonFlags))
	rootCmd.AddCommand(registry.NewCommand(getCommonFlags))
	rootCmd.AddCommand(sdn.NewCommand(getCommonFlags))
	rootCmd.AddCommand(tenant.NewCommand(getCommonFlags))
	rootCmd.AddCommand(tpm.NewCommand(getCommonFlags))
	rootCmd.AddCommand(vtpm.NewCommand(getCommonFlags))

	// Set version
	rootCmd.Version = app.Version
}

// getCommonFlags returns a function that creates CommonFlags from global state
func getCommonFlags() *cli.CommonFlags {
	return &cli.CommonFlags{
		ConfigPath:   configPath,
		ContextName:  contextName,
		OutputFormat: cli.OutputFormat(outputFormat),
		Verbose:      verbose,
		NoColor:      noColor,
		GetConfig:    getConfig,
		GetContext:   getContext,
	}
}

// getConfig returns the current configuration
func getConfig() (*cli.Config, error) {
	if config == nil {
		var err error
		config, err = cli.LoadConfig(configPath)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}

// getContext returns the active context, applying --protocol / --server
// overrides from flags or env vars. A --server override without a named
// context synthesizes an ad-hoc remote context (kubectl-style).
func getContext() (*cli.Context, error) {
	var (
		base *cli.Context
		err  error
	)

	switch {
	case contextName != "":
		cfg, cErr := getConfig()
		if cErr != nil {
			return nil, cErr
		}
		base, err = cfg.GetContext(contextName)
	case serverOverride != "" && contextName == "":
		// Ad-hoc remote context from --server flag / PLATFORMCTL_SERVER env
		base = &cli.Context{
			Name:   "override",
			Type:   cli.ContextTypeRemote,
			Remote: &cli.RemoteContext{Server: serverOverride},
		}
	default:
		cfg, cErr := getConfig()
		if cErr != nil {
			return nil, cErr
		}
		if cfg.CurrentContext != "" {
			base, err = cfg.GetCurrentContext()
		} else {
			base, err = cli.AutoDetectContext()
		}
	}
	if err != nil {
		return nil, err
	}

	// Apply overrides on a shallow clone so we never mutate the loaded config.
	resolved := *base
	if base.Local != nil {
		l := *base.Local
		resolved.Local = &l
	}
	if base.Remote != nil {
		r := *base.Remote
		resolved.Remote = &r
	}

	if serverOverride != "" {
		if resolved.Remote == nil {
			resolved.Remote = &cli.RemoteContext{}
		}
		resolved.Remote.Server = serverOverride
		if resolved.Type != cli.ContextTypeRemote {
			resolved.Type = cli.ContextTypeRemote
		}
	}

	if protocolOverride != "" {
		resolved.Protocol = protocolOverride
	}

	return &resolved, nil
}
