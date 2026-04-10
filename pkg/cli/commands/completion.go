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
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCompletionCommand creates the completion command
func NewCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for platformctl.

To load completions:

Bash:
  $ source <(platformctl completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ platformctl completion bash > /etc/bash_completion.d/platformctl
  # macOS:
  $ platformctl completion bash > $(brew --prefix)/etc/bash_completion.d/platformctl

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. Execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ platformctl completion zsh > "${fpath[1]}/_platformctl"

  # You may need to start a new shell for this to take effect.

Fish:
  $ platformctl completion fish | source

  # To load completions for each session, execute once:
  $ platformctl completion fish > ~/.config/fish/completions/platformctl.fish

PowerShell:
  PS> platformctl completion powershell | Out-String | Invoke-Expression

  # To load completions for each session, execute once:
  PS> platformctl completion powershell > platformctl.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateCompletion(cmd, args[0])
		},
	}

	return cmd
}

// generateCompletion generates the completion script for the specified shell
func generateCompletion(cmd *cobra.Command, shell string) error {
	var err error

	switch shell {
	case "bash":
		err = cmd.Root().GenBashCompletion(os.Stdout)
	case "zsh":
		err = cmd.Root().GenZshCompletion(os.Stdout)
	case "fish":
		err = cmd.Root().GenFishCompletion(os.Stdout, true)
	case "powershell":
		err = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
	default:
		return cli.ErrInvalidShellType{Shell: shell}
	}

	if err != nil {
		return cli.ErrCompletionGenerationFailed{
			Shell: shell,
			Err:   err,
		}
	}

	return nil
}
