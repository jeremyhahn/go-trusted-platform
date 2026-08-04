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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewContextCommand creates the context management command
func NewContextCommand(getConfig func() (*cli.Config, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Manage connection contexts",
		Long:  "Manage connection contexts for local and remote platform connections",
	}

	cmd.AddCommand(newContextListCommand(getConfig))
	cmd.AddCommand(newContextUseCommand(getConfig))
	cmd.AddCommand(newContextCurrentCommand(getConfig))
	cmd.AddCommand(newContextAddCommand(getConfig))
	cmd.AddCommand(newContextDeleteCommand(getConfig))

	return cmd
}

// newContextListCommand creates the context list subcommand
func newContextListCommand(getConfig func() (*cli.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all contexts",
		Long:  "Display a list of all configured connection contexts",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextList(getConfig)
		},
	}
}

// newContextUseCommand creates the context use subcommand
func newContextUseCommand(getConfig func() (*cli.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "use <context-name>",
		Short: "Set the current context",
		Long:  "Set the current connection context to use",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextUse(getConfig, args[0])
		},
	}
}

// newContextCurrentCommand creates the context current subcommand
func newContextCurrentCommand(getConfig func() (*cli.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show current context",
		Long:  "Display the currently active connection context",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextCurrent(getConfig)
		},
	}
}

// newContextAddCommand creates the context add subcommand
func newContextAddCommand(getConfig func() (*cli.Config, error)) *cobra.Command {
	var (
		contextType string
		socketPath  string
		server      string
		caCert      string
		clientCert  string
		clientKey   string
		protocol    string
		token       string
	)

	cmd := &cobra.Command{
		Use:   "add <context-name>",
		Short: "Add a new context",
		Long:  "Add a new connection context (local or remote)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextAdd(getConfig, args[0], contextType, protocol, socketPath,
				server, caCert, clientCert, clientKey, token)
		},
	}

	cmd.Flags().StringVarP(&contextType, "type", "t", "local",
		"context type: local or remote")
	cmd.Flags().StringVar(&socketPath, "socket-path", "/run/platformd.sock",
		"Unix socket path (for local contexts)")
	cmd.Flags().StringVar(&server, "server", "",
		"server address (for remote contexts)")
	cmd.Flags().StringVar(&caCert, "ca-cert", "",
		"CA certificate path")
	cmd.Flags().StringVar(&clientCert, "client-cert", "",
		"client certificate path")
	cmd.Flags().StringVar(&clientKey, "client-key", "",
		"client key path")
	cmd.Flags().StringVar(&protocol, "protocol", "",
		"protocol: unix, grpc, rest, quic, mcp, embedded (default: auto)")
	cmd.Flags().StringVar(&token, "token", "",
		"bearer token for REST/MCP/QUIC authentication")

	return cmd
}

// newContextDeleteCommand creates the context delete subcommand
func newContextDeleteCommand(getConfig func() (*cli.Config, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <context-name>",
		Short: "Delete a context",
		Long:  "Delete a connection context",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runContextDelete(getConfig, args[0])
		},
	}
}

func runContextList(getConfig func() (*cli.Config, error)) error {
	cfg, err := getConfig()
	if err != nil {
		return err
	}

	printer := cli.NewPrinter(cli.OutputFormatTable, false)

	table := cli.NewTableData("Current", "Name", "Type", "Protocol", "Target")
	for _, ctx := range cfg.Contexts {
		current := ""
		if ctx.Name == cfg.CurrentContext {
			current = "*"
		}

		protocol := ctx.ResolveProtocol()

		target := ""
		if ctx.Type == cli.ContextTypeLocal && ctx.Local != nil {
			target = ctx.Local.SocketPath
		} else if ctx.Type == cli.ContextTypeRemote && ctx.Remote != nil {
			target = ctx.Remote.Server
		} else if ctx.Type == cli.ContextTypeEmbedded {
			target = "in-process"
		}

		table.AddRow(current, ctx.Name, string(ctx.Type), protocol, target)
	}

	return printer.Print(*table)
}

func runContextUse(getConfig func() (*cli.Config, error), name string) error {
	cfg, err := getConfig()
	if err != nil {
		return err
	}

	if err := cfg.SetCurrentContext(name); err != nil {
		return err
	}

	if err := cfg.Save(""); err != nil {
		return &WrappedError{Msg: "failed to save config", Err: err}
	}

	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	printer.PrintSuccess(fmt.Sprintf("Switched to context '%s'", name))

	return nil
}

func runContextCurrent(getConfig func() (*cli.Config, error)) error {
	cfg, err := getConfig()
	if err != nil {
		return err
	}

	if cfg.CurrentContext == "" {
		return cli.ErrNoContextSet{}
	}

	ctx, err := cfg.GetCurrentContext()
	if err != nil {
		return err
	}

	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	printer.PrintKeyValue("Name", ctx.Name)
	printer.PrintKeyValue("Type", string(ctx.Type))
	printer.PrintKeyValue("Protocol", ctx.ResolveProtocol())

	if ctx.Type == cli.ContextTypeLocal && ctx.Local != nil {
		printer.PrintKeyValue("Socket Path", ctx.Local.SocketPath)
	} else if ctx.Type == cli.ContextTypeRemote && ctx.Remote != nil {
		printer.PrintKeyValue("Server", ctx.Remote.Server)
		if ctx.Remote.CACert != "" {
			printer.PrintKeyValue("CA Certificate", ctx.Remote.CACert)
		}
		if ctx.Remote.ClientCert != "" {
			printer.PrintKeyValue("Client Certificate", ctx.Remote.ClientCert)
		}
		if ctx.Remote.Token != "" {
			printer.PrintKeyValue("Token", "***")
		}
	} else if ctx.Type == cli.ContextTypeEmbedded {
		printer.PrintKeyValue("Target", "in-process")
	}

	return nil
}

func runContextAdd(getConfig func() (*cli.Config, error), name, contextType, protocol,
	socketPath, server, caCert, clientCert, clientKey, token string) error {

	cfg, err := getConfig()
	if err != nil {
		return err
	}

	ctx := &cli.Context{
		Name:     name,
		Protocol: protocol,
	}

	// Validate protocol if provided
	if protocol != "" {
		if _, ok := cli.ValidProtocols[protocol]; !ok {
			return &MessageError{Msg: fmt.Sprintf("invalid protocol: %s (must be one of: unix, grpc, rest, quic, mcp, embedded)", protocol)}
		}
	}

	switch contextType {
	case "local":
		ctx.Type = cli.ContextTypeLocal
		ctx.Local = &cli.LocalContext{
			SocketPath: socketPath,
		}
	case "remote":
		if server == "" {
			return &MessageError{Msg: "--server is required for remote contexts"}
		}
		ctx.Type = cli.ContextTypeRemote
		ctx.Remote = &cli.RemoteContext{
			Server:     server,
			Protocol:   protocol,
			CACert:     caCert,
			ClientCert: clientCert,
			ClientKey:  clientKey,
			Token:      token,
		}
	case "embedded":
		ctx.Type = cli.ContextTypeEmbedded
	default:
		return &MessageError{Msg: fmt.Sprintf("invalid context type: %s (must be 'local', 'remote', or 'embedded')", contextType)}
	}

	cfg.AddContext(ctx)

	if err := cfg.Save(""); err != nil {
		return &WrappedError{Msg: "failed to save config", Err: err}
	}

	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	printer.PrintSuccess(fmt.Sprintf("Context '%s' added", name))

	return nil
}

func runContextDelete(getConfig func() (*cli.Config, error), name string) error {
	cfg, err := getConfig()
	if err != nil {
		return err
	}

	if err := cfg.RemoveContext(name); err != nil {
		return err
	}

	if err := cfg.Save(""); err != nil {
		return &WrappedError{Msg: "failed to save config", Err: err}
	}

	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	printer.PrintSuccess(fmt.Sprintf("Context '%s' deleted", name))

	return nil
}
