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

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	dbsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/db"
)

// Dump command flags
type dumpFlags struct {
	output     string
	format     string
	entityType string
	pretty     bool
	configDir  string
}

// NewDumpCommand creates the dump subcommand
func NewDumpCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &dumpFlags{}

	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Export QuicBaaS data to files",
		Long: `Export QuicBaaS data to JSON or YAML files.

This command connects to platformd via Unix socket and exports all data
to files organized by entity type. Each entity is saved as an individual
file named by its ID.

The output directory structure will be:
  <output>/<entity-type>/<id>.<format>

Available entity types:
  Organization, User, Registration, Role, WebAuthn,
  Device, DeviceProfile, Zone

Examples:
  # Dump all data to JSON files
  platformctl db dump --output ./backup

  # Dump with pretty printing
  platformctl db dump --output ./backup --pretty

  # Dump only DNS zones
  platformctl db dump --output ./backup --entity-type Zone

  # Dump to YAML format
  platformctl db dump --output ./backup --format yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runDump(commonFlags, flags)
		},
	}

	cmd.Flags().StringVarP(&flags.output, "output", "o", "./quicbaas-dump",
		"output directory for exported files")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "json",
		"output format: json or yaml")
	cmd.Flags().StringVarP(&flags.entityType, "entity-type", "t", "",
		"filter by entity type (e.g., Zone, User)")
	cmd.Flags().BoolVar(&flags.pretty, "pretty", false,
		"pretty print output with indentation")
	cmd.Flags().StringVar(&flags.configDir, "config-dir", "",
		"platform configuration directory (unused, kept for compatibility)")

	return cmd
}

func runDump(commonFlags *cli.CommonFlags, flags *dumpFlags) error {
	printer := cli.NewPrinter(commonFlags.OutputFormat, commonFlags.NoColor)

	// Validate format
	format := strings.ToLower(flags.format)
	if format != "json" && format != "yaml" {
		return ErrInvalidFormat{Format: flags.format}
	}

	// Create base command to get SDK client
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return &WrappedError{Msg: "failed to connect to platformd", Err: err}
	}
	defer base.Close()

	printer.PrintInfo("Connected to platformd")

	// Verify daemon client is available (requires gRPC connection, not Unix socket)
	if base.Client().Daemon() == nil {
		return ErrGRPCRequired{Operation: "db dump"}
	}

	// Create output directory
	if err := os.MkdirAll(flags.output, 0755); err != nil {
		return ErrOutputDirectoryFailed{Path: flags.output, Err: err}
	}

	sdkClient := dbsvc.NewClientFromGRPC(base.Client().Daemon())

	// Create request context with timeout
	reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Track counts per entity type
	typeCounts := make(map[string]int)
	totalExported := 0

	// Stream dump via SDK client
	dumpErr := sdkClient.DumpEntityTypes(reqCtx, &dbsvc.DumpParams{
		EntityType: flags.entityType,
		Format:     format,
		Pretty:     flags.pretty,
	}, func(entry *dbsvc.DumpEntry) error {
		// Create entity type directory if needed
		entityDir := filepath.Join(flags.output, entry.EntityType)
		if typeCounts[entry.EntityType] == 0 {
			if mkdirErr := os.MkdirAll(entityDir, 0755); mkdirErr != nil {
				return ErrOutputDirectoryFailed{Path: entityDir, Err: mkdirErr}
			}
		}

		// Format the data
		var outputData []byte
		switch format {
		case "json":
			if flags.pretty {
				var parsed interface{}
				if jsonErr := json.Unmarshal(entry.Data, &parsed); jsonErr != nil {
					outputData = entry.Data
				} else {
					outputData, _ = json.MarshalIndent(parsed, "", "  ")
				}
			} else {
				outputData = entry.Data
			}
		case "yaml":
			var parsed interface{}
			if jsonErr := json.Unmarshal(entry.Data, &parsed); jsonErr != nil {
				return ErrDeserializationFailed{EntityType: entry.EntityType, ID: entry.EntityID, Err: jsonErr}
			}
			yamlData, yamlErr := yaml.Marshal(parsed)
			if yamlErr != nil {
				return ErrSerializationFailed{EntityType: entry.EntityType, ID: entry.EntityID, Err: yamlErr}
			}
			outputData = yamlData
		}

		// Write file
		filename := filepath.Join(entityDir, fmt.Sprintf("%d.%s", entry.EntityID, format))
		if writeErr := os.WriteFile(filename, outputData, 0644); writeErr != nil {
			return ErrFileWriteFailed{Path: filename, Err: writeErr}
		}

		typeCounts[entry.EntityType]++
		totalExported++
		return nil
	})
	if dumpErr != nil {
		return dumpErr
	}

	// Print summary
	for entityType, count := range typeCounts {
		if count > 0 {
			printer.PrintInfo(fmt.Sprintf("Exported %d %s entities", count, entityType))
		}
	}

	if totalExported == 0 {
		printer.PrintWarning("No data found to export")
	} else {
		printer.PrintSuccess(fmt.Sprintf("Exported %d total entities to %s", totalExported, flags.output))
	}

	return nil
}

// Error types for the dump command

// ErrInvalidFormat is returned when an invalid output format is specified
type ErrInvalidFormat struct {
	Format string
}

func (e ErrInvalidFormat) Error() string {
	return fmt.Sprintf("invalid format: %s (valid: json, yaml)", e.Format)
}

// ErrConfigLoadFailed is returned when loading platform configuration fails
type ErrConfigLoadFailed struct {
	Err error
}

func (e ErrConfigLoadFailed) Error() string {
	return fmt.Sprintf("failed to load platform configuration: %v", e.Err)
}

// ErrDatabaseConnectionFailed is returned when connecting to the database fails
type ErrDatabaseConnectionFailed struct {
	Err error
}

func (e ErrDatabaseConnectionFailed) Error() string {
	return fmt.Sprintf("failed to connect to database: %v", e.Err)
}

// ErrDatabaseStartFailed is returned when starting the database fails
type ErrDatabaseStartFailed struct {
	Err error
}

func (e ErrDatabaseStartFailed) Error() string {
	return fmt.Sprintf("failed to start database: %v", e.Err)
}

// ErrInvalidFactoryType is returned when the factory type is not QuicBaaS
type ErrInvalidFactoryType struct{}

func (e ErrInvalidFactoryType) Error() string {
	return "expected QuicBaaS factory but got different type"
}

// ErrOutputDirectoryFailed is returned when creating the output directory fails
type ErrOutputDirectoryFailed struct {
	Path string
	Err  error
}

func (e ErrOutputDirectoryFailed) Error() string {
	return fmt.Sprintf("failed to create output directory %s: %v", e.Path, e.Err)
}

// ErrSerializationFailed is returned when serializing entity data fails
type ErrSerializationFailed struct {
	EntityType string
	ID         uint64
	Err        error
}

func (e ErrSerializationFailed) Error() string {
	return fmt.Sprintf("failed to serialize %s entity %d: %v", e.EntityType, e.ID, e.Err)
}

// ErrDeserializationFailed is returned when deserializing entity data fails
type ErrDeserializationFailed struct {
	EntityType string
	ID         uint64
	Err        error
}

func (e ErrDeserializationFailed) Error() string {
	return fmt.Sprintf("failed to deserialize %s entity %d: %v", e.EntityType, e.ID, e.Err)
}

// ErrFileWriteFailed is returned when writing a file fails
type ErrFileWriteFailed struct {
	Path string
	Err  error
}

func (e ErrFileWriteFailed) Error() string {
	return fmt.Sprintf("failed to write file %s: %v", e.Path, e.Err)
}

// ErrGRPCRequired is returned when an operation requires gRPC but only Unix socket is available
type ErrGRPCRequired struct {
	Operation string
}

func (e ErrGRPCRequired) Error() string {
	return fmt.Sprintf("%s requires gRPC connection; Unix socket does not support streaming RPCs. "+
		"Use 'platformctl context add' to configure a remote gRPC context, or ensure daemon gRPC TCP is enabled", e.Operation)
}
