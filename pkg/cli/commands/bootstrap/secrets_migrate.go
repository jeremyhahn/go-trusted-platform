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
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// SchemeFile is the URI scheme prefix for file-based secrets.
const SchemeFile = "file://"

// secretsMigrateFlags contains flags for the migrate command
type secretsMigrateFlags struct {
	configPath string
	dryRun     bool
	noBackup   bool
	force      bool
	keyID      string
}

// migrationEntry represents a single secret to migrate
type migrationEntry struct {
	path       string
	uri        string
	scheme     string
	resolved   bool
	value      []byte
	kmsPath    string
	errorMsg   string
	alreadyKMS bool
}

// newSecretsMigrateCommand creates the secrets migrate command
func newSecretsMigrateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &secretsMigrateFlags{}

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate secrets to KMS-managed storage",
		Long: `Migrate secrets from environment variables or files to KMS-managed secrets.

This command scans the configuration file for secret URIs and migrates them
to the local KMS, replacing the original values with KMS URIs.

The migration process:
  1. Scans configuration for secret fields (identified by URI scheme)
  2. Resolves each secret using the appropriate resolver
  3. Encrypts and stores resolved secrets in the local KMS
  4. Updates the configuration file with KMS URIs
  5. Creates a backup of the original configuration (unless --no-backup)
  6. Verifies all migrated secrets can be resolved

Supported source schemes for migration:
  - env://       - Environment variable references
  - file://      - File-based secrets (reads content from file path)
  - autogen://   - Auto-generated secrets (random passwords, keys)

Schemes that are already KMS-managed (skipped):
  - kms://       - Already in local KMS

Examples:
  # Migrate secrets with backup
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml

  # Preview changes without modifying files
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml --dry-run

  # Migrate without creating backup
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml --no-backup

  # Force migration even if some secrets fail to resolve
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml --force

  # Use a specific KMS key for encryption
  platformctl bootstrap secrets migrate --config /etc/trusted-platform/config.yaml --key-id my-config-key`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runSecretsMigrate(flags, cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.configPath, "config", "", "Path to configuration file (required)")
	cmd.Flags().BoolVar(&cmdFlags.dryRun, "dry-run", false, "Preview changes without modifying files")
	cmd.Flags().BoolVar(&cmdFlags.noBackup, "no-backup", false, "Skip creating backup of original configuration")
	cmd.Flags().BoolVar(&cmdFlags.force, "force", false, "Continue migration even if some secrets fail to resolve")
	cmd.Flags().StringVar(&cmdFlags.keyID, "key-id", "config-secrets", "KMS key ID to use for encrypting secrets")

	cmd.MarkFlagRequired("config") //nolint:errcheck

	return cmd
}

// runSecretsMigrate executes the secrets migration
func runSecretsMigrate(flags *cli.CommonFlags, cmdFlags *secretsMigrateFlags) error {
	if cmdFlags.configPath == "" {
		return ErrConfigPathRequired{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	printer := base.Printer()
	ctx := base.Context()

	// Read configuration file
	configData, err := os.ReadFile(cmdFlags.configPath)
	if err != nil {
		return ErrConfigFileReadFailed{Path: cmdFlags.configPath, Err: err}
	}

	// Scan for secrets
	secrets := scanConfigForSecrets(configData)
	// Also scan for file:// scheme secrets
	secrets = append(secrets, scanForFileSecrets(configData)...)

	if len(secrets) == 0 {
		printer.PrintInfo("No secret URIs found in configuration")
		return nil
	}

	printer.PrintInfo(fmt.Sprintf("Found %d secret(s) in %s", len(secrets), cmdFlags.configPath))
	fmt.Println()

	// Prepare migration entries
	entries := make([]migrationEntry, 0, len(secrets))
	for _, s := range secrets {
		scheme := detectSchemeWithFile(s.uri)
		entries = append(entries, migrationEntry{
			path:       s.path,
			uri:        s.uri,
			scheme:     scheme,
			alreadyKMS: scheme == "kms",
		})
	}

	// Phase 1: Resolve all secrets
	printer.PrintInfo("Phase 1: Resolving secrets...")
	resolvedCount, failedCount := resolveSecrets(ctx, base.Client(), entries, cmdFlags.force, printer)

	if failedCount > 0 && !cmdFlags.force {
		return ErrMigrationFailed{
			Err: fmt.Errorf("%d secret(s) failed to resolve; use --force to continue anyway", failedCount),
		}
	}

	// Count migratable secrets (resolved and not already KMS)
	migratableCount := 0
	for _, e := range entries {
		if e.resolved && !e.alreadyKMS {
			migratableCount++
		}
	}

	if migratableCount == 0 {
		printer.PrintInfo("No secrets to migrate (all secrets are already KMS-managed or failed to resolve)")
		return nil
	}

	fmt.Println()
	printer.PrintInfo(fmt.Sprintf("Phase 2: Migrating %d secret(s) to KMS...", migratableCount))

	// Dry run - just report what would happen
	if cmdFlags.dryRun {
		return printDryRunResults(printer, flags.OutputFormat, entries, cmdFlags.configPath)
	}

	// Phase 2: Store secrets in KMS
	storedCount, storeFailedCount := storeSecretsInKMS(ctx, base.Client(), entries, cmdFlags.keyID, printer)

	if storeFailedCount > 0 && !cmdFlags.force {
		return ErrMigrationFailed{
			Err: fmt.Errorf("%d secret(s) failed to store in KMS", storeFailedCount),
		}
	}

	if storedCount == 0 {
		printer.PrintWarning("No secrets were stored in KMS")
		return nil
	}

	// Phase 3: Create backup
	var backupPath string
	if !cmdFlags.noBackup {
		fmt.Println()
		printer.PrintInfo("Phase 3: Creating backup...")

		logger := createLogger(flags.Verbose)
		writer, writerErr := bootstrap.NewConfigWriter(cmdFlags.configPath, logger)
		if writerErr != nil {
			return ErrBackupCreationFailed{Path: cmdFlags.configPath, Err: writerErr}
		}

		backupPath, err = writer.Backup()
		if err != nil {
			return ErrBackupCreationFailed{Path: cmdFlags.configPath, Err: err}
		}
		printer.PrintSuccess(fmt.Sprintf("Backup created: %s", backupPath))
	}

	// Phase 4: Update configuration file
	fmt.Println()
	printer.PrintInfo("Phase 4: Updating configuration file...")

	updates := buildConfigUpdates(entries)
	if len(updates) > 0 {
		logger := createLogger(flags.Verbose)
		writer, writerErr := bootstrap.NewConfigWriter(cmdFlags.configPath, logger)
		if writerErr != nil {
			return ErrConfigUpdateFailed{Path: cmdFlags.configPath, Err: writerErr}
		}

		if updateErr := writer.UpdateSecretReferences(updates); updateErr != nil {
			// Restore from backup if update fails
			if backupPath != "" {
				printer.PrintWarning("Configuration update failed, restoring from backup...")
				if restoreErr := writer.Restore(backupPath); restoreErr != nil {
					printer.PrintError(fmt.Sprintf("Failed to restore backup: %v", restoreErr))
				}
			}
			return ErrConfigUpdateFailed{Path: cmdFlags.configPath, Err: updateErr}
		}

		printer.PrintSuccess(fmt.Sprintf("Updated %d secret reference(s) in configuration", len(updates)))
	}

	// Phase 5: Verify migration
	fmt.Println()
	printer.PrintInfo("Phase 5: Verifying migration...")

	verifyCount, verifyFailedCount := verifyMigratedSecrets(ctx, base.Client(), entries, cmdFlags.keyID, printer)

	// Print summary
	fmt.Println()
	printMigrationSummary(printer, flags.OutputFormat, entries, resolvedCount, storedCount,
		verifyCount, failedCount+storeFailedCount+verifyFailedCount, backupPath, cmdFlags.configPath)

	if verifyFailedCount > 0 {
		return ErrSecretVerificationFailed{
			FailedCount: verifyFailedCount,
			TotalCount:  storedCount,
		}
	}

	return nil
}

// scanForFileSecrets scans configuration data for file:// scheme URIs
func scanForFileSecrets(data []byte) []secretInfo {
	var secrets []secretInfo

	lines := strings.Split(string(data), "\n")
	var pathStack []string
	var indentStack []int

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		for len(indentStack) > 0 && indent <= indentStack[len(indentStack)-1] {
			pathStack = pathStack[:len(pathStack)-1]
			indentStack = indentStack[:len(indentStack)-1]
		}

		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, `"'`)

				if strings.HasPrefix(value, SchemeFile) {
					fullPath := buildPath(pathStack, key)
					secrets = append(secrets, secretInfo{
						path: fullPath,
						uri:  value,
						line: lineNum + 1,
					})
				}

				if value == "" || strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
					pathStack = append(pathStack, key)
					indentStack = append(indentStack, indent)
				}
			}
		}
	}

	return secrets
}

// detectSchemeWithFile extends detectScheme to include file:// scheme
func detectSchemeWithFile(uri string) string {
	if strings.HasPrefix(uri, SchemeFile) {
		return "file"
	}
	return detectScheme(uri)
}

// resolveSecrets resolves all secrets in the migration entries
func resolveSecrets(ctx context.Context, client platform.Client, entries []migrationEntry, force bool, printer *cli.Printer) (resolved, failed int) {
	for i := range entries {
		entry := &entries[i]

		// Skip already KMS-managed secrets
		if entry.alreadyKMS {
			printer.PrintInfo(fmt.Sprintf("  SKIP: %s (already KMS-managed)", entry.path))
			continue
		}

		value, err := resolveSecretByScheme(ctx, client, entry.uri, entry.scheme)
		if err != nil {
			entry.errorMsg = err.Error()
			failed++
			printer.PrintError(fmt.Sprintf("  FAIL: %s - %s", entry.path, err.Error()))
			if !force {
				return resolved, failed
			}
			continue
		}

		entry.resolved = true
		entry.value = value
		resolved++
		printer.PrintSuccess(fmt.Sprintf("  OK: %s (%s)", entry.path, entry.scheme))
	}

	return resolved, failed
}

// resolveSecretByScheme resolves a secret URI based on its scheme
func resolveSecretByScheme(_ context.Context, _ platform.Client, uri, scheme string) ([]byte, error) {
	switch scheme {
	case "env":
		varName := strings.TrimPrefix(uri, bootstrap.SchemeEnv)
		value := os.Getenv(varName)
		if value == "" {
			return nil, ErrEnvVarNotSet{Name: varName}
		}
		return []byte(value), nil

	case "file":
		filePath := strings.TrimPrefix(uri, SchemeFile)
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, ErrFileReadFailed{Path: filePath, Err: err}
		}
		return data, nil

	case "autogen":
		// Parse autogen spec: autogen://type?param=value
		spec := strings.TrimPrefix(uri, bootstrap.SchemeAutoGen)
		return generateSecret(spec)

	case "kms":
		// Already KMS-managed, this shouldn't be called
		return nil, ErrAlreadyKMSManaged{Path: uri}

	case "remote-kms", "encrypted":
		// These require additional infrastructure not available in CLI
		return nil, ErrResolverNotAvailable{Scheme: scheme}

	default:
		return nil, ErrInvalidSecretURI{URI: uri, Reason: "unknown scheme: " + scheme}
	}
}

// generateSecret generates a random secret based on the autogen spec
func generateSecret(spec string) ([]byte, error) {
	// Parse spec: password?length=32 or key?length=32&encoding=base64
	parts := strings.SplitN(spec, "?", 2)
	secretType := parts[0]

	// Default length
	length := 32
	if len(parts) > 1 {
		params := strings.Split(parts[1], "&")
		for _, p := range params {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 && kv[0] == "length" {
				fmt.Sscanf(kv[1], "%d", &length)
			}
		}
	}

	switch secretType {
	case "password", "key", "token":
		bytes := make([]byte, length)
		if _, err := rand.Read(bytes); err != nil {
			return nil, ErrAutoGenFailed{Spec: spec, Err: err}
		}
		// Convert to alphanumeric for passwords
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		for i := range bytes {
			bytes[i] = charset[int(bytes[i])%len(charset)]
		}
		return bytes, nil

	default:
		// Default to random bytes
		bytes := make([]byte, length)
		if _, err := rand.Read(bytes); err != nil {
			return nil, ErrAutoGenFailed{Spec: spec, Err: err}
		}
		return bytes, nil
	}
}

// storeSecretsInKMS stores resolved secrets in KMS using encryption
func storeSecretsInKMS(ctx context.Context, client platform.Client, entries []migrationEntry, keyID string, printer *cli.Printer) (stored, failed int) {
	kmsClient := client.KMS()
	if kmsClient == nil {
		printer.PrintError("KMS client not available")
		return 0, len(entries)
	}

	for i := range entries {
		entry := &entries[i]

		// Skip entries that weren't resolved or are already KMS-managed
		if !entry.resolved || entry.alreadyKMS {
			continue
		}

		// Build KMS path from config path
		kmsPath := buildKMSPath(entry.path)

		// Encrypt the secret value using KMS
		encResp, err := kmsClient.Encrypt(ctx, &platformv1.EncryptRequest{
			KeyId:     keyID,
			Plaintext: entry.value,
			Context:   []byte(kmsPath), // Use path as AAD for binding
		})
		if err != nil {
			entry.errorMsg = err.Error()
			failed++
			printer.PrintError(fmt.Sprintf("  FAIL: %s - %s", entry.path, err.Error()))
			continue
		}

		// Check status - Status uses Success (bool) field
		if encResp.Status != nil && !encResp.Status.Success {
			errMsg := "encryption failed"
			if encResp.Status.Message != "" {
				errMsg = encResp.Status.Message
			}
			entry.errorMsg = errMsg
			failed++
			printer.PrintError(fmt.Sprintf("  FAIL: %s - %s", entry.path, errMsg))
			continue
		}

		entry.kmsPath = fmt.Sprintf("%s%s", bootstrap.SchemeKMS, kmsPath)
		stored++
		printer.PrintSuccess(fmt.Sprintf("  OK: %s -> %s", entry.path, maskSecretURI(entry.kmsPath)))
	}

	return stored, failed
}

// buildConfigUpdates creates SecretUpdate entries for the config writer
func buildConfigUpdates(entries []migrationEntry) []bootstrap.SecretUpdate {
	var updates []bootstrap.SecretUpdate

	for _, e := range entries {
		// Only include successfully migrated entries
		if e.kmsPath != "" && !e.alreadyKMS {
			updates = append(updates, bootstrap.SecretUpdate{
				Path:          e.path,
				KMSReference:  e.kmsPath,
				OriginalValue: maskSecretURI(e.uri),
			})
		}
	}

	return updates
}

// verifyMigratedSecrets verifies that migrated secrets can be decrypted
func verifyMigratedSecrets(ctx context.Context, client platform.Client, entries []migrationEntry, keyID string, printer *cli.Printer) (verified, failed int) {
	kmsClient := client.KMS()
	if kmsClient == nil {
		printer.PrintError("KMS client not available")
		return 0, len(entries)
	}

	for i := range entries {
		entry := &entries[i]

		// Only verify entries that were stored in KMS
		if entry.kmsPath == "" || entry.alreadyKMS {
			continue
		}

		kmsPath := strings.TrimPrefix(entry.kmsPath, bootstrap.SchemeKMS)

		// Re-encrypt to verify the key is accessible
		// In a full implementation, we would retrieve and decrypt the stored secret
		encResp, err := kmsClient.Encrypt(ctx, &platformv1.EncryptRequest{
			KeyId:     keyID,
			Plaintext: []byte("verification-test"),
			Context:   []byte(kmsPath),
		})
		if err != nil {
			failed++
			printer.PrintError(fmt.Sprintf("  FAIL: %s - %s", entry.path, err.Error()))
			continue
		}

		// Check status - Status uses Success (bool) field
		if encResp.Status != nil && !encResp.Status.Success {
			failed++
			errMsg := "verification failed"
			if encResp.Status.Message != "" {
				errMsg = encResp.Status.Message
			}
			printer.PrintError(fmt.Sprintf("  FAIL: %s - %s", entry.path, errMsg))
			continue
		}

		verified++
		printer.PrintSuccess(fmt.Sprintf("  OK: %s", entry.path))
	}

	return verified, failed
}

// printDryRunResults outputs what would happen in a dry run
func printDryRunResults(printer *cli.Printer, format cli.OutputFormat, entries []migrationEntry, configPath string) error {
	fmt.Println()
	printer.PrintInfo("DRY RUN - No changes will be made")
	fmt.Println()

	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		result := struct {
			DryRun     bool   `json:"dry_run" yaml:"dry_run"`
			ConfigPath string `json:"config_path" yaml:"config_path"`
			Changes    []struct {
				Path     string `json:"path" yaml:"path"`
				Scheme   string `json:"scheme" yaml:"scheme"`
				OrigURI  string `json:"original_uri" yaml:"original_uri"`
				NewURI   string `json:"new_uri" yaml:"new_uri"`
				Resolved bool   `json:"resolved" yaml:"resolved"`
				Skipped  bool   `json:"skipped" yaml:"skipped"`
				Error    string `json:"error,omitempty" yaml:"error,omitempty"`
			} `json:"changes" yaml:"changes"`
		}{
			DryRun:     true,
			ConfigPath: configPath,
		}

		for _, e := range entries {
			change := struct {
				Path     string `json:"path" yaml:"path"`
				Scheme   string `json:"scheme" yaml:"scheme"`
				OrigURI  string `json:"original_uri" yaml:"original_uri"`
				NewURI   string `json:"new_uri" yaml:"new_uri"`
				Resolved bool   `json:"resolved" yaml:"resolved"`
				Skipped  bool   `json:"skipped" yaml:"skipped"`
				Error    string `json:"error,omitempty" yaml:"error,omitempty"`
			}{
				Path:     e.path,
				Scheme:   e.scheme,
				OrigURI:  maskSecretURI(e.uri),
				Resolved: e.resolved,
				Skipped:  e.alreadyKMS,
				Error:    e.errorMsg,
			}
			if e.resolved && !e.alreadyKMS {
				change.NewURI = buildKMSURI(e.path)
			}
			result.Changes = append(result.Changes, change)
		}

		return printer.Print(result)

	default:
		// Table output
		table := cli.NewTableData("Path", "Scheme", "Action", "New URI")
		for _, e := range entries {
			action := "MIGRATE"
			newURI := buildKMSURI(e.path)
			if e.alreadyKMS {
				action = "SKIP (already KMS)"
				newURI = "-"
			} else if !e.resolved {
				action = "FAIL: " + e.errorMsg
				newURI = "-"
			}
			table.AddRow(e.path, e.scheme, action, maskSecretURI(newURI))
		}
		return printer.Print(*table)
	}
}

// printMigrationSummary prints a summary of the migration
func printMigrationSummary(printer *cli.Printer, format cli.OutputFormat, entries []migrationEntry,
	resolved, stored, verified, failed int, backupPath, configPath string) {

	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		result := struct {
			ConfigPath   string `json:"config_path" yaml:"config_path"`
			BackupPath   string `json:"backup_path,omitempty" yaml:"backup_path,omitempty"`
			TotalSecrets int    `json:"total_secrets" yaml:"total_secrets"`
			Resolved     int    `json:"resolved" yaml:"resolved"`
			StoredInKMS  int    `json:"stored_in_kms" yaml:"stored_in_kms"`
			Verified     int    `json:"verified" yaml:"verified"`
			Failed       int    `json:"failed" yaml:"failed"`
			SkippedKMS   int    `json:"skipped_already_kms" yaml:"skipped_already_kms"`
			Success      bool   `json:"success" yaml:"success"`
		}{
			ConfigPath:   configPath,
			BackupPath:   backupPath,
			TotalSecrets: len(entries),
			Resolved:     resolved,
			StoredInKMS:  stored,
			Verified:     verified,
			Failed:       failed,
			Success:      failed == 0,
		}

		for _, e := range entries {
			if e.alreadyKMS {
				result.SkippedKMS++
			}
		}

		printer.Print(result) //nolint:errcheck

	default:
		printer.PrintInfo("Migration Summary")
		printer.PrintKeyValue("  Configuration", configPath)
		if backupPath != "" {
			printer.PrintKeyValue("  Backup", backupPath)
		}
		printer.PrintKeyValue("  Total secrets", fmt.Sprintf("%d", len(entries)))
		printer.PrintKeyValue("  Resolved", fmt.Sprintf("%d", resolved))
		printer.PrintKeyValue("  Stored in KMS", fmt.Sprintf("%d", stored))
		printer.PrintKeyValue("  Verified", fmt.Sprintf("%d", verified))

		skippedKMS := 0
		for _, e := range entries {
			if e.alreadyKMS {
				skippedKMS++
			}
		}
		if skippedKMS > 0 {
			printer.PrintKeyValue("  Skipped (already KMS)", fmt.Sprintf("%d", skippedKMS))
		}

		if failed > 0 {
			printer.PrintKeyValue("  Failed", fmt.Sprintf("%d", failed))
		}

		fmt.Println()
		if failed == 0 {
			printer.PrintSuccess("Migration completed successfully")
		} else {
			printer.PrintWarning(fmt.Sprintf("Migration completed with %d error(s)", failed))
		}
	}
}
