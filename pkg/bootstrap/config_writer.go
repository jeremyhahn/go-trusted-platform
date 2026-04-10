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

// Package bootstrap provides components for secure platform initialization
// and configuration management, including secret migration to KMS references.
package bootstrap

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// SecretUpdate represents a single secret reference update to be applied
// to the configuration file.
type SecretUpdate struct {
	// Path is the YAML path to the secret value.
	// Supports dot notation with array indices.
	// Example: "certificate-authority.identity[0].keystores.tpm2.srk-auth"
	Path string

	// KMSReference is the new KMS URI to replace the original value.
	// Example: "kms://config/ca/identity/0/keystores/tpm2/srk-auth"
	KMSReference string

	// OriginalValue is the original secret value for verification and logging.
	OriginalValue string
}

// ConfigWriter handles updating configuration files with KMS references
// after secret migration. It preserves YAML comments and formatting while
// performing atomic writes with backup support.
type ConfigWriter struct {
	path   string
	logger *slog.Logger
}

// NewConfigWriter creates a new ConfigWriter for the specified config file path.
func NewConfigWriter(path string, logger *slog.Logger) (*ConfigWriter, error) {
	if path == "" {
		return nil, ErrEmptyPath{}
	}
	if logger == nil {
		return nil, ErrNilLogger{}
	}

	return &ConfigWriter{
		path:   path,
		logger: logger,
	}, nil
}

// Path returns the configuration file path.
func (w *ConfigWriter) Path() string {
	return w.path
}

// Backup creates a timestamped backup of the configuration file.
// Returns the backup file path on success.
func (w *ConfigWriter) Backup() (string, error) {
	// Verify source file exists
	if _, err := os.Stat(w.path); os.IsNotExist(err) {
		return "", ErrConfigFileNotFound{Path: w.path}
	}

	// Generate backup path with timestamp
	timestamp := time.Now().UTC().Format("20060102-150405")
	dir := filepath.Dir(w.path)
	base := filepath.Base(w.path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	backupPath := filepath.Join(dir, name+"."+timestamp+".backup"+ext)

	w.logger.Debug("creating config backup",
		slog.String("source", w.path),
		slog.String("backup", backupPath))

	// Read source file
	data, err := os.ReadFile(w.path)
	if err != nil {
		return "", ErrBackupFailed{Path: w.path, Err: err}
	}

	// Write backup file
	if err := os.WriteFile(backupPath, data, 0600); err != nil {
		return "", ErrBackupFailed{Path: w.path, Err: err}
	}

	w.logger.Info("config backup created",
		slog.String("backup", backupPath))

	return backupPath, nil
}

// Restore restores the configuration file from a backup.
func (w *ConfigWriter) Restore(backupPath string) error {
	// Verify backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return ErrBackupNotFound{Path: backupPath}
	}

	w.logger.Debug("restoring config from backup",
		slog.String("backup", backupPath),
		slog.String("target", w.path))

	// Read backup file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return ErrRestoreFailed{
			BackupPath: backupPath,
			TargetPath: w.path,
			Err:        err,
		}
	}

	// Write to target using atomic write
	if err := w.atomicWrite(data); err != nil {
		return ErrRestoreFailed{
			BackupPath: backupPath,
			TargetPath: w.path,
			Err:        err,
		}
	}

	w.logger.Info("config restored from backup",
		slog.String("backup", backupPath))

	return nil
}

// UpdateSecretReferences applies the secret updates to the configuration file.
// It reads the YAML file, updates each path with the new KMS reference,
// and writes the result atomically.
func (w *ConfigWriter) UpdateSecretReferences(updates []SecretUpdate) error {
	return w.updateSecretReferencesInternal(updates, false)
}

// DryRun validates the updates and reports what changes would be made
// without actually modifying the file.
func (w *ConfigWriter) DryRun(updates []SecretUpdate) ([]SecretUpdate, error) {
	if len(updates) == 0 {
		return nil, ErrEmptyUpdates{}
	}

	// Verify file exists
	if _, err := os.Stat(w.path); os.IsNotExist(err) {
		return nil, ErrConfigFileNotFound{Path: w.path}
	}

	// Read and parse config
	data, err := os.ReadFile(w.path)
	if err != nil {
		return nil, ErrParseYAML{Path: w.path, Err: err}
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, ErrParseYAML{Path: w.path, Err: err}
	}

	// Validate each path
	validUpdates := make([]SecretUpdate, 0, len(updates))
	for _, update := range updates {
		segments, err := parsePath(update.Path)
		if err != nil {
			w.logger.Warn("invalid path, skipping update",
				slog.String("path", update.Path),
				slog.String("error", err.Error()))
			continue
		}

		// Navigate to verify path exists
		node, err := w.navigateToNode(&root, segments)
		if err != nil {
			w.logger.Warn("path not found, skipping update",
				slog.String("path", update.Path),
				slog.String("error", err.Error()))
			continue
		}

		w.logger.Info("dry-run: would update",
			slog.String("path", update.Path),
			slog.String("current_value", node.Value),
			slog.String("new_value", update.KMSReference))

		validUpdates = append(validUpdates, update)
	}

	return validUpdates, nil
}

// updateSecretReferencesInternal is the internal implementation that handles
// both regular updates and dry-run mode.
func (w *ConfigWriter) updateSecretReferencesInternal(updates []SecretUpdate, dryRun bool) error {
	if len(updates) == 0 {
		return ErrEmptyUpdates{}
	}

	// Verify file exists
	if _, err := os.Stat(w.path); os.IsNotExist(err) {
		return ErrConfigFileNotFound{Path: w.path}
	}

	// Read config file
	data, err := os.ReadFile(w.path)
	if err != nil {
		return ErrParseYAML{Path: w.path, Err: err}
	}

	// Parse YAML preserving comments
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return ErrParseYAML{Path: w.path, Err: err}
	}

	// Apply each update
	appliedCount := 0
	for _, update := range updates {
		if err := w.applyUpdate(&root, update); err != nil {
			w.logger.Warn("failed to apply update",
				slog.String("path", update.Path),
				slog.String("error", err.Error()))
			continue
		}
		appliedCount++

		w.logger.Debug("applied secret update",
			slog.String("path", update.Path),
			slog.String("kms_reference", update.KMSReference))
	}

	if dryRun {
		return ErrDryRunMode{UpdateCount: appliedCount}
	}

	// Marshal back to YAML
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	if err := encoder.Encode(&root); err != nil {
		return ErrWriteFailed{Path: w.path, Err: err}
	}

	if err := encoder.Close(); err != nil {
		return ErrWriteFailed{Path: w.path, Err: err}
	}

	// Write atomically
	if err := w.atomicWrite(buf.Bytes()); err != nil {
		return err
	}

	w.logger.Info("updated secret references",
		slog.Int("count", appliedCount),
		slog.String("config", w.path))

	return nil
}

// applyUpdate applies a single secret update to the YAML node tree.
func (w *ConfigWriter) applyUpdate(root *yaml.Node, update SecretUpdate) error {
	// Parse the path into segments
	segments, err := parsePath(update.Path)
	if err != nil {
		return err
	}

	// Navigate to the target node
	node, err := w.navigateToNode(root, segments)
	if err != nil {
		return err
	}

	// Update the value
	node.Value = update.KMSReference
	node.Tag = "!!str"
	node.Kind = yaml.ScalarNode

	return nil
}

// pathSegment represents a single segment in a YAML path.
type pathSegment struct {
	key   string
	index int
	isArr bool
}

// parsePath parses a YAML path string into segments.
// Supports dot notation with array indices.
// Example: "certificate-authority.identity[0].keystores.tpm2.srk-auth"
func parsePath(path string) ([]pathSegment, error) {
	if path == "" {
		return nil, ErrInvalidYAMLPath{Path: path, Reason: "path cannot be empty"}
	}

	// Regular expression to match path segments with optional array indices
	// Matches: key, key[0], key[123], etc.
	segmentRegex := regexp.MustCompile(`^([a-zA-Z0-9_-]+)(?:\[(\d+)\])?$`)

	parts := strings.Split(path, ".")
	segments := make([]pathSegment, 0, len(parts)*2)

	for _, part := range parts {
		if part == "" {
			return nil, ErrInvalidYAMLPath{Path: path, Reason: "empty segment"}
		}

		matches := segmentRegex.FindStringSubmatch(part)
		if matches == nil {
			return nil, ErrInvalidYAMLPath{Path: path, Reason: "invalid segment: " + part}
		}

		key := matches[1]
		segments = append(segments, pathSegment{key: key})

		// Check for array index
		if matches[2] != "" {
			index, err := strconv.Atoi(matches[2])
			if err != nil {
				return nil, ErrInvalidYAMLPath{Path: path, Reason: "invalid array index: " + matches[2]}
			}
			segments = append(segments, pathSegment{index: index, isArr: true})
		}
	}

	return segments, nil
}

// navigateToNode navigates through the YAML node tree following the path segments
// and returns the target node.
func (w *ConfigWriter) navigateToNode(root *yaml.Node, segments []pathSegment) (*yaml.Node, error) {
	if root == nil {
		return nil, ErrPathNotFound{Path: "root"}
	}

	// Handle document node wrapper
	current := root
	if current.Kind == yaml.DocumentNode && len(current.Content) > 0 {
		current = current.Content[0]
	}

	pathStr := ""
	for _, seg := range segments {
		if seg.isArr {
			// Array index access
			pathStr += "[" + strconv.Itoa(seg.index) + "]"

			if current.Kind != yaml.SequenceNode {
				return nil, ErrUnexpectedNodeType{
					Path:     pathStr,
					Expected: "sequence",
					Got:      nodeKindString(current.Kind),
				}
			}

			if seg.index < 0 || seg.index >= len(current.Content) {
				return nil, ErrIndexOutOfBounds{
					Path:  pathStr,
					Index: seg.index,
					Size:  len(current.Content),
				}
			}

			current = current.Content[seg.index]
		} else {
			// Map key access
			if pathStr != "" {
				pathStr += "."
			}
			pathStr += seg.key

			if current.Kind != yaml.MappingNode {
				return nil, ErrUnexpectedNodeType{
					Path:     pathStr,
					Expected: "mapping",
					Got:      nodeKindString(current.Kind),
				}
			}

			found := false
			for i := 0; i < len(current.Content)-1; i += 2 {
				keyNode := current.Content[i]
				if keyNode.Value == seg.key {
					current = current.Content[i+1]
					found = true
					break
				}
			}

			if !found {
				return nil, ErrPathNotFound{Path: pathStr}
			}
		}
	}

	return current, nil
}

// nodeKindString returns a human-readable string for a YAML node kind.
func nodeKindString(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

// atomicWrite writes data to the config file atomically by writing to a
// temporary file first and then renaming.
func (w *ConfigWriter) atomicWrite(data []byte) error {
	dir := filepath.Dir(w.path)
	base := filepath.Base(w.path)

	// Create temp file in same directory for atomic rename
	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp.*")
	if err != nil {
		return ErrAtomicWriteFailed{
			TempPath:   "",
			TargetPath: w.path,
			Err:        err,
		}
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on error
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	// Write data
	n, err := tmpFile.Write(data)
	if err != nil {
		_ = tmpFile.Close()
		return ErrAtomicWriteFailed{
			TempPath:   tmpPath,
			TargetPath: w.path,
			Err:        err,
		}
	}
	if n != len(data) {
		_ = tmpFile.Close()
		return ErrAtomicWriteFailed{
			TempPath:   tmpPath,
			TargetPath: w.path,
			Err:        io.ErrShortWrite,
		}
	}

	// Sync to disk
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return ErrAtomicWriteFailed{
			TempPath:   tmpPath,
			TargetPath: w.path,
			Err:        err,
		}
	}

	if err := tmpFile.Close(); err != nil {
		return ErrAtomicWriteFailed{
			TempPath:   tmpPath,
			TargetPath: w.path,
			Err:        err,
		}
	}

	// Preserve original file permissions if it exists
	var perm os.FileMode = 0600
	if info, err := os.Stat(w.path); err == nil {
		perm = info.Mode().Perm()
	}

	if err := os.Chmod(tmpPath, perm); err != nil {
		return ErrAtomicWriteFailed{
			TempPath:   tmpPath,
			TargetPath: w.path,
			Err:        err,
		}
	}

	// Atomic rename
	if err := os.Rename(tmpPath, w.path); err != nil {
		return ErrAtomicWriteFailed{
			TempPath:   tmpPath,
			TargetPath: w.path,
			Err:        err,
		}
	}

	// Clear tmpPath so cleanup doesn't try to remove the renamed file
	tmpPath = ""

	return nil
}
