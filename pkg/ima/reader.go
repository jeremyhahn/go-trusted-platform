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

// Package ima provides functionality for reading and verifying
// Linux Integrity Measurement Architecture (IMA) event logs.
package ima

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Reader reads and parses IMA event logs
type Reader struct {
	securityFSPath string
}

// ReaderOption configures a Reader
type ReaderOption func(*Reader)

// WithSecurityFSPath sets a custom securityfs mount path
func WithSecurityFSPath(path string) ReaderOption {
	return func(r *Reader) {
		r.securityFSPath = path
	}
}

// NewReader creates a new IMA event log reader
func NewReader(opts ...ReaderOption) *Reader {
	r := &Reader{
		securityFSPath: DefaultSecurityFSPath,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// IsAvailable checks if IMA is available on the system
func (r *Reader) IsAvailable() bool {
	imaPath := r.securityFSPath + "/ima"
	_, err := os.Stat(imaPath)
	return err == nil
}

// IsSecurityFSMounted checks if securityfs is mounted
func (r *Reader) IsSecurityFSMounted() bool {
	_, err := os.Stat(r.securityFSPath)
	return err == nil
}

// GetStatus retrieves the current IMA status
func (r *Reader) GetStatus() (*Status, error) {
	if !r.IsSecurityFSMounted() {
		return nil, ErrSecurityFSNotMounted
	}

	if !r.IsAvailable() {
		return &Status{
			Available: false,
			Enabled:   false,
		}, nil
	}

	status := &Status{
		Available: true,
		Enabled:   true,
	}

	// Read measurement count
	log, err := r.ReadEventLog()
	if err == nil {
		status.MeasurementCount = log.TotalCount
		status.ViolationCount = log.ViolationCount
	}

	// Check if policy is loaded
	policyPath := r.securityFSPath + "/ima/policy"
	if _, err := os.Stat(policyPath); err == nil {
		status.PolicyLoaded = true
	}

	// Try to determine hash algorithm from first event
	if log != nil && len(log.Events) > 0 {
		status.HashAlgorithm = log.Events[0].HashAlgorithm
	}

	return status, nil
}

// ReadEventLog reads and parses the IMA ASCII runtime measurements
func (r *Reader) ReadEventLog() (*EventLog, error) {
	asciiPath := r.securityFSPath + "/ima/ascii_runtime_measurements"
	return r.ReadEventLogFromFile(asciiPath)
}

// ReadEventLogFromFile reads and parses an IMA event log from a specific file
func (r *Reader) ReadEventLogFromFile(path string) (eventLog *EventLog, retErr error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotAvailable
		}
		return nil, fmt.Errorf("failed to open IMA event log: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("failed to close IMA event log: %w", cerr)
		}
	}()

	return r.ParseEventLog(file)
}

// ParseEventLog parses IMA events from a reader
func (r *Reader) ParseEventLog(reader io.Reader) (*EventLog, error) {
	log := &EventLog{
		Events:   make([]*Event, 0),
		ParsedAt: time.Now(),
	}

	uniqueFiles := make(map[string]struct{})
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		event, err := r.ParseEvent(line)
		if err != nil {
			log.ParseErrors++
			continue
		}

		log.Events = append(log.Events, event)
		log.TotalCount++

		if event.FilePath != "" {
			uniqueFiles[event.FilePath] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading IMA event log: %w", err)
	}

	log.UniqueFiles = len(uniqueFiles)

	return log, nil
}

// ParseEvent parses a single IMA event line
// Format: PCR TEMPLATE_HASH TEMPLATE_NAME FILEDATA_HASH FILENAME_HINT
// Example (ima-ng): 10 abc123... ima-ng sha256:def456... /usr/bin/bash
// Example (ima-sig): 10 abc123... ima-sig sha256:def456... /usr/bin/bash 0302...
func (r *Reader) ParseEvent(line string) (*Event, error) {
	event := &Event{
		RawLine: line,
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return nil, ErrInvalidEventFormat
	}

	// Parse PCR index
	pcr, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid PCR index: %s", ErrInvalidEventFormat, fields[0])
	}
	event.PCR = pcr

	// Parse template hash
	templateHash, err := hex.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid template hash: %s", ErrInvalidEventFormat, fields[1])
	}
	event.TemplateHash = templateHash

	// Template name
	event.TemplateName = fields[2]

	// Parse file hash (format: algorithm:hash or just hash)
	fileHashField := fields[3]
	if strings.Contains(fileHashField, ":") {
		parts := strings.SplitN(fileHashField, ":", 2)
		event.HashAlgorithm = parts[0]
		fileHash, err := hex.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%w: invalid file hash: %s", ErrInvalidEventFormat, parts[1])
		}
		event.FileHash = fileHash
	} else {
		// Legacy format without algorithm prefix (sha1)
		event.HashAlgorithm = "sha1"
		fileHash, err := hex.DecodeString(fileHashField)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid file hash: %s", ErrInvalidEventFormat, fileHashField)
		}
		event.FileHash = fileHash
	}

	// Parse file path (field 4)
	if len(fields) > 4 {
		event.FilePath = fields[4]
	}

	// Parse signature if present (ima-sig template, field 5+)
	if event.TemplateName == "ima-sig" && len(fields) > 5 {
		sig, err := hex.DecodeString(fields[5])
		if err == nil {
			event.Signature = sig
		}
	}

	return event, nil
}

// ReadPolicy reads the currently loaded IMA policy
func (r *Reader) ReadPolicy() (*Policy, error) {
	policyPath := r.securityFSPath + "/ima/policy"
	return r.ReadPolicyFromFile(policyPath)
}

// ReadPolicyFromFile reads an IMA policy from a specific file
func (r *Reader) ReadPolicyFromFile(path string) (policy *Policy, retErr error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotAvailable
		}
		return nil, fmt.Errorf("failed to open IMA policy: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && retErr == nil {
			retErr = fmt.Errorf("failed to close IMA policy: %w", cerr)
		}
	}()

	return r.ParsePolicy(file)
}

// ParsePolicy parses IMA policy rules from a reader
func (r *Reader) ParsePolicy(reader io.Reader) (*Policy, error) {
	policy := &Policy{
		Rules:    make([]*PolicyRule, 0),
		LoadedAt: time.Now(),
	}

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := r.ParsePolicyRule(line)
		if err != nil {
			continue // Skip invalid rules
		}

		policy.Rules = append(policy.Rules, rule)
		policy.RuleCount++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading IMA policy: %w", err)
	}

	return policy, nil
}

// ParsePolicyRule parses a single IMA policy rule
// Format: action condition [func=X] [mask=X] [pcr=X] [template=X] ...
// Example: measure func=FILE_CHECK mask=MAY_READ pcr=10 template=ima-ng
func (r *Reader) ParsePolicyRule(line string) (*PolicyRule, error) {
	rule := &PolicyRule{
		RawRule: line,
	}

	fields := strings.Fields(line)
	if len(fields) < 1 {
		return nil, ErrInvalidEventFormat
	}

	// First field is the action
	rule.Action = fields[0]

	// Parse key=value pairs
	for _, field := range fields[1:] {
		if !strings.Contains(field, "=") {
			// This is a condition without =
			if rule.Condition == "" {
				rule.Condition = field
			} else {
				rule.Condition += " " + field
			}
			continue
		}

		parts := strings.SplitN(field, "=", 2)
		key := strings.ToLower(parts[0])
		value := parts[1]

		switch key {
		case "func":
			rule.Func = value
		case "mask":
			rule.Mask = value
		case "pcr":
			pcr, err := strconv.Atoi(value)
			if err == nil {
				rule.PCR = pcr
			}
		case "template":
			rule.Template = value
		default:
			// Add to condition for unknown keys
			if rule.Condition == "" {
				rule.Condition = field
			} else {
				rule.Condition += " " + field
			}
		}
	}

	return rule, nil
}

// GetStatistics calculates statistics from an event log
func (r *Reader) GetStatistics(log *EventLog) *Statistics {
	if log == nil {
		return nil
	}

	stats := &Statistics{
		TotalEvents:     log.TotalCount,
		UniqueFiles:     log.UniqueFiles,
		ViolationCount:  log.ViolationCount,
		FilesByHashAlg:  make(map[string]int),
		FilesByTemplate: make(map[string]int),
		FilesByAction:   make(map[string]int),
		CollectedAt:     time.Now(),
	}

	pathCounts := make(map[string]int)

	for _, event := range log.Events {
		// Count by hash algorithm
		if event.HashAlgorithm != "" {
			stats.FilesByHashAlg[event.HashAlgorithm]++
		}

		// Count by template
		if event.TemplateName != "" {
			stats.FilesByTemplate[event.TemplateName]++
		}

		// Count by event type/action
		if event.EventType != "" {
			stats.FilesByAction[event.EventType]++
		}

		// Track path counts for top paths
		if event.FilePath != "" {
			pathCounts[event.FilePath]++
		}
	}

	// Find top 10 paths
	stats.TopPaths = r.getTopPaths(pathCounts, 10)

	return stats
}

// getTopPaths returns the top N most frequently measured paths
func (r *Reader) getTopPaths(pathCounts map[string]int, n int) []string {
	type pathCount struct {
		path  string
		count int
	}

	// Convert to slice for sorting
	paths := make([]pathCount, 0, len(pathCounts))
	for path, count := range pathCounts {
		paths = append(paths, pathCount{path: path, count: count})
	}

	// Simple bubble sort for small n (good enough for top 10)
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			if paths[j].count > paths[i].count {
				paths[i], paths[j] = paths[j], paths[i]
			}
		}
	}

	// Take top n
	result := make([]string, 0, n)
	for i := 0; i < n && i < len(paths); i++ {
		result = append(result, paths[i].path)
	}

	return result
}

// ReadViolations reads the IMA violations count
func (r *Reader) ReadViolations() (int, error) {
	violationsPath := r.securityFSPath + "/ima/violations"
	data, err := os.ReadFile(violationsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // No violations file means no violations
		}
		return 0, fmt.Errorf("failed to read violations: %w", err)
	}

	count, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid violations count: %w", err)
	}

	return count, nil
}

// FindEventByPath finds all events for a specific file path
func (r *Reader) FindEventByPath(log *EventLog, path string) []*Event {
	if log == nil {
		return nil
	}

	var events []*Event
	for _, event := range log.Events {
		if event.FilePath == path {
			events = append(events, event)
		}
	}
	return events
}

// FindEventByHash finds events with a specific file hash
func (r *Reader) FindEventByHash(log *EventLog, hash []byte) []*Event {
	if log == nil || len(hash) == 0 {
		return nil
	}

	var events []*Event
	for _, event := range log.Events {
		if len(event.FileHash) == len(hash) {
			match := true
			for i := range hash {
				if event.FileHash[i] != hash[i] {
					match = false
					break
				}
			}
			if match {
				events = append(events, event)
			}
		}
	}
	return events
}
