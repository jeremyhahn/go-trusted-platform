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

package opa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
)

const (
	// defaultAllowQuery is the default query for allow decisions.
	defaultAllowQuery = "allow"

	// defaultViolationsQuery is the default query for violations.
	defaultViolationsQuery = "violations"

	// regoFileExtension is the file extension for Rego policies.
	regoFileExtension = ".rego"

	// maxPolicyNameLength is the maximum allowed policy name length.
	maxPolicyNameLength = 256
)

var (
	// policyNameRegex validates policy names.
	policyNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)
)

// OPAEngine implements the PolicyEngine interface using Open Policy Agent.
type OPAEngine struct {
	config      *config.PolicyConfig
	policies    map[string]*PolicyBundle
	compiler    *ast.Compiler
	store       storage.Store
	initialized atomic.Bool
	mu          sync.RWMutex

	// Statistics
	evaluationCount atomic.Int64
	allowedCount    atomic.Int64
	deniedCount     atomic.Int64
	errorCount      atomic.Int64
	totalDuration   atomic.Int64
	lastEvaluation  atomic.Pointer[time.Time]
	initializedAt   time.Time
}

// NewOPAEngine creates a new OPA policy engine instance.
func NewOPAEngine() *OPAEngine {
	return &OPAEngine{
		policies: make(map[string]*PolicyBundle),
		store:    inmem.New(),
	}
}

// Initialize prepares the engine with the given configuration.
func (e *OPAEngine) Initialize(ctx context.Context, cfg *config.PolicyConfig) error {
	if cfg == nil {
		return ErrNilConfig{}
	}

	if e.initialized.Load() {
		return ErrEngineAlreadyInitialized{}
	}

	// Validate policy directory if specified
	if cfg.PolicyDir != "" {
		info, err := os.Stat(cfg.PolicyDir)
		if err != nil {
			if os.IsNotExist(err) {
				return ErrPolicyDirNotFound{Path: cfg.PolicyDir}
			}
			return ErrPolicyLoadFailed{Path: cfg.PolicyDir, Reason: err.Error()}
		}
		if !info.IsDir() {
			return ErrPolicyDirNotFound{Path: cfg.PolicyDir}
		}
	}

	e.mu.Lock()
	e.config = cfg
	e.policies = make(map[string]*PolicyBundle)
	e.initializedAt = time.Now()
	e.mu.Unlock()

	// Load policies from directory if specified
	if cfg.PolicyDir != "" {
		if err := e.loadPoliciesFromDir(ctx, cfg.PolicyDir); err != nil {
			return err
		}
	}

	// Load embedded default policies
	if err := e.loadEmbeddedPolicies(ctx); err != nil {
		return err
	}

	// Compile all loaded policies
	if err := e.recompile(); err != nil {
		return err
	}

	e.initialized.Store(true)
	return nil
}

// LoadPolicy loads a policy with the given name and content.
func (e *OPAEngine) LoadPolicy(ctx context.Context, name string, content []byte) error {
	if !e.initialized.Load() {
		return ErrEngineNotInitialized{}
	}

	if err := validatePolicyName(name); err != nil {
		return err
	}

	if len(content) == 0 {
		return ErrEmptyPolicyContent{Name: name}
	}

	// Parse and validate the policy
	module, err := ast.ParseModule(name, string(content))
	if err != nil {
		return ErrInvalidPolicy{Name: name, Reason: err.Error()}
	}

	// Extract package name
	packageName := ""
	if module.Package != nil {
		packageName = module.Package.Path.String()
	}

	// Calculate checksum
	hash := sha256.Sum256(content)
	checksum := hex.EncodeToString(hash[:])

	bundle := &PolicyBundle{
		Name:     name,
		Content:  string(content),
		LoadedAt: time.Now(),
		Package:  packageName,
		Checksum: checksum,
	}

	e.mu.Lock()
	e.policies[name] = bundle
	e.mu.Unlock()

	// Recompile all policies
	if err := e.recompile(); err != nil {
		// Roll back on compilation failure
		e.mu.Lock()
		delete(e.policies, name)
		e.mu.Unlock()
		return err
	}

	return nil
}

// UnloadPolicy removes a loaded policy by name.
func (e *OPAEngine) UnloadPolicy(ctx context.Context, name string) error {
	if !e.initialized.Load() {
		return ErrEngineNotInitialized{}
	}

	e.mu.Lock()
	if _, exists := e.policies[name]; !exists {
		e.mu.Unlock()
		return ErrPolicyNotFound{Name: name}
	}
	delete(e.policies, name)
	e.mu.Unlock()

	// Recompile remaining policies
	return e.recompile()
}

// Evaluate evaluates a policy against the provided input.
func (e *OPAEngine) Evaluate(ctx context.Context, policyName string, input map[string]interface{}) (*EvaluationResult, error) {
	return e.EvaluateWithData(ctx, policyName, input, nil)
}

// EvaluateWithData evaluates a policy with additional data context.
func (e *OPAEngine) EvaluateWithData(ctx context.Context, policyName string, input map[string]interface{}, data map[string]interface{}) (*EvaluationResult, error) {
	startTime := time.Now()

	if !e.initialized.Load() {
		e.errorCount.Add(1)
		return nil, ErrEngineNotInitialized{}
	}

	if input == nil {
		e.errorCount.Add(1)
		return nil, ErrInvalidInput{Reason: "input cannot be nil"}
	}

	e.mu.RLock()
	bundle, exists := e.policies[policyName]
	compiler := e.compiler
	store := e.store
	defaultAction := e.config.DefaultAction
	e.mu.RUnlock()

	if !exists {
		e.errorCount.Add(1)
		return nil, ErrPolicyNotFound{Name: policyName}
	}

	if compiler == nil {
		e.errorCount.Add(1)
		return nil, ErrEngineNotInitialized{}
	}

	// Build the allow query path
	packagePath := strings.TrimPrefix(bundle.Package, "data.")
	allowQuery := "data." + packagePath + "." + defaultAllowQuery
	violationsQuery := "data." + packagePath + "." + defaultViolationsQuery

	// Store additional data if provided
	if data != nil {
		txn, err := store.NewTransaction(ctx, storage.WriteParams)
		if err != nil {
			e.errorCount.Add(1)
			return nil, ErrEvaluationFailed{PolicyName: policyName, Reason: err.Error()}
		}

		for key, value := range data {
			path, ok := storage.ParsePath("/" + key)
			if !ok {
				store.Abort(ctx, txn)
				e.errorCount.Add(1)
				return nil, ErrEvaluationFailed{PolicyName: policyName, Reason: "invalid storage path: /" + key}
			}
			if err := store.Write(ctx, txn, storage.AddOp, path, value); err != nil {
				// Try replace if add fails
				if err := store.Write(ctx, txn, storage.ReplaceOp, path, value); err != nil {
					store.Abort(ctx, txn)
					e.errorCount.Add(1)
					return nil, ErrEvaluationFailed{PolicyName: policyName, Reason: err.Error()}
				}
			}
		}

		if err := store.Commit(ctx, txn); err != nil {
			e.errorCount.Add(1)
			return nil, ErrEvaluationFailed{PolicyName: policyName, Reason: err.Error()}
		}
	}

	// Evaluate allow rule
	allowed := false
	reason := ""

	allowRego := rego.New(
		rego.Query(allowQuery),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(input),
	)

	allowResults, err := allowRego.Eval(ctx)
	if err != nil {
		e.errorCount.Add(1)
		return nil, ErrEvaluationFailed{PolicyName: policyName, Reason: err.Error()}
	}

	if len(allowResults) > 0 && len(allowResults[0].Expressions) > 0 {
		if val, ok := allowResults[0].Expressions[0].Value.(bool); ok {
			allowed = val
		}
	}

	// Apply default action if no result
	if len(allowResults) == 0 || len(allowResults[0].Expressions) == 0 {
		allowed = defaultAction == config.DefaultActionAllow
		reason = "no matching rules, applied default action: " + defaultAction
	}

	// Evaluate violations rule
	var violations []Violation

	violationsRego := rego.New(
		rego.Query(violationsQuery),
		rego.Compiler(compiler),
		rego.Store(store),
		rego.Input(input),
	)

	violationsResults, err := violationsRego.Eval(ctx)
	if err == nil && len(violationsResults) > 0 && len(violationsResults[0].Expressions) > 0 {
		if val, ok := violationsResults[0].Expressions[0].Value.([]interface{}); ok {
			for _, v := range val {
				switch msg := v.(type) {
				case string:
					violations = append(violations, Violation{
						Rule:     "violations",
						Message:  msg,
						Severity: SeverityError,
					})
				case map[string]interface{}:
					violation := Violation{Severity: SeverityError}
					if rule, ok := msg["rule"].(string); ok {
						violation.Rule = rule
					}
					if message, ok := msg["message"].(string); ok {
						violation.Message = message
					}
					if sev, ok := msg["severity"].(string); ok {
						violation.Severity = ViolationSeverity(sev)
					}
					violations = append(violations, violation)
				}
			}
		}
	}

	duration := time.Since(startTime)

	// Update statistics
	e.evaluationCount.Add(1)
	e.totalDuration.Add(int64(duration))
	now := time.Now()
	e.lastEvaluation.Store(&now)

	if allowed {
		e.allowedCount.Add(1)
	} else {
		e.deniedCount.Add(1)
	}

	result := &EvaluationResult{
		Allowed:    allowed,
		Reason:     reason,
		PolicyName: policyName,
		Timestamp:  startTime,
		Input:      input,
		Violations: violations,
		Duration:   duration,
	}

	return result, nil
}

// ListPolicies returns all loaded policies.
func (e *OPAEngine) ListPolicies() []*PolicyBundle {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := make([]*PolicyBundle, 0, len(e.policies))
	for _, bundle := range e.policies {
		// Create a copy to prevent external modification
		policyCopy := *bundle
		policies = append(policies, &policyCopy)
	}
	return policies
}

// GetPolicy returns a specific policy by name.
func (e *OPAEngine) GetPolicy(name string) (*PolicyBundle, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	bundle, exists := e.policies[name]
	if !exists {
		return nil, ErrPolicyNotFound{Name: name}
	}

	// Return a copy
	policyCopy := *bundle
	return &policyCopy, nil
}

// Reload reloads all policies from the configured directory.
func (e *OPAEngine) Reload(ctx context.Context) error {
	if !e.initialized.Load() {
		return ErrEngineNotInitialized{}
	}

	e.mu.Lock()
	policyDir := e.config.PolicyDir
	e.policies = make(map[string]*PolicyBundle)
	e.mu.Unlock()

	// Reload from directory
	if policyDir != "" {
		if err := e.loadPoliciesFromDir(ctx, policyDir); err != nil {
			return err
		}
	}

	// Reload embedded policies
	if err := e.loadEmbeddedPolicies(ctx); err != nil {
		return err
	}

	return e.recompile()
}

// Close releases resources held by the engine.
func (e *OPAEngine) Close() error {
	if !e.initialized.Load() {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = make(map[string]*PolicyBundle)
	e.compiler = nil
	e.initialized.Store(false)

	return nil
}

// IsInitialized returns whether the engine has been initialized.
func (e *OPAEngine) IsInitialized() bool {
	return e.initialized.Load()
}

// Stats returns engine statistics.
func (e *OPAEngine) Stats() EngineStats {
	e.mu.RLock()
	policyCount := len(e.policies)
	initializedAt := e.initializedAt
	e.mu.RUnlock()

	evalCount := e.evaluationCount.Load()
	totalDuration := time.Duration(e.totalDuration.Load())

	var avgDuration time.Duration
	if evalCount > 0 {
		avgDuration = totalDuration / time.Duration(evalCount)
	}

	stats := EngineStats{
		PolicyCount:           policyCount,
		EvaluationCount:       evalCount,
		AllowedCount:          e.allowedCount.Load(),
		DeniedCount:           e.deniedCount.Load(),
		ErrorCount:            e.errorCount.Load(),
		AverageEvaluationTime: avgDuration,
		InitializedAt:         initializedAt,
	}

	if lastEval := e.lastEvaluation.Load(); lastEval != nil {
		stats.LastEvaluationTime = *lastEval
	}

	return stats
}

// loadPoliciesFromDir loads all .rego files from the specified directory.
func (e *OPAEngine) loadPoliciesFromDir(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ErrPolicyLoadFailed{Path: dir, Reason: err.Error()}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), regoFileExtension) {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return ErrPolicyLoadFailed{Path: path, Reason: err.Error()}
		}

		name := strings.TrimSuffix(entry.Name(), regoFileExtension)

		// Parse and validate
		module, err := ast.ParseModule(name, string(content))
		if err != nil {
			return ErrInvalidPolicy{Name: name, Reason: err.Error()}
		}

		packageName := ""
		if module.Package != nil {
			packageName = module.Package.Path.String()
		}

		hash := sha256.Sum256(content)
		checksum := hex.EncodeToString(hash[:])

		bundle := &PolicyBundle{
			Name:     name,
			Content:  string(content),
			LoadedAt: time.Now(),
			Package:  packageName,
			Path:     path,
			Checksum: checksum,
		}

		e.mu.Lock()
		e.policies[name] = bundle
		e.mu.Unlock()
	}

	return nil
}

// loadEmbeddedPolicies loads the embedded default policies.
func (e *OPAEngine) loadEmbeddedPolicies(ctx context.Context) error {
	entries, err := embeddedPolicies.ReadDir("policies")
	if err != nil {
		// No embedded policies is not an error
		return nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), regoFileExtension) {
			continue
		}

		content, err := embeddedPolicies.ReadFile("policies/" + entry.Name())
		if err != nil {
			continue // Skip files that can't be read
		}

		name := strings.TrimSuffix(entry.Name(), regoFileExtension)

		// Don't overwrite policies loaded from directory
		e.mu.RLock()
		_, exists := e.policies[name]
		e.mu.RUnlock()

		if exists {
			continue
		}

		module, err := ast.ParseModule(name, string(content))
		if err != nil {
			continue // Skip invalid embedded policies
		}

		packageName := ""
		if module.Package != nil {
			packageName = module.Package.Path.String()
		}

		hash := sha256.Sum256(content)
		checksum := hex.EncodeToString(hash[:])

		bundle := &PolicyBundle{
			Name:     name,
			Content:  string(content),
			LoadedAt: time.Now(),
			Package:  packageName,
			Checksum: checksum,
		}

		e.mu.Lock()
		e.policies[name] = bundle
		e.mu.Unlock()
	}

	return nil
}

// recompile compiles all loaded policies into an AST compiler.
func (e *OPAEngine) recompile() error {
	e.mu.RLock()
	modules := make(map[string]*ast.Module)
	for name, bundle := range e.policies {
		module, err := ast.ParseModule(name, bundle.Content)
		if err != nil {
			e.mu.RUnlock()
			return ErrPolicyCompilationFailed{Name: name, Errors: []string{err.Error()}}
		}
		modules[name] = module
	}
	e.mu.RUnlock()

	compiler := ast.NewCompiler()
	compiler.Compile(modules)

	if compiler.Failed() {
		errors := make([]string, 0)
		for _, err := range compiler.Errors {
			errors = append(errors, err.Error())
		}
		return ErrPolicyCompilationFailed{Errors: errors}
	}

	e.mu.Lock()
	e.compiler = compiler
	e.mu.Unlock()

	return nil
}

// validatePolicyName validates a policy name.
func validatePolicyName(name string) error {
	if name == "" {
		return ErrInvalidPolicyName{Name: name, Reason: "name cannot be empty"}
	}

	if len(name) > maxPolicyNameLength {
		return ErrInvalidPolicyName{Name: name, Reason: "name exceeds maximum length"}
	}

	if !policyNameRegex.MatchString(name) {
		return ErrInvalidPolicyName{Name: name, Reason: "name must start with a letter and contain only alphanumeric characters, underscores, and hyphens"}
	}

	return nil
}
