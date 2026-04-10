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

package iam

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// AuthzOption is a functional option for configuring the AuthzMiddleware.
type AuthzOption func(*AuthzMiddleware)

// WithAuthzAuditLogger sets the audit logger for the authorization middleware.
func WithAuthzAuditLogger(logger audit.AuditLogger) AuthzOption {
	return func(m *AuthzMiddleware) {
		m.auditLogger = logger
	}
}

// AuthzMiddleware provides authorization using the PEP (Policy Enforcement Point) service.
type AuthzMiddleware struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	config         AuthzConfig
	pepService     PEPServiceClient
	auditLogger    audit.AuditLogger

	// Cache for authorization decisions
	cache      map[string]*authzCacheEntry
	cacheMutex sync.RWMutex
}

// authzCacheEntry represents a cached authorization decision.
type authzCacheEntry struct {
	allowed   bool
	policy    string
	rule      string
	expiresAt time.Time
}

// NewAuthzMiddleware creates a new authorization middleware instance.
func NewAuthzMiddleware(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	config AuthzConfig,
	pepService PEPServiceClient,
	opts ...AuthzOption,
) (*AuthzMiddleware, error) {

	if logger == nil {
		return nil, ErrInvalidConfig{Field: "logger", Reason: "logger is required"}
	}
	if responseWriter == nil {
		return nil, ErrInvalidConfig{Field: "responseWriter", Reason: "response writer is required"}
	}
	if pepService == nil {
		return nil, ErrInvalidConfig{Field: "pepService", Reason: "PEP service client is required"}
	}

	m := &AuthzMiddleware{
		logger:         logger,
		responseWriter: responseWriter,
		config:         config,
		pepService:     pepService,
	}

	// Apply functional options
	for _, opt := range opts {
		opt(m)
	}

	if config.CacheDecisions {
		m.cache = make(map[string]*authzCacheEntry)
		go m.cleanupCache()
	}

	return m, nil
}

// Handler returns an http.Handler middleware for authorization.
func (m *AuthzMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.Authorize(w, r, next.ServeHTTP)
	})
}

// Authorize checks if the current session is authorized to perform the request.
func (m *AuthzMiddleware) Authorize(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Get session from context
	session, ok := GetSessionFromContext(r.Context())
	if !ok {
		m.logger.Debugf("authz: no session in context")
		m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required for authorization"})
		return
	}

	// Check MFA requirement
	if m.config.RequireMFA {
		if !session.IsMFAVerified() {
			m.logger.Debugf("authz: MFA verification required")
			m.responseWriter.Error401(w, r, ErrMFARequired{})
			return
		}

		// Check MFA grace period
		if m.config.MFAGracePeriod > 0 {
			if time.Since(session.MFATimestamp()) > m.config.MFAGracePeriod {
				m.logger.Debugf("authz: MFA verification expired")
				m.responseWriter.Error401(w, r, ErrMFAExpired{})
				return
			}
		}
	}

	// Extract action from HTTP method
	action := m.extractAction(r)

	// Extract resource from URL path
	resource := m.extractResource(r)

	// Extract additional context from headers
	policyContext := m.extractPolicyContext(r)

	// Check authorization
	allowed, matchedPolicy, matchedRule, err := m.checkAuthorization(r.Context(), session, action, resource, policyContext)
	if err != nil {
		m.logger.Errorf("authz: authorization check failed: %v", err)
		m.responseWriter.Error500(w, r, ErrServiceUnavailable{Service: "PEP", Reason: err.Error()})
		return
	}

	if !allowed {
		m.logger.Debugf("authz: access denied for user %s action %s on resource %s (policy: %s, rule: %s)",
			session.UserID(), action, resource, matchedPolicy, matchedRule)
		m.logAuthzDecision(r.Context(), session, action, resource, matchedPolicy, matchedRule, false)
		m.responseWriter.Error403(w, r, ErrForbidden{
			Action:   action,
			Resource: resource,
		}, nil)
		return
	}

	m.logger.Debugf("authz: access granted for user %s action %s on resource %s (policy: %s, rule: %s)",
		session.UserID(), action, resource, matchedPolicy, matchedRule)
	m.logAuthzDecision(r.Context(), session, action, resource, matchedPolicy, matchedRule, true)

	next(w, r)
}

// logAuthzDecision logs an authorization decision to the audit logger.
func (m *AuthzMiddleware) logAuthzDecision(
	ctx context.Context,
	session IAMSession,
	action, resource, policyName, ruleName string,
	allowed bool,
) {
	if m.auditLogger == nil {
		return
	}

	var outcome audit.Outcome
	var auditAction string
	if allowed {
		outcome = audit.OutcomeSuccess
		auditAction = "access_granted"
	} else {
		outcome = audit.OutcomeDenied
		auditAction = "access_denied"
	}

	event := audit.AuditEvent{
		ID:           uuid.New().String(),
		Timestamp:    time.Now().UTC(),
		Actor:        session.UserID(),
		Action:       auditAction,
		Resource:     resource,
		ResourceType: "authorization",
		Outcome:      outcome,
		Details: map[string]any{
			"requested_action": action,
			"policy_name":      policyName,
			"rule_name":        ruleName,
			"tenant_id":        session.TenantID(),
		},
	}

	if err := m.auditLogger.LogAsync(event); err != nil {
		m.logger.Errorf("authz: failed to log audit event: %v", err)
	}
}

// extractAction maps the HTTP method to an authorization action.
func (m *AuthzMiddleware) extractAction(r *http.Request) string {
	if action, ok := HTTPMethodToAction[r.Method]; ok {
		return action
	}
	return strings.ToLower(r.Method)
}

// extractResource extracts the resource identifier from the URL path.
func (m *AuthzMiddleware) extractResource(r *http.Request) string {
	// Use the full path as the resource
	resource := r.URL.Path

	// Clean up the path
	resource = strings.TrimPrefix(resource, "/")
	if resource == "" {
		resource = "/"
	}

	return resource
}

// extractPolicyContext extracts additional context from request headers.
func (m *AuthzMiddleware) extractPolicyContext(r *http.Request) map[string]string {
	context := make(map[string]string)

	// Extract policy context from header (JSON encoded)
	policyContextHeader := r.Header.Get(PolicyContextHeader)
	if policyContextHeader != "" {
		var headerContext map[string]string
		if err := json.Unmarshal([]byte(policyContextHeader), &headerContext); err == nil {
			for k, v := range headerContext {
				context[k] = v
			}
		}
	}

	// Add request metadata
	context["request.method"] = r.Method
	context["request.path"] = r.URL.Path
	context["request.host"] = r.Host
	context["request.remote_addr"] = r.RemoteAddr

	// Add timestamp
	context["request.time"] = time.Now().UTC().Format(time.RFC3339)

	return context
}

// checkAuthorization performs the authorization check using the PEP service.
func (m *AuthzMiddleware) checkAuthorization(
	ctx context.Context,
	session IAMSession,
	action, resource string,
	policyContext map[string]string,
) (allowed bool, matchedPolicy, matchedRule string, err error) {

	// Check cache first
	if m.config.CacheDecisions {
		if entry := m.getCachedDecision(session, action, resource); entry != nil {
			return entry.allowed, entry.policy, entry.rule, nil
		}
	}

	// Build the check request
	subject := session.ToSubject()
	if subject == nil {
		return m.handleDefaultDecision(), "", "", nil
	}

	req := &iampb.CheckRequest{
		Subject:  subject,
		Action:   action,
		Resource: resource,
		Context:  policyContext,
	}

	// Call the PEP service
	resp, err := m.pepService.Check(ctx, req)
	if err != nil {
		// On error, apply default policy
		m.logger.Errorf("authz: PEP service error: %v", err)
		return m.handleDefaultDecision(), "", "", err
	}

	// Cache the decision
	if m.config.CacheDecisions {
		m.cacheDecision(session, action, resource, resp.Allowed, resp.MatchedPolicy, resp.MatchedRule)
	}

	return resp.Allowed, resp.MatchedPolicy, resp.MatchedRule, nil
}

// handleDefaultDecision returns the default authorization decision based on configuration.
func (m *AuthzMiddleware) handleDefaultDecision() bool {
	return !m.config.DefaultDeny
}

// getCachedDecision retrieves a cached authorization decision.
func (m *AuthzMiddleware) getCachedDecision(session IAMSession, action, resource string) *authzCacheEntry {
	cacheKey := m.buildCacheKey(session, action, resource)

	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()

	if entry, ok := m.cache[cacheKey]; ok {
		if time.Now().Before(entry.expiresAt) {
			return entry
		}
	}

	return nil
}

// cacheDecision stores an authorization decision in the cache.
func (m *AuthzMiddleware) cacheDecision(session IAMSession, action, resource string, allowed bool, policy, rule string) {
	cacheKey := m.buildCacheKey(session, action, resource)

	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()

	m.cache[cacheKey] = &authzCacheEntry{
		allowed:   allowed,
		policy:    policy,
		rule:      rule,
		expiresAt: time.Now().Add(m.config.CacheTTL),
	}
}

// buildCacheKey creates a unique cache key for an authorization decision.
func (m *AuthzMiddleware) buildCacheKey(session IAMSession, action, resource string) string {
	return session.TenantID() + ":" + session.UserID() + ":" + action + ":" + resource
}

// cleanupCache periodically removes expired cache entries.
func (m *AuthzMiddleware) cleanupCache() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.cacheMutex.Lock()
		now := time.Now()
		for key, entry := range m.cache {
			if now.After(entry.expiresAt) {
				delete(m.cache, key)
			}
		}
		m.cacheMutex.Unlock()
	}
}

// ClearCache clears all cached authorization decisions.
func (m *AuthzMiddleware) ClearCache() {
	if !m.config.CacheDecisions {
		return
	}

	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()

	m.cache = make(map[string]*authzCacheEntry)
}

// ClearUserCache clears cached authorization decisions for a specific user.
func (m *AuthzMiddleware) ClearUserCache(tenantID, userID string) {
	if !m.config.CacheDecisions {
		return
	}

	prefix := tenantID + ":" + userID + ":"

	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()

	for key := range m.cache {
		if strings.HasPrefix(key, prefix) {
			delete(m.cache, key)
		}
	}
}

// CheckResource provides a programmatic way to check authorization for a specific resource.
func (m *AuthzMiddleware) CheckResource(
	ctx context.Context,
	session IAMSession,
	action, resource string,
) (bool, error) {
	allowed, _, _, err := m.checkAuthorization(ctx, session, action, resource, nil)
	return allowed, err
}

// CheckBatch performs batch authorization checks for multiple resources.
func (m *AuthzMiddleware) CheckBatch(
	ctx context.Context,
	session IAMSession,
	action string,
	resources []string,
) (map[string]bool, error) {
	subject := session.ToSubject()
	if subject == nil {
		defaultDecision := m.handleDefaultDecision()
		results := make(map[string]bool, len(resources))
		for _, resource := range resources {
			results[resource] = defaultDecision
		}
		return results, nil
	}

	req := &iampb.CheckBatchRequest{
		Subject:   subject,
		Action:    action,
		Resources: resources,
	}

	resp, err := m.pepService.CheckBatch(ctx, req)
	if err != nil {
		return nil, ErrServiceUnavailable{Service: "PEP", Reason: err.Error()}
	}

	results := make(map[string]bool, len(resources))
	for i, resource := range resources {
		if i < len(resp.Results) {
			results[resource] = resp.Results[i]
		} else {
			results[resource] = m.handleDefaultDecision()
		}
	}

	return results, nil
}

// ResourceAuthorizer is a helper that checks authorization for a specific resource pattern.
type ResourceAuthorizer struct {
	middleware     *AuthzMiddleware
	resourcePrefix string
}

// NewResourceAuthorizer creates a new resource authorizer with a prefix.
func (m *AuthzMiddleware) NewResourceAuthorizer(resourcePrefix string) *ResourceAuthorizer {
	return &ResourceAuthorizer{
		middleware:     m,
		resourcePrefix: resourcePrefix,
	}
}

// CanRead checks if the session can read the resource.
func (ra *ResourceAuthorizer) CanRead(ctx context.Context, session IAMSession, resourceID string) (bool, error) {
	resource := ra.resourcePrefix + "/" + resourceID
	return ra.middleware.CheckResource(ctx, session, "read", resource)
}

// CanCreate checks if the session can create resources.
func (ra *ResourceAuthorizer) CanCreate(ctx context.Context, session IAMSession) (bool, error) {
	return ra.middleware.CheckResource(ctx, session, "create", ra.resourcePrefix)
}

// CanUpdate checks if the session can update the resource.
func (ra *ResourceAuthorizer) CanUpdate(ctx context.Context, session IAMSession, resourceID string) (bool, error) {
	resource := ra.resourcePrefix + "/" + resourceID
	return ra.middleware.CheckResource(ctx, session, "update", resource)
}

// CanDelete checks if the session can delete the resource.
func (ra *ResourceAuthorizer) CanDelete(ctx context.Context, session IAMSession, resourceID string) (bool, error) {
	resource := ra.resourcePrefix + "/" + resourceID
	return ra.middleware.CheckResource(ctx, session, "delete", resource)
}

// AuthorizeHandler wraps a handler with authorization for a specific action and resource.
func (m *AuthzMiddleware) AuthorizeHandler(action, resource string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := GetSessionFromContext(r.Context())
			if !ok {
				m.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
				return
			}

			allowed, err := m.CheckResource(r.Context(), session, action, resource)
			if err != nil {
				m.responseWriter.Error500(w, r, err)
				return
			}

			if !allowed {
				m.responseWriter.Error403(w, r, ErrForbidden{
					Action:   action,
					Resource: resource,
				}, nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
