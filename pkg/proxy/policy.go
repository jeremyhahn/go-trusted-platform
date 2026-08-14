package proxy

import (
	"context"
	"net/http"
)

// PolicyEvaluator evaluates a named authorization policy against a request
// input document and returns the decision plus any violation messages. It is
// the seam to the platform OPA engine (pkg/policy/opa), adapted in
// pkg/sdn/gateway/proxysvc so this package does not link the OPA runtime.
// The chain fails closed: a false decision denies with "opa_denied" and an
// evaluation error denies with "opa_error".
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, policy string, input map[string]any) (allowed bool, violations []string, err error)
}

// checkPolicy evaluates the route's OPA policy, when one is configured,
// against the authenticated identity and returns a deny decision unless the
// policy allows. Violations are logged and audited server-side, never leaked
// to the client.
func (c *Chain) checkPolicy(ctx context.Context, r *http.Request, route *CompiledRoute, id *ClientIdentity) *AuthDecision {
	policyName := route.cfg.Auth.OPAPolicy
	if policyName == "" {
		return nil
	}
	// The engine rejects OPA-requiring routes on a chain without an
	// evaluator at construction time; deny defensively regardless.
	if c.policy == nil {
		return deny(ReasonOPAError)
	}
	allowed, violations, err := c.policy.Evaluate(ctx, policyName, policyInput(r, route, id))
	if err != nil {
		c.logger.Error("proxy: opa evaluation failed",
			"route", route.cfg.ID, "policy", policyName, "error", err)
		return deny(ReasonOPAError)
	}
	if !allowed {
		c.logger.Warn("proxy: opa policy denied request",
			"route", route.cfg.ID, "policy", policyName, "client", id.ID,
			"violations", violations)
		return deny(ReasonOPADenied)
	}
	return nil
}

// policyInput builds the OPA input document for one request. The schema is
// part of the proxy's policy contract (documented in docs/proxy):
//
//	{
//	  "client":  {"id", "zone", "device_id", "attested", "auth_method", "roles"},
//	  "route":   {"id", "hosts", "path_prefix", "backend_zone"},
//	  "request": {"method", "path", "host"}
//	}
func policyInput(r *http.Request, route *CompiledRoute, id *ClientIdentity) map[string]any {
	roles := make([]any, 0, len(id.Roles))
	for _, role := range id.Roles {
		roles = append(roles, role)
	}
	hosts := make([]any, 0, len(route.cfg.Hosts))
	for _, h := range route.cfg.Hosts {
		hosts = append(hosts, h)
	}
	return map[string]any{
		"client": map[string]any{
			"id":          id.ID,
			"zone":        id.Zone,
			"device_id":   id.DeviceID,
			"attested":    id.Attested,
			"auth_method": id.AuthMethod,
			"roles":       roles,
		},
		"route": map[string]any{
			"id":           route.cfg.ID,
			"hosts":        hosts,
			"path_prefix":  route.cfg.PathPrefix,
			"backend_zone": route.cfg.Auth.BackendZone,
		},
		"request": map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"host":   r.Host,
		},
	}
}
