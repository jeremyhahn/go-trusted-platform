/**
 * SDN policy wire types for the served `/api/v1/sdn/policies` routes.
 *
 * The handlers (pkg/webservice/v1/rest/sdn/handlers.go ApplyPolicy,
 * ListPolicies, GetPolicy) decode and encode protojson, so the field names are
 * the camelCase JSON names of the messages in pkg/api/grpc/proto/sdn.proto.
 * Enums are their proto names as strings (for example `POLICY_TYPE_ACL`);
 * 64-bit integers and timestamps are strings, as protojson writes them.
 */

/** The status block of a mutating response (sdn.proto Status). */
export interface PolicyOperationStatus {
  code?: number;
  message?: string;
  [key: string]: unknown;
}

/** Match criteria of a policy rule (sdn.proto PolicyRuleMatch). */
export interface PolicyRuleMatch {
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  direction?: string;
  interface?: string;
  vlanId?: number;
  dscp?: number;
  application?: string;
}

/** A policy rule (sdn.proto PolicyRule); `action` is a PolicyRuleAction name. */
export interface PolicyRule {
  ruleId?: string;
  priority?: number;
  match?: PolicyRuleMatch;
  action?: string;
  actionValue?: string;
  log?: boolean;
  counter?: boolean;
}

/** A policy target (sdn.proto PolicyTarget); `type` is a PolicyTargetType name. */
export interface PolicyTarget {
  type?: string;
  id?: string;
  direction?: string;
  zone?: string;
}

/** A policy schedule (sdn.proto PolicySchedule). */
export interface PolicySchedule {
  startTime?: string;
  endTime?: string;
  days?: string[];
  timezone?: string;
  enabled?: boolean;
}

/** A policy configuration (sdn.proto PolicyConfig); `type` is a PolicyType name. */
export interface PolicyConfig {
  name?: string;
  description?: string;
  type?: string;
  priority?: number;
  enabled?: boolean;
  rules?: PolicyRule[];
  targets?: PolicyTarget[];
  schedule?: PolicySchedule;
}

/** A policy (sdn.proto Policy); `status` is a PolicyStatus name. */
export interface Policy {
  id?: string;
  config?: PolicyConfig;
  status?: string;
  hitCount?: string;
  byteCount?: string;
  createdAt?: string;
  updatedAt?: string;
}

/** The body of POST /api/v1/sdn/policies (sdn.proto ApplyPolicyRequest). */
export interface ApplyPolicyRequest {
  policyId: string;
  config?: PolicyConfig;
}

/** The answer of POST /api/v1/sdn/policies (sdn.proto ApplyPolicyResponse). */
export interface ApplyPolicyResponse {
  status?: PolicyOperationStatus;
  policy?: Policy;
}

/** The answer of GET /api/v1/sdn/policies/{id} (sdn.proto GetPolicyResponse). */
export interface GetPolicyResponse {
  policy?: Policy;
}

/** The filters of GET /api/v1/sdn/policies (sdn.proto ListPoliciesRequest). */
export interface ListPoliciesRequest {
  type?: string;
  targetId?: string;
}

/** The answer of GET /api/v1/sdn/policies (sdn.proto ListPoliciesResponse). */
export interface ListPoliciesResponse {
  policies: Policy[];
  pagination?: Record<string, unknown>;
}
