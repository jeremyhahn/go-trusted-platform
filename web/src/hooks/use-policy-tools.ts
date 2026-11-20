"use client";

/**
 * Policy tools: validate a policy document and evaluate a request against
 * the tenant's policies (POST /policies/validate and POST /policies/test).
 */

import { useIAM, useMutation } from "trusted-platform-sdk";
import type {
  TestIAMPolicyRequest,
  TestIAMPolicyResponse,
  ValidateIAMPolicyRequest,
  ValidateIAMPolicyResponse,
} from "trusted-platform-sdk";

export interface ValidatePolicyInput {
  tenantId: string;
  specYaml: string;
}

export type TestPolicyInput = TestIAMPolicyRequest;

/** Why the policy tools are unavailable on the embedded IAM backend. */
export const POLICY_TOOLS_UNAVAILABLE_REASON =
  "the embedded IAM backend does not implement Policy.Validate or Policy.Simulate yet";

// Flip when the embedded backend implements Policy.Validate and Policy.Simulate.
const POLICY_TOOLS_AVAILABLE = false as boolean;

/** Splits a comma-separated field into trimmed, non-empty entries. */
export function splitList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function usePolicyTools() {
  const iam = useIAM();

  // The embedded IAM backend (go-quicbaas v0.12.0-alpha) does not implement
  // Policy.Validate or Policy.Simulate, so both routes fail on it. Until it
  // does, the tools report themselves unavailable and reject without a call.
  const available = POLICY_TOOLS_AVAILABLE;

  const validate = useMutation<ValidateIAMPolicyResponse, ValidatePolicyInput>(
    ({ tenantId, specYaml }) => {
      if (!available) return Promise.reject(new Error(POLICY_TOOLS_UNAVAILABLE_REASON));
      // The REST handler reads `spec_yaml`; send it with the SDK field.
      const request: ValidateIAMPolicyRequest & { spec_yaml: string } = {
        tenantId,
        specYaml,
        spec_yaml: specYaml,
      };
      return iam.validatePolicy(request);
    },
  );

  const test = useMutation<TestIAMPolicyResponse, TestPolicyInput>(
    ({ tenantId, subjectId, roles, groups, action, resource, context, attributes }) => {
      if (!available) return Promise.reject(new Error(POLICY_TOOLS_UNAVAILABLE_REASON));
      // The REST handler decodes only `subject_id`; send that key alone.
      const request = {
        tenantId,
        subject_id: subjectId,
        roles,
        groups,
        action,
        resource,
        context,
        attributes,
      } as unknown as TestIAMPolicyRequest & { subject_id: string };
      return iam.testPolicy(request);
    },
  );

  return {
    /** False while the IAM backend lacks Policy.Validate and Policy.Simulate. */
    available,
    /** Why the tools are unavailable; null when they are available. */
    unavailableReason: available ? null : POLICY_TOOLS_UNAVAILABLE_REASON,
    validate,
    test,
  };
}
