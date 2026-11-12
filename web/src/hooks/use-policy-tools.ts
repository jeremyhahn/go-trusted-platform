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

/** Splits a comma-separated field into trimmed, non-empty entries. */
export function splitList(value: string): string[] {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function usePolicyTools() {
  const iam = useIAM();

  const validate = useMutation<ValidateIAMPolicyResponse, ValidatePolicyInput>(
    ({ tenantId, specYaml }) => {
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

  return { validate, test };
}
