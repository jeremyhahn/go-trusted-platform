'use client';

/**
 * PolicyValidateCard — validates an IAM policy spec through the SDK
 * validatePolicy (POST /api/v1/iam/tenants/{tenant}/policies/validate, #2054)
 * and shows the server's verdict and the rule errors it returns.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

export interface PolicyValidateResult {
  valid: boolean;
  errors?: string[];
}

export interface PolicyValidateCardProps {
  specYaml: string;
  validate: (specYaml: string) => Promise<PolicyValidateResult>;
}

export function PolicyValidateCard({ specYaml, validate }: PolicyValidateCardProps) {
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<PolicyValidateResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const onValidate = async () => {
    setPending(true);
    setResult(null);
    setError(null);
    try {
      setResult(await validate(specYaml));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setPending(false);
    }
  };

  const errors = result?.errors ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Validate</CardTitle>
        <CardDescription>Check the policy spec against the server&apos;s policy rules.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Button onClick={onValidate} disabled={!specYaml || pending}>
          {pending ? 'Validating' : 'Validate'}
        </Button>
        {result && (
          <div className="space-y-2">
            <p role="status" className={result.valid ? 'text-sm' : 'text-sm text-destructive'}>
              {result.valid ? 'Policy is valid' : 'Policy is not valid'}
            </p>
            {!result.valid && errors.length > 0 && (
              <ul className="list-disc pl-5 text-sm text-destructive">
                {errors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            )}
          </div>
        )}
        {error && (
          <p role="status" className="text-sm text-destructive">
            Validation failed: {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
