"use client";

/**
 * <Gated op="POST /api/v1/ntp/step">{control}</Gated>
 *
 * Disables its single child control when the server does not enable `op`,
 * with the reason as the control's title. It never hides the control.
 * The clone carries `data-capability-op` and `data-capability-enabled` so
 * tests and specs can find it (#2033 item 4, #2058).
 */

import { cloneElement, isValidElement, type ReactElement } from "react";
import { useCapabilities } from "@/hooks/use-capabilities";

interface GatedChildProps {
  disabled?: boolean;
  title?: string;
}

export interface GatedProps {
  /** The server's op string, "METHOD /api/v1/path". */
  op: string;
  children: ReactElement<GatedChildProps>;
}

export function Gated({ op, children }: GatedProps) {
  const { capability } = useCapabilities();
  if (!isValidElement<GatedChildProps>(children)) {
    return children;
  }
  const answer = capability(op);
  const props: GatedChildProps & Record<string, unknown> = {
    "data-capability-op": op,
    "data-capability-enabled": answer.enabled ? "true" : "false",
  };
  if (!answer.enabled) {
    props.disabled = true;
    props.title = answer.reason;
  }
  return cloneElement(children, props);
}
