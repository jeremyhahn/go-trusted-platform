"use client";

import * as CollapsiblePrimitive from "@radix-ui/react-collapsible";

/**
 * Collapsible component for expandable sections
 *
 * @example
 * ```tsx
 * <Collapsible>
 *   <CollapsibleTrigger>Toggle</CollapsibleTrigger>
 *   <CollapsibleContent>
 *     Hidden content here
 *   </CollapsibleContent>
 * </Collapsible>
 * ```
 */
const Collapsible = CollapsiblePrimitive.Root;

const CollapsibleTrigger = CollapsiblePrimitive.CollapsibleTrigger;

const CollapsibleContent = CollapsiblePrimitive.CollapsibleContent;

export { Collapsible, CollapsibleTrigger, CollapsibleContent };
