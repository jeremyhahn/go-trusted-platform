import type { ChangeEvent } from "react";

/** The parts of a react-hook-form field (ControllerRenderProps) this reads. */
interface NumberField {
  value: number | undefined;
  onChange: (value: number | undefined) => void;
}

/**
 * Read a number input as react-hook-form's `valueAsNumber` does: the input's
 * numeric value, or undefined when it is blank (valueAsNumber is NaN). A
 * blank therefore fails `z.number()` as missing and passes
 * `z.number().optional()`, so a form schema's input and output types agree
 * and `zodResolver` needs no cast (#451).
 */
export function readNumberInput(
  event: ChangeEvent<HTMLInputElement>
): number | undefined {
  const value = event.target.valueAsNumber;
  return Number.isNaN(value) ? undefined : value;
}

/**
 * Bind a form field to `<Input type="number">`: spread the result onto the
 * input in place of `{...field}`. The field holds a number (or undefined); the
 * input shows a blank for undefined so it stays controlled.
 */
export function numberFieldProps<F extends NumberField>(field: F) {
  const { value, onChange, ...rest } = field;
  return {
    ...rest,
    value: value ?? "",
    onChange: (event: ChangeEvent<HTMLInputElement>) =>
      onChange(readNumberInput(event)),
  };
}
