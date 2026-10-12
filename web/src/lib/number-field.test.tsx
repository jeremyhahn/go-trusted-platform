import { zodResolver } from "@hookform/resolvers/zod";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ChangeEvent } from "react";
import { Controller, useForm } from "react-hook-form";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { numberFieldProps, readNumberInput } from "./number-field";

/** A change event from a real number input holding `text`. */
function numberInputChange(text: string): ChangeEvent<HTMLInputElement> {
  const input = document.createElement("input");
  input.type = "number";
  input.value = text;
  return { target: input } as ChangeEvent<HTMLInputElement>;
}

describe("readNumberInput", () => {
  it("reads the input's numeric value", () => {
    expect(readNumberInput(numberInputChange("3600"))).toBe(3600);
  });

  it("reads a blank input as undefined, not NaN or 0", () => {
    expect(readNumberInput(numberInputChange(""))).toBeUndefined();
  });
});

describe("numberFieldProps", () => {
  it("hands the field a number on change and keeps its other props", () => {
    const onChange = vi.fn<(value: number | undefined) => void>();
    const props = numberFieldProps({ name: "ttl", value: 60, onChange });

    props.onChange(numberInputChange("120"));

    expect(onChange).toHaveBeenCalledWith(120);
    expect(props.value).toBe(60);
    expect(props.name).toBe("ttl");
  });

  it("shows an undefined value as a blank and clears it to undefined", () => {
    const onChange = vi.fn<(value: number | undefined) => void>();
    const props = numberFieldProps({ value: undefined, onChange });

    props.onChange(numberInputChange(""));

    expect(props.value).toBe("");
    expect(onChange).toHaveBeenCalledWith(undefined);
  });
});

// The #451 forms in miniature: a z.number() schema through zodResolver with no
// cast, the input bound with numberFieldProps.
const ttlSchema = z.object({ ttl: z.number().min(60) });
type TtlValues = z.infer<typeof ttlSchema>;

function TtlForm({ onValid }: { onValid: (values: TtlValues) => void }) {
  const form = useForm<TtlValues>({
    resolver: zodResolver(ttlSchema),
    defaultValues: { ttl: 3600 },
  });
  return (
    <form onSubmit={form.handleSubmit(onValid)}>
      <Controller
        control={form.control}
        name="ttl"
        render={({ field }) => (
          <input type="number" aria-label="ttl" {...numberFieldProps(field)} />
        )}
      />
      <span role="alert">{form.formState.errors.ttl?.message}</span>
      <button type="submit">save</button>
    </form>
  );
}

describe("numberFieldProps with zodResolver", () => {
  afterEach(cleanup);

  it("submits the typed value as a number", async () => {
    const onValid = vi.fn<(values: TtlValues) => void>();
    render(<TtlForm onValid={onValid} />);

    fireEvent.change(screen.getByLabelText("ttl"), { target: { value: "120" } });
    await act(async () => fireEvent.click(screen.getByText("save")));

    expect(onValid).toHaveBeenCalledTimes(1);
    expect(onValid.mock.calls[0][0]).toEqual({ ttl: 120 });
  });

  it("rejects a blank required number instead of submitting 0", async () => {
    const onValid = vi.fn<(values: TtlValues) => void>();
    render(<TtlForm onValid={onValid} />);

    fireEvent.change(screen.getByLabelText("ttl"), { target: { value: "" } });
    await act(async () => fireEvent.click(screen.getByText("save")));

    expect(onValid).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).not.toBe("");
  });
});
