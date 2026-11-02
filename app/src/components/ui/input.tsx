// Reusable Input and Textarea components with consistent styling.
// Consolidates the repeated border/focus/ring patterns used across
// secrets-table, environments-table, sidebar, and create-org-form.

import type * as React from "react";
import { cn } from "../../lib/utils";

export function Input({
  className,
  inputSize = "default",
  ...props
}: Omit<React.ComponentProps<"input">, "size"> & { inputSize?: "default" | "sm"; size?: never }): React.ReactElement {
  return (
    <input
      className={cn(
        "min-w-0 w-full rounded-lg border border-input bg-background text-base focus:outline-none focus:ring-2 focus:ring-ring sm:text-sm",
        inputSize === "sm" ? "h-9 px-2 sm:h-7" : "h-11 px-3 sm:h-9",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({
  className,
  ...props
}: React.ComponentProps<"textarea">): React.ReactElement {
  return (
    <textarea
      className={cn(
        "w-full min-w-0 rounded-lg border border-input bg-background px-3 py-3 text-base focus:outline-none focus:ring-2 focus:ring-ring resize-y sm:py-2 sm:text-sm",
        className,
      )}
      {...props}
    />
  );
}
