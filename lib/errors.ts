import { z } from "zod";
import { zodMessage } from "@/lib/validation";

const RLS_FRIENDLY: Array<[RegExp, string]> = [
  [
    /violates row.level security/i,
    "You don't have permission to perform this action.",
  ],
  [
    /permission denied for table/i,
    "You don't have permission to access that data.",
  ],
  [
    /permission denied for sequence/i,
    "You don't have permission to create that record.",
  ],
  [
    /permission denied for function/i,
    "Your account role does not allow this operation.",
  ],
  [
    /duplicate key|already exists/i,
    "A record with these details already exists.",
  ],
  [
    /foreign key|still referenced/i,
    "This record is still in use elsewhere and cannot be changed.",
  ],
  [
    /violates not-null|null value in column/i,
    "Some required fields are missing.",
  ],
  [
    /invalid input syntax for type uuid/i,
    "The selected record no longer exists. Refresh and try again.",
  ],
  [
    /violates check constraint/i,
    "One of the selected values is not allowed.",
  ],
  [
    /cannot demote the last administrator|last administrator/i,
    "The final administrator cannot be demoted or deleted.",
  ],
  [
    /Each port can only be used by one active or planned cable/i,
    "One of those ports is already used by another active or planned cable.",
  ],
  [
    /network|fetch failed|load failed/i,
    "A network problem interrupted the request. Check your connection.",
  ],
  [/jwt|token.*expired/i, "Your session has expired. Please sign in again."],
];

/** Postgres / PostgREST error codes mapped to safe, user-facing text. */
const CODE_MESSAGES: Record<string, string> = {
  "23505": "A record with these details already exists.",
  "23503": "This record is still in use elsewhere and cannot be changed.",
  "23502": "Some required fields are missing.",
  "23514": "One of the selected values is not allowed.",
  "22P02": "The selected record no longer exists. Refresh and try again.",
  "42501": "You don't have permission to perform this action.",
  PGRST116: "The requested record could not be found.",
  PGRST301: "Your session has expired. Please sign in again.",
};

function messageFrom(error: unknown): string {
  if (error == null) return "";
  if (typeof error === "string") return error.trim();
  const value =
    (error as { message?: unknown } | null)?.message ??
    (error as { error_description?: unknown } | null)?.error_description;
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Turn any unknown error into a short, safe user-facing message.
 *
 * Raw database messages are never returned to the UI: they can reveal table
 * names, constraints and SQL internals. Known patterns/codes are mapped, and
 * everything else falls back to a generic message. Details are logged only in
 * development.
 */
export function toUserMessage(
  error: unknown,
  fallback = "Something went wrong. Please try again."
): string {
  if (error == null) return fallback;

  if (error instanceof z.ZodError) return zodMessage(error);

  const raw = messageFrom(error);
  if (!raw) return fallback;

  for (const [pattern, replacement] of RLS_FRIENDLY) {
    if (pattern.test(raw)) return replacement;
  }

  const code = (error as { code?: unknown } | null)?.code;
  if (typeof code === "string" && CODE_MESSAGES[code]) {
    return CODE_MESSAGES[code];
  }

  if (process.env.NODE_ENV !== "production") {
    console.warn("[toUserMessage]", error);
  }

  return fallback;
}
