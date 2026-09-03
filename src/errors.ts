import { SCHEMA_VERSION, type ErrorEnvelope } from "./types.js";

export const EXIT = {
  OK: 0,
  USAGE: 2,
  CONFIG: 3,
  PARTIAL: 4,
  SOURCE_FAILED: 5,
  OUTPUT: 6,
  POLICY: 7,
  INTERNAL: 70,
} as const;

export class AppError extends Error {
  readonly code: string;
  readonly exitCode: number;

  constructor(code: string, message: string, exitCode: number = EXIT.INTERNAL) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.exitCode = exitCode;
  }
}

export function redactSecrets(input: string): string {
  return input
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "***")
    .replace(/\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{8,}\b/g, "***")
    .replace(/(X-API-Key\s*[:=]\s*)\S+/gi, "$1***")
    .replace(/((?:socks5h?|https?):\/\/)[^/@\s]+@/gi, "$1***@")
    .replace(/([?&](?:api_?key|token|access_token)=)[^&\s]+/gi, "$1***");
}

export function asAppError(error: unknown): AppError {
  if (error instanceof AppError) return error;
  if (error instanceof Error) {
    return new AppError(
      "INTERNAL_ERROR",
      redactSecrets(error.message),
      EXIT.INTERNAL,
    );
  }
  return new AppError(
    "INTERNAL_ERROR",
    "Unexpected internal error.",
    EXIT.INTERNAL,
  );
}

export function errorEnvelope(command: string, error: AppError): ErrorEnvelope {
  return {
    schema_version: SCHEMA_VERSION,
    command,
    ok: false,
    error: {
      code: error.code,
      message: redactSecrets(error.message),
    },
  };
}
