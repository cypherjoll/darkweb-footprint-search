const ANSI_CSI = /\u001B\[[0-?]*[ -/]*[@-~]/g;
const ANSI_OSC = /\u001B\][^\u0007]*(?:\u0007|\u001B\\)/g;
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
const BIDI_CONTROLS = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

export function stripTerminalControls(value: string): string {
  return value
    .replace(ANSI_OSC, "")
    .replace(ANSI_CSI, "")
    .replace(BIDI_CONTROLS, "")
    .replace(CONTROL_CHARS, "");
}

function canonicalizeText(value: string): string {
  return stripTerminalControls(value)
    .normalize("NFKC")
    .replace(/\s+/g, " ")
    .trim();
}

export function sanitizeText(value: unknown, maxLength = 500): string {
  if (typeof value !== "string") return "";
  return canonicalizeText(value).slice(0, maxLength);
}

export function redactExactSecrets(
  value: string,
  secrets: readonly string[],
): string {
  const candidates = new Set<string>();
  for (const secret of secrets) {
    if (!secret) continue;
    candidates.add(secret);
    try {
      candidates.add(encodeURIComponent(secret));
    } catch {
      // The exact value is still redacted if it contains an unpaired surrogate.
    }
  }
  let redacted = value;
  for (const candidate of [...candidates].sort((a, b) => b.length - a.length))
    redacted = redacted.split(candidate).join("***");
  return redacted;
}

export function sanitizeSecretText(
  value: unknown,
  secrets: readonly string[],
  maxLength = 500,
): string {
  if (typeof value !== "string") return "";
  const clean = canonicalizeText(value);
  const canonicalSecrets = secrets.flatMap((secret) => [
    secret,
    canonicalizeText(secret),
  ]);
  return redactExactSecrets(clean, canonicalSecrets).slice(0, maxLength);
}

export function sanitizeQuery(value: string): string {
  const normalized = sanitizeText(value, 1024);
  if (!normalized) return "";
  return normalized;
}

export function escapeMarkdown(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}\[\]()#+.!|~-])/g, "\\$1");
}

export function codeSpan(value: string): string {
  const ticks =
    value.match(/`+/g)?.reduce((max, item) => Math.max(max, item.length), 0) ??
    0;
  const fence = "`".repeat(ticks + 1);
  return `${fence}${value}${fence}`;
}

export function sanitizeJsonValue(
  value: unknown,
  secrets: readonly string[] = [],
  depth = 0,
): unknown {
  if (depth > 20) return "[depth limit]";
  if (typeof value === "string") {
    return redactExactSecrets(stripTerminalControls(value), secrets);
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeJsonValue(item, secrets, depth + 1));
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      const safeKey = redactExactSecrets(stripTerminalControls(key), secrets);
      output[safeKey] = sanitizeJsonValue(item, secrets, depth + 1);
    }
    return output;
  }
  return value;
}
