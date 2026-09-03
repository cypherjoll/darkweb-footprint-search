import assert from "node:assert/strict";
import test from "node:test";
import { AppError } from "../src/errors.js";
import { getProviderJson } from "../src/http.js";

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof AppError && error.code === code;
}

test("provider transport fixes the origin and redacts reflected secrets in headers", async (context) => {
  const originalFetch = globalThis.fetch;
  const key = "opaque-provider-key-123";
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ status: "success", results: [] }), {
      status: 200,
      headers: {
        "content-type": `application/json; reflected=${key}`,
        "x-ratelimit-remaining": key,
        "x-untrusted-header": key,
      },
    });
  context.after(() => {
    globalThis.fetch = originalFetch;
  });

  const response = await getProviderJson(
    new URL("https://onionsearchengine.com/api.php?q=APT10&page=1"),
    key,
    1_000,
  );
  assert.deepEqual(response.headers, {
    "content-type": "application/json; reflected=***",
    "x-ratelimit-remaining": "***",
  });
  assert.doesNotMatch(JSON.stringify(response.headers), new RegExp(key));
});

test("provider transport does not follow a caller-selected origin", async () => {
  await assert.rejects(
    getProviderJson(
      new URL("https://example.invalid/api.php"),
      "synthetic-key",
      1_000,
    ),
    hasErrorCode("PROVIDER_ORIGIN_BLOCKED"),
  );
});

test("provider HTTP errors redact a reflected exact key", async (context) => {
  const originalFetch = globalThis.fetch;
  const key = "opaque-provider-key-123";
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ message: `Rejected credential ${key}` }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  context.after(() => {
    globalThis.fetch = originalFetch;
  });

  await assert.rejects(
    getProviderJson(
      new URL("https://onionsearchengine.com/api.php?q=APT10"),
      key,
      1_000,
    ),
    (error: unknown) =>
      error instanceof AppError &&
      error.code === "PROVIDER_AUTH_FAILED" &&
      error.message.includes("***") &&
      !error.message.includes(key),
  );
});
