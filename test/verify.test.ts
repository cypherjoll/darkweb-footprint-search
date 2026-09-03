import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { AppError, EXIT } from "../src/errors.js";
import type { OnionTextResponse } from "../src/http.js";
import { extractSafeText, verifyReport } from "../src/verify.js";
import { makeSearchReport } from "./helpers.js";

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof AppError && error.code === code;
}

test("extractSafeText keeps visible HTML evidence and discards active or embedded content", () => {
  const body = Buffer.from(
    [
      "<!doctype html><html><head>",
      "<title>  APT10 \u001b[31mResearch\u001b[0m  </title>",
      "<style>.hidden{display:none}</style><script>APT10 hidden script</script>",
      "</head><body><main>Public APT10 intelligence signal</main>",
      "<iframe>APT10 embedded text</iframe><form>APT10 form text</form>",
      "</body></html>",
    ].join(""),
    "utf8",
  );

  const extracted = extractSafeText(body, "text/html", "APT10");
  assert.equal(extracted.title, "APT10 Research");
  assert.equal(extracted.keywordPresent, true);
  assert.match(extracted.text, /Public APT10 intelligence signal/);
  assert.doesNotMatch(extracted.text, /hidden script|embedded text|form text/);
  assert.match(extracted.evidenceSnippet, /APT10/);
});

test("extractSafeText handles plain text and does not invent absent evidence", () => {
  const present = extractSafeText(
    Buffer.from("  Public\nAPT10\tmention \u001b[31mred\u001b[0m  ", "utf8"),
    "text/plain",
    "apt10",
  );
  assert.equal(present.text, "Public APT10 mention red");
  assert.equal(present.keywordPresent, true);
  assert.match(present.evidenceSnippet, /APT10/);

  const absent = extractSafeText(
    Buffer.from("No matching public evidence", "utf8"),
    "text/plain",
    "APT10",
  );
  assert.equal(absent.keywordPresent, false);
  assert.equal(absent.evidenceSnippet, "");
});

test("verifyReport uses an injected fetcher, records safe evidence, and bounds selection", async () => {
  const report = makeSearchReport(3);
  const firstUrl = report.data.results[0]?.canonical_url;
  const blockedUrl = report.data.results[1]?.canonical_url;
  assert.ok(firstUrl);
  assert.ok(blockedUrl);
  const responseBody = Buffer.from(
    "<html><head><title>Synthetic report</title></head><body>Observed APT10 reference.</body></html>",
    "utf8",
  );
  const calls: Array<{ url: string; proxy: string; timeoutMs: number }> = [];

  const fetcher = async (
    url: string,
    proxy: string,
    timeoutMs: number,
  ): Promise<OnionTextResponse> => {
    calls.push({ url, proxy, timeoutMs });
    if (url === blockedUrl) {
      throw new AppError(
        "CONTENT_TYPE_BLOCKED",
        "Synthetic blocked response.",
        EXIT.POLICY,
      );
    }
    return {
      status: 200,
      contentType: "text/html",
      body: responseBody,
      finalUrl: url,
      elapsedMs: 12,
    };
  };

  const verified = await verifyReport(report, {
    proxy: "socks5h://127.0.0.1:9050",
    max: 2,
    timeoutMs: 4_000,
    now: () => new Date("2026-01-20T11:00:00.000Z"),
    fetcher,
  });

  assert.deepEqual(calls, [
    { url: firstUrl, proxy: "socks5h://127.0.0.1:9050", timeoutMs: 4_000 },
    { url: blockedUrl, proxy: "socks5h://127.0.0.1:9050", timeoutMs: 4_000 },
  ]);
  assert.equal(verified.command, "onion.verify");
  assert.equal(verified.partial, true);
  assert.equal(verified.run.completed_at, "2026-01-20T11:00:00.000Z");

  const reachable = verified.data.results[0]?.verification;
  assert.equal(reachable?.state, "reachable");
  if (reachable?.state === "reachable") {
    assert.equal(reachable.keyword_present, true);
    assert.equal(reachable.safe_title, "Synthetic report");
    assert.equal(reachable.final_url, firstUrl);
    assert.equal(
      reachable.raw_sha256,
      createHash("sha256").update(responseBody).digest("hex"),
    );
    assert.match(reachable.evidence_snippet ?? "", /APT10/);
  }

  assert.deepEqual(verified.data.results[1]?.verification, {
    state: "blocked",
    checked_at: "2026-01-20T11:00:00.000Z",
    error_code: "CONTENT_TYPE_BLOCKED",
  });
  assert.deepEqual(verified.data.results[2]?.verification, {
    state: "not_requested",
  });
  assert.equal(
    verified.warnings.some(
      (warning) => warning.code === "ONION_VERIFICATION_PARTIAL",
    ),
    true,
  );
  assert.deepEqual(
    report.data.results.map((item) => item.verification),
    [
      { state: "not_requested" },
      { state: "not_requested" },
      { state: "not_requested" },
    ],
  );
});

test("verifyReport validates verification bounds and loopback proxy even with a fake fetcher", async () => {
  const report = makeSearchReport(1);
  const fetcher = async (): Promise<OnionTextResponse> => {
    throw new Error("must not be called");
  };

  await assert.rejects(
    verifyReport(report, {
      proxy: "socks5h://127.0.0.1:9050",
      max: 0,
      timeoutMs: 1_000,
      fetcher,
    }),
    hasErrorCode("MAX_VERIFY_INVALID"),
  );
  await assert.rejects(
    verifyReport(report, {
      proxy: "socks5h://192.0.2.1:9050",
      max: 1,
      timeoutMs: 1_000,
      fetcher,
    }),
    hasErrorCode("TOR_PROXY_INVALID"),
  );
  await assert.rejects(
    verifyReport(report, {
      proxy: "socks5h://127.0.0.1:9050",
      max: 1,
      timeoutMs: 999,
      fetcher,
    }),
    hasErrorCode("TIMEOUT_INVALID"),
  );
  await assert.rejects(
    verifyReport(report, {
      proxy: "socks5h://127.0.0.1:9050",
      max: 1,
      timeoutMs: 60_001,
      fetcher,
    }),
    hasErrorCode("TIMEOUT_INVALID"),
  );
});
