import assert from "node:assert/strict";
import test from "node:test";
import { publicDefaultConfig, type ConfigState } from "../src/config.js";
import { AppError } from "../src/errors.js";
import { isValidV3OnionHost, resultId } from "../src/onion.js";
import { FixtureProvider } from "../src/providers/fixture.js";
import {
  normalizeQuery,
  runSearch,
  type RunSearchOptions,
} from "../src/search.js";

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof AppError && error.code === code;
}

const configState: ConfigState = {
  config: publicDefaultConfig(),
  path: "synthetic-test-config.json",
  exists: false,
  secrets: { onionSearchEngineApiKeySource: "missing" },
};

function fixtureOptions(
  overrides: Partial<RunSearchOptions> = {},
): RunSearchOptions {
  return {
    sources: ["fixture"],
    limit: 10,
    maxPages: 1,
    timeoutMs: 5_000,
    configState,
    now: () => new Date("2026-01-20T10:00:00.000Z"),
    ...overrides,
  };
}

test("normalizeQuery applies Unicode normalization and collapses harmless whitespace", () => {
  assert.equal(
    normalizeQuery("  ＡＰＴ１０\n\t intelligence  "),
    "APT10 intelligence",
  );
  assert.equal(normalizeQuery("x".repeat(256)), "x".repeat(256));
});

test("normalizeQuery rejects empty, oversized, ANSI, control, and bidi input", () => {
  assert.throws(() => normalizeQuery(" \n\t "), hasErrorCode("QUERY_EMPTY"));
  assert.throws(
    () => normalizeQuery("x".repeat(257)),
    hasErrorCode("QUERY_TOO_LONG"),
  );
  assert.throws(
    () => normalizeQuery("\u001b[31mAPT10\u001b[0m"),
    hasErrorCode("QUERY_CONTROL_CHAR"),
  );
  assert.throws(
    () => normalizeQuery("APT\u000010"),
    hasErrorCode("QUERY_CONTROL_CHAR"),
  );
  assert.throws(
    () => normalizeQuery("APT10\u202ereversed"),
    hasErrorCode("QUERY_CONTROL_CHAR"),
  );
});

test("FixtureProvider returns only deterministic synthetic v3 onion hits", async () => {
  const provider = new FixtureProvider();
  const first = await provider.search("APT10", { page: 1, timeoutMs: 1_000 });
  const repeated = await provider.search("APT10", {
    page: 1,
    timeoutMs: 1_000,
  });

  assert.deepEqual(repeated, first);
  assert.equal(first.hits.length, 2);
  assert.equal(first.totalPages, 1);
  for (const hit of first.hits) {
    const hostname = new URL(hit.url).hostname;
    assert.equal(isValidV3OnionHost(hostname), true);
    assert.match(hit.title, /APT10/);
    assert.match(hit.snippet, /Synthetic|fixture/i);
  }

  const laterPage = await provider.search("APT10", {
    page: 2,
    timeoutMs: 1_000,
  });
  assert.deepEqual(laterPage.hits, []);
  assert.equal(laterPage.totalResults, 0);
});

test("runSearch produces stable synthetic findings without a network source", async () => {
  const report = await runSearch(
    "  APT10  ",
    fixtureOptions({ sources: ["fixture", "fixture"] }),
  );

  assert.equal(report.ok, true);
  assert.equal(report.partial, false);
  assert.equal(report.run.query, "APT10");
  assert.equal(report.run.index_route, "offline");
  assert.deepEqual(report.run.sources, ["fixture"]);
  assert.equal(report.data.source_status.length, 1);
  assert.equal(report.data.source_status[0]?.source_id, "fixture");
  assert.equal(report.data.source_status[0]?.result_count, 2);
  assert.deepEqual(
    report.data.results.map((item) => item.relevance_score),
    [0.91, 0.72],
  );
  for (const item of report.data.results) {
    assert.equal(
      isValidV3OnionHost(new URL(item.canonical_url).hostname),
      true,
    );
    assert.equal(item.id, resultId(item.canonical_url));
    assert.deepEqual(item.verification, { state: "not_requested" });
  }
  assert.equal(
    report.warnings.some((warning) => warning.code === "QUERY_DISCLOSURE"),
    false,
  );
});

test("runSearch enforces bounded search controls before contacting a provider", async () => {
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ limit: 0 })),
    hasErrorCode("LIMIT_INVALID"),
  );
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ limit: 101 })),
    hasErrorCode("LIMIT_INVALID"),
  );
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ maxPages: 0 })),
    hasErrorCode("MAX_PAGES_INVALID"),
  );
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ maxPages: 6 })),
    hasErrorCode("MAX_PAGES_INVALID"),
  );
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ timeoutMs: 999 })),
    hasErrorCode("TIMEOUT_INVALID"),
  );
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ timeoutMs: 60_001 })),
    hasErrorCode("TIMEOUT_INVALID"),
  );
  await assert.rejects(
    runSearch("APT10", fixtureOptions({ sources: ["ahmia-manual"] })),
    hasErrorCode("SOURCE_UNKNOWN"),
  );
});

test("runSearch honors a disabled default live source while allowing an explicit source", async () => {
  const disabledConfig: ConfigState = {
    ...configState,
    config: {
      ...configState.config,
      providers: { onionsearchengine: { enabled: false } },
    },
  };

  await assert.rejects(
    runSearch(
      "APT10",
      fixtureOptions({ sources: [], configState: disabledConfig }),
    ),
    hasErrorCode("NO_SOURCE_ENABLED"),
  );

  const report = await runSearch(
    "APT10",
    fixtureOptions({ sources: ["fixture"], configState: disabledConfig }),
  );
  assert.equal(report.ok, true);
  assert.deepEqual(report.run.sources, ["fixture"]);
});
