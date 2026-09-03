import { resultId, createSyntheticV3OnionHost } from "../src/onion.js";
import type { FootprintResult, SearchReport } from "../src/types.js";

const STARTED_AT = "2026-01-20T10:00:00.000Z";
const COMPLETED_AT = "2026-01-20T10:00:01.000Z";

export function makeSyntheticResult(index: number): FootprintResult {
  const hostname = createSyntheticV3OnionHost(`test-result-${index}`);
  const canonicalUrl = `http://${hostname}/evidence/${index}`;
  return {
    id: resultId(canonicalUrl),
    canonical_url: canonicalUrl,
    onion_service_id: hostname.slice(0, -6),
    title: `Synthetic APT10 result ${index}`,
    snippet: `Offline evidence fixture ${index} mentioning APT10.`,
    relevance_score: Math.max(0, 0.9 - index / 10),
    provenance: [
      {
        source_id: "fixture",
        source_rank: index,
        retrieved_at: COMPLETED_AT,
        provider_score: Math.max(0, 0.9 - index / 10),
      },
    ],
    verification: { state: "not_requested" },
  };
}

export function makeSearchReport(resultCount = 1): SearchReport {
  return {
    schema_version: "1.0",
    command: "search",
    ok: true,
    partial: false,
    run: {
      id: "run_fixture_0001",
      query: "APT10",
      started_at: STARTED_AT,
      completed_at: COMPLETED_AT,
      sources: ["fixture"],
      limits: { limit: 10, max_pages: 1, timeout_ms: 5_000 },
      index_route: "offline",
    },
    data: {
      results: Array.from({ length: resultCount }, (_, index) =>
        makeSyntheticResult(index + 1),
      ),
      source_status: [
        {
          source_id: "fixture",
          status: "ok",
          result_count: resultCount,
          pages_requested: 1,
          elapsed_ms: 0,
        },
      ],
    },
    warnings: [
      {
        code: "INDEX_RESULTS_UNVERIFIED",
        message: "Synthetic indexed matches are investigative leads only.",
      },
    ],
    errors: [],
  };
}
