import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";
import type { ConfigState } from "./config.js";
import { AppError, EXIT, redactSecrets } from "./errors.js";
import { canonicalizeOnionUrl, resultId } from "./onion.js";
import { createProvider, isSourceId } from "./providers/registry.js";
import {
  sanitizeQuery,
  sanitizeText,
  stripTerminalControls,
} from "./sanitize.js";
import {
  SCHEMA_VERSION,
  type FootprintResult,
  type ProviderSearchHit,
  type Provenance,
  type ReportIssue,
  type SearchLimits,
  type SearchReport,
  type SourceStatus,
} from "./types.js";

export interface RunSearchOptions {
  sources: string[];
  limit: number;
  maxPages: number;
  timeoutMs: number;
  configState: ConfigState;
  now?: () => Date;
}

interface ProviderOutcome {
  sourceId: string;
  status: SourceStatus;
  results: FootprintResult[];
  warnings: ReportIssue[];
  errors: ReportIssue[];
}

export function normalizeQuery(raw: string): string {
  if (stripTerminalControls(raw) !== raw) {
    throw new AppError(
      "QUERY_CONTROL_CHAR",
      "Query contains terminal or bidirectional control characters.",
      EXIT.USAGE,
    );
  }
  const query = sanitizeQuery(raw);
  if (!query)
    throw new AppError("QUERY_EMPTY", "Query must not be empty.", EXIT.USAGE);
  if (
    Array.from(query).length > 256 ||
    Buffer.byteLength(query, "utf8") > 1024
  ) {
    throw new AppError(
      "QUERY_TOO_LONG",
      "Query must be at most 256 characters and 1 KiB.",
      EXIT.USAGE,
    );
  }
  return query;
}

function normalizedProviderScore(value: number | undefined): number | null {
  if (value === undefined || !Number.isFinite(value)) return null;
  const normalized = value > 1 ? value / 100 : value;
  return Math.round(Math.max(0, Math.min(1, normalized)) * 1000) / 1000;
}

function inferredScore(query: string, hit: ProviderSearchHit): number {
  const needle = query.toLocaleLowerCase("en-US");
  const title = hit.title.toLocaleLowerCase("en-US");
  const snippet = hit.snippet.toLocaleLowerCase("en-US");
  let score = 0.1 + 0.25 / Math.max(1, hit.rank);
  if (title.includes(needle)) score += 0.4;
  if (snippet.includes(needle)) score += 0.25;
  return Math.round(Math.min(1, score) * 1000) / 1000;
}

function toResult(
  query: string,
  sourceId: string,
  hit: ProviderSearchHit,
  retrievedAt: string,
): FootprintResult {
  const onion = canonicalizeOnionUrl(hit.url);
  const providerScore = normalizedProviderScore(hit.providerScore);
  const provenance: Provenance = {
    source_id: sourceId,
    source_rank: hit.rank,
    retrieved_at: retrievedAt,
    ...(hit.providerScore === undefined
      ? {}
      : { provider_score: hit.providerScore }),
    ...(hit.indexedAt === undefined ? {} : { indexed_at: hit.indexedAt }),
  };
  return {
    id: resultId(onion.canonicalUrl),
    canonical_url: onion.canonicalUrl,
    onion_service_id: onion.serviceId,
    title: sanitizeText(hit.title, 240) || "Untitled indexed result",
    snippet: sanitizeText(hit.snippet, 600),
    relevance_score: providerScore ?? inferredScore(query, hit),
    provenance: [provenance],
    verification: { state: "not_requested" },
  };
}

function mergeResult(
  existing: FootprintResult,
  incoming: FootprintResult,
): FootprintResult {
  const existingScore = existing.relevance_score ?? 0;
  const incomingScore = incoming.relevance_score ?? 0;
  const preferred = incomingScore > existingScore ? incoming : existing;
  const provenance = [...existing.provenance, ...incoming.provenance].sort(
    (a, b) =>
      a.source_id.localeCompare(b.source_id) || a.source_rank - b.source_rank,
  );
  return {
    ...preferred,
    id: existing.id,
    canonical_url: existing.canonical_url,
    onion_service_id: existing.onion_service_id,
    relevance_score: Math.max(existingScore, incomingScore),
    provenance,
    verification: existing.verification,
  };
}

export async function runSearch(
  rawQuery: string,
  options: RunSearchOptions,
): Promise<SearchReport> {
  const query = normalizeQuery(rawQuery);
  if (
    !Number.isInteger(options.limit) ||
    options.limit < 1 ||
    options.limit > 100
  ) {
    throw new AppError(
      "LIMIT_INVALID",
      "--limit must be between 1 and 100.",
      EXIT.USAGE,
    );
  }
  if (
    !Number.isInteger(options.maxPages) ||
    options.maxPages < 1 ||
    options.maxPages > 5
  ) {
    throw new AppError(
      "MAX_PAGES_INVALID",
      "--max-pages must be between 1 and 5.",
      EXIT.USAGE,
    );
  }
  if (
    !Number.isInteger(options.timeoutMs) ||
    options.timeoutMs < 1000 ||
    options.timeoutMs > 60000
  ) {
    throw new AppError(
      "TIMEOUT_INVALID",
      "--timeout must be between 1000 and 60000 ms.",
      EXIT.USAGE,
    );
  }

  const defaultSources = options.configState.config.providers.onionsearchengine
    .enabled
    ? ["onionsearchengine"]
    : [];
  const sourceIds = [
    ...new Set(options.sources.length ? options.sources : defaultSources),
  ];
  if (sourceIds.length === 0) {
    throw new AppError(
      "NO_SOURCE_ENABLED",
      "No search source is enabled; enable onionsearchengine or pass --source explicitly.",
      EXIT.CONFIG,
    );
  }
  for (const sourceId of sourceIds) {
    if (!isSourceId(sourceId)) {
      throw new AppError(
        "SOURCE_UNKNOWN",
        `Unknown or non-automated source: ${sourceId}.`,
        EXIT.USAGE,
      );
    }
  }
  const usesApi = sourceIds.includes("onionsearchengine");
  const usesOffline = sourceIds.includes("fixture");
  const indexRoute =
    usesApi && usesOffline ? "mixed" : usesApi ? "direct" : "offline";

  const now = options.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const warnings: ReportIssue[] = [
    {
      code: "INDEX_RESULTS_UNVERIFIED",
      message:
        "Indexed matches are leads, not proof of authenticity or attribution.",
    },
    ...(usesApi
      ? [
          {
            code: "QUERY_DISCLOSURE",
            message:
              "API providers can observe search terms; do not submit personal or secret data.",
          },
        ]
      : []),
  ];
  const outcomes = await Promise.all(
    sourceIds.map(async (sourceId): Promise<ProviderOutcome> => {
      const provider = createProvider(sourceId);
      if (!provider) {
        throw new AppError(
          "SOURCE_UNKNOWN",
          `Unknown source: ${sourceId}.`,
          EXIT.USAGE,
        );
      }
      const started = performance.now();
      let pagesRequested = 0;
      let accepted = 0;
      const localResults = new Map<string, FootprintResult>();
      const localWarnings: ReportIssue[] = [];
      try {
        for (
          let page = 1;
          page <= options.maxPages && localResults.size < options.limit;
          page += 1
        ) {
          pagesRequested += 1;
          const apiKey =
            provider.id === "onionsearchengine"
              ? options.configState.secrets.onionSearchEngineApiKey
              : undefined;
          const response = await provider.search(query, {
            page,
            timeoutMs: options.timeoutMs,
            ...(apiKey ? { apiKey } : {}),
          });
          const retrievedAt = now().toISOString();
          for (const hit of response.hits) {
            if (localResults.size >= options.limit) break;
            try {
              const result = toResult(query, sourceId, hit, retrievedAt);
              const existing = localResults.get(result.canonical_url);
              localResults.set(
                result.canonical_url,
                existing ? mergeResult(existing, result) : result,
              );
              accepted += 1;
            } catch (error) {
              const appError = error instanceof AppError ? error : undefined;
              localWarnings.push({
                code: appError?.code ?? "RESULT_REJECTED",
                message:
                  "A provider result was rejected because it was not a valid v3 onion URL.",
                source_id: sourceId,
              });
            }
          }
          if (
            !response.totalPages ||
            page >= response.totalPages ||
            response.hits.length === 0
          )
            break;
        }
        return {
          sourceId,
          status: {
            source_id: sourceId,
            status: "ok",
            result_count: accepted,
            pages_requested: pagesRequested,
            elapsed_ms: Math.round(performance.now() - started),
          },
          results: [...localResults.values()],
          warnings: localWarnings,
          errors: [],
        };
      } catch (error) {
        const appError =
          error instanceof AppError
            ? error
            : new AppError(
                "SOURCE_FAILED",
                "Source failed.",
                EXIT.SOURCE_FAILED,
              );
        const message = redactSecrets(appError.message);
        return {
          sourceId,
          status: {
            source_id: sourceId,
            status: "error",
            result_count: accepted,
            pages_requested: pagesRequested,
            elapsed_ms: Math.round(performance.now() - started),
            error_code: appError.code,
            message,
          },
          results: [...localResults.values()],
          warnings: localWarnings,
          errors: [{ code: appError.code, message, source_id: sourceId }],
        };
      }
    }),
  );

  const collected = new Map<string, FootprintResult>();
  const sourceStatus: SourceStatus[] = [];
  const errors: ReportIssue[] = [];
  for (const outcome of outcomes.sort((a, b) =>
    a.sourceId.localeCompare(b.sourceId),
  )) {
    sourceStatus.push(outcome.status);
    warnings.push(...outcome.warnings);
    errors.push(...outcome.errors);
    for (const result of outcome.results) {
      const existing = collected.get(result.canonical_url);
      collected.set(
        result.canonical_url,
        existing ? mergeResult(existing, result) : result,
      );
    }
  }

  const successfulSources = sourceStatus.filter(
    (status) => status.status === "ok",
  ).length;
  const failedSources = sourceStatus.filter(
    (status) => status.status === "error",
  ).length;
  const partial = successfulSources > 0 && failedSources > 0;
  const ok = successfulSources > 0;
  const limits: SearchLimits = {
    limit: options.limit,
    max_pages: options.maxPages,
    timeout_ms: options.timeoutMs,
  };
  const results = [...collected.values()]
    .sort(
      (a, b) =>
        (b.relevance_score ?? 0) - (a.relevance_score ?? 0) ||
        a.canonical_url.localeCompare(b.canonical_url),
    )
    .slice(0, options.limit);

  return {
    schema_version: SCHEMA_VERSION,
    command: "search",
    ok,
    partial,
    run: {
      id: `run_${randomUUID()}`,
      query,
      started_at: startedAt,
      completed_at: now().toISOString(),
      sources: sourceIds,
      limits,
      index_route: indexRoute,
    },
    data: { results, source_status: sourceStatus },
    warnings,
    errors,
  };
}
