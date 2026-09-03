import { z } from "zod";
import { AppError, EXIT } from "../errors.js";
import { getProviderJson } from "../http.js";
import { sanitizeSecretText } from "../sanitize.js";
import type {
  ProviderSearchHit,
  ProviderSearchPage,
  SourceDescriptor,
} from "../types.js";
import type { ProviderSearchOptions, SearchProvider } from "./provider.js";

const ResultSchema = z
  .object({
    title: z.unknown().optional(),
    url: z.unknown(),
    context: z.unknown().optional(),
    snippet: z.unknown().optional(),
    score: z.unknown().optional(),
    indexed_at: z.unknown().optional(),
    last_seen: z.unknown().optional(),
  })
  .passthrough();

const ResponseSchema = z
  .object({
    status: z.string(),
    pagination: z.record(z.string(), z.unknown()).optional(),
    results: z.array(ResultSchema),
    message: z.unknown().optional(),
  })
  .passthrough();

export const ONION_SEARCH_ENGINE_DESCRIPTOR: SourceDescriptor = {
  id: "onionsearchengine",
  name: "Onion Search Engine API",
  mode: "api",
  automated: true,
  requires_api_key: true,
  requires_tor: false,
  enabled_by_default: true,
  description: "Documented HTTPS API returning indexed Tor search results.",
  documentation_url: "https://onionsearchengine.com/api_documentation.php",
  note: "Queries and API usage are visible to this third-party provider; review its current terms before use.",
};

function optionalNumber(value: unknown): number | undefined {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string"
        ? Number(value)
        : NaN;
  return Number.isFinite(parsed) ? parsed : undefined;
}

function optionalDate(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? undefined : date.toISOString();
}

export class OnionSearchEngineProvider implements SearchProvider {
  readonly id = "onionsearchengine" as const;
  readonly descriptor = ONION_SEARCH_ENGINE_DESCRIPTOR;

  async search(
    query: string,
    options: ProviderSearchOptions,
  ): Promise<ProviderSearchPage> {
    if (!options.apiKey) {
      throw new AppError(
        "PROVIDER_API_KEY_MISSING",
        "Set DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY or use --source fixture for an offline demo.",
        EXIT.CONFIG,
      );
    }
    const apiKey = options.apiKey;

    const url = new URL("https://onionsearchengine.com/api.php");
    url.searchParams.set("q", query);
    url.searchParams.set("page", String(options.page));
    const response = await getProviderJson(url, apiKey, options.timeoutMs);
    const parsed = ResponseSchema.safeParse(response.data);
    if (!parsed.success) {
      throw new AppError(
        "PROVIDER_SCHEMA_CHANGED",
        "Provider response did not match the documented schema.",
        EXIT.SOURCE_FAILED,
      );
    }
    if (parsed.data.status.toLowerCase() !== "success") {
      const detail =
        sanitizeSecretText(parsed.data.message, [apiKey], 200) ||
        "Provider returned a non-success status.";
      throw new AppError("PROVIDER_ERROR", detail, EXIT.SOURCE_FAILED);
    }

    const hits: ProviderSearchHit[] = parsed.data.results.map((item, index) => {
      const urlValue = sanitizeSecretText(item.url, [apiKey], 2048);
      const title =
        sanitizeSecretText(item.title, [apiKey], 240) ||
        "Untitled indexed result";
      const snippet = sanitizeSecretText(
        item.context ?? item.snippet,
        [apiKey],
        600,
      );
      const score = optionalNumber(item.score);
      const indexedAt = optionalDate(item.indexed_at ?? item.last_seen);
      return {
        title,
        url: urlValue,
        snippet,
        rank: index + 1,
        ...(score === undefined ? {} : { providerScore: score }),
        ...(indexedAt === undefined ? {} : { indexedAt }),
      };
    });

    const totalPages = optionalNumber(parsed.data.pagination?.total_pages);
    const totalResults = optionalNumber(parsed.data.pagination?.total_results);
    return {
      hits,
      page: options.page,
      ...(totalPages === undefined
        ? {}
        : { totalPages: Math.max(1, Math.trunc(totalPages)) }),
      ...(totalResults === undefined
        ? {}
        : { totalResults: Math.max(0, Math.trunc(totalResults)) }),
    };
  }
}
