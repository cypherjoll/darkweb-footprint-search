import { createSyntheticV3OnionHost } from "../onion.js";
import { sanitizeText } from "../sanitize.js";
import type { ProviderSearchPage, SourceDescriptor } from "../types.js";
import type { ProviderSearchOptions, SearchProvider } from "./provider.js";

export const FIXTURE_DESCRIPTOR: SourceDescriptor = {
  id: "fixture",
  name: "Synthetic offline fixture",
  mode: "offline",
  automated: true,
  requires_api_key: false,
  requires_tor: false,
  enabled_by_default: false,
  description:
    "Deterministic synthetic results for demos and tests; never contacts a network.",
};

export class FixtureProvider implements SearchProvider {
  readonly id = "fixture" as const;
  readonly descriptor = FIXTURE_DESCRIPTOR;

  async search(
    query: string,
    options: ProviderSearchOptions,
  ): Promise<ProviderSearchPage> {
    const normalized = sanitizeText(query, 256);
    if (options.page !== 1)
      return { hits: [], page: options.page, totalPages: 1, totalResults: 0 };

    const hostA = createSyntheticV3OnionHost("research-forum");
    const hostB = createSyntheticV3OnionHost("paste-mirror");
    const hits = [
      {
        title: `Synthetic threat-intelligence mention: ${normalized}`,
        url: `http://${hostA}/reports/${encodeURIComponent(normalized.toLowerCase())}`,
        snippet: `Offline fixture showing how an indexed digital footprint for ${normalized} is represented. No live onion service is contacted.`,
        rank: 1,
        providerScore: 0.91,
        indexedAt: "2026-01-15T10:00:00.000Z",
      },
      {
        title: `Synthetic paste reference for ${normalized}`,
        url: `http://${hostB}/archive?id=fixture-${encodeURIComponent(normalized.toLowerCase())}`,
        snippet: `Synthetic context contains the keyword ${normalized}; this record is safe test data and not real intelligence.`,
        rank: 2,
        providerScore: 0.72,
        indexedAt: "2026-01-14T09:00:00.000Z",
      },
    ];
    return { hits, page: 1, totalPages: 1, totalResults: hits.length };
  }
}
