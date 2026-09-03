import type {
  ProviderSearchPage,
  SourceDescriptor,
  SourceId,
} from "../types.js";

export interface ProviderSearchOptions {
  page: number;
  timeoutMs: number;
  apiKey?: string;
}

export interface SearchProvider {
  readonly id: SourceId;
  readonly descriptor: SourceDescriptor;
  search(
    query: string,
    options: ProviderSearchOptions,
  ): Promise<ProviderSearchPage>;
}
