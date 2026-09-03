export const SCHEMA_VERSION = "1.0" as const;

export type SourceId = "fixture" | "onionsearchengine";

export interface ProviderSearchHit {
  title: string;
  url: string;
  snippet: string;
  rank: number;
  providerScore?: number;
  indexedAt?: string;
}

export interface ProviderSearchPage {
  hits: ProviderSearchHit[];
  page: number;
  totalPages?: number;
  totalResults?: number;
}

export interface SearchLimits {
  limit: number;
  max_pages: number;
  timeout_ms: number;
}

export interface SourceStatus {
  source_id: string;
  status: "ok" | "error" | "skipped";
  result_count: number;
  pages_requested: number;
  elapsed_ms: number;
  error_code?: string;
  message?: string;
}

export type VerificationState =
  | "not_requested"
  | "reachable"
  | "unreachable"
  | "blocked"
  | "invalid"
  | "parse_error";

export interface Verification {
  state: VerificationState;
  checked_at?: string;
  http_status?: number;
  content_type?: string;
  bytes_read?: number;
  elapsed_ms?: number;
  final_url?: string;
  safe_title?: string;
  raw_sha256?: string;
  text_sha256?: string;
  keyword_present?: boolean;
  evidence_snippet?: string;
  error_code?: string;
}

export interface Provenance {
  source_id: string;
  source_rank: number;
  retrieved_at: string;
  provider_score?: number;
  indexed_at?: string;
}

export interface FootprintResult {
  id: string;
  canonical_url: string;
  onion_service_id: string;
  title: string;
  snippet: string;
  relevance_score: number | null;
  provenance: Provenance[];
  verification: Verification;
}

export interface ReportIssue {
  code: string;
  message: string;
  source_id?: string;
}

export interface SearchReport {
  schema_version: typeof SCHEMA_VERSION;
  command: "search" | "onion.verify";
  ok: boolean;
  partial: boolean;
  run: {
    id: string;
    query: string;
    started_at: string;
    completed_at: string;
    sources: string[];
    limits: SearchLimits;
    index_route: "offline" | "direct" | "mixed";
  };
  data: {
    results: FootprintResult[];
    source_status: SourceStatus[];
  };
  warnings: ReportIssue[];
  errors: ReportIssue[];
}

export interface SourceDescriptor {
  id: string;
  name: string;
  mode: "api" | "offline" | "manual";
  automated: boolean;
  requires_api_key: boolean;
  requires_tor: boolean;
  enabled_by_default: boolean;
  description: string;
  documentation_url?: string;
  note?: string;
}

export interface ErrorEnvelope {
  schema_version: typeof SCHEMA_VERSION;
  command: string;
  ok: false;
  error: {
    code: string;
    message: string;
  };
}
