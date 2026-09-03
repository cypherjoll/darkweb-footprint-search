import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { AppError, EXIT } from "./errors.js";
import { canonicalizeOnionUrl, resultId } from "./onion.js";
import { sanitizeText } from "./sanitize.js";
import type { SearchReport } from "./types.js";

const MAX_REPORT_BYTES = 5 * 1024 * 1024;

const ProvenanceSchema = z
  .object({
    source_id: z.string().min(1),
    source_rank: z.number().int().min(1),
    retrieved_at: z.string().min(1),
    provider_score: z.number().optional(),
    indexed_at: z.string().optional(),
  })
  .strict();

const VerificationSchema = z
  .object({
    state: z.enum([
      "not_requested",
      "reachable",
      "unreachable",
      "blocked",
      "invalid",
      "parse_error",
    ]),
    checked_at: z.string().optional(),
    http_status: z.number().int().optional(),
    content_type: z.string().optional(),
    bytes_read: z.number().int().min(0).optional(),
    elapsed_ms: z.number().int().min(0).optional(),
    final_url: z.string().optional(),
    safe_title: z.string().optional(),
    raw_sha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
    text_sha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
    keyword_present: z.boolean().optional(),
    evidence_snippet: z.string().optional(),
    error_code: z.string().optional(),
  })
  .strict();

const ResultSchema = z
  .object({
    id: z.string().regex(/^dfp_[a-f0-9]{24}$/),
    canonical_url: z.string().min(1).max(4096),
    onion_service_id: z.string().regex(/^[a-z2-7]{56}$/),
    title: z.string().max(240),
    snippet: z.string().max(600),
    relevance_score: z.number().min(0).max(1).nullable(),
    provenance: z.array(ProvenanceSchema).min(1),
    verification: VerificationSchema,
  })
  .strict();

const SourceStatusSchema = z
  .object({
    source_id: z.string(),
    status: z.enum(["ok", "error", "skipped"]),
    result_count: z.number().int().min(0),
    pages_requested: z.number().int().min(0),
    elapsed_ms: z.number().int().min(0),
    error_code: z.string().optional(),
    message: z.string().optional(),
  })
  .strict();

const IssueSchema = z
  .object({
    code: z.string(),
    message: z.string(),
    source_id: z.string().optional(),
  })
  .strict();

const ReportSchema = z
  .object({
    schema_version: z.literal("1.0"),
    command: z.enum(["search", "onion.verify"]),
    ok: z.boolean(),
    partial: z.boolean(),
    run: z
      .object({
        id: z.string(),
        query: z.string(),
        started_at: z.string(),
        completed_at: z.string(),
        sources: z.array(z.string()),
        limits: z
          .object({
            limit: z.number(),
            max_pages: z.number(),
            timeout_ms: z.number(),
          })
          .strict(),
        index_route: z.enum(["offline", "direct", "mixed"]),
      })
      .strict(),
    data: z
      .object({
        results: z.array(ResultSchema).max(100),
        source_status: z.array(SourceStatusSchema).max(16),
      })
      .strict(),
    warnings: z.array(IssueSchema).max(1000),
    errors: z.array(IssueSchema).max(1000),
  })
  .strict();

export async function readReport(inputPath: string): Promise<SearchReport> {
  try {
    const resolved = path.resolve(inputPath);
    const stat = await fs.stat(resolved);
    if (!stat.isFile() || stat.size > MAX_REPORT_BYTES) {
      throw new AppError(
        "REPORT_SIZE_INVALID",
        "Report must be a regular file no larger than 5 MiB.",
        EXIT.OUTPUT,
      );
    }
    const raw = await fs.readFile(resolved, "utf8");
    const parsed = ReportSchema.parse(JSON.parse(raw));
    const canonicalText = (value: string, maxLength: number): boolean =>
      sanitizeText(value, maxLength) === value;
    const canonicalIsoDate = (value: string): boolean => {
      const timestamp = Date.parse(value);
      return (
        Number.isFinite(timestamp) &&
        new Date(timestamp).toISOString() === value
      );
    };
    if (
      !canonicalText(parsed.run.id, 128) ||
      !canonicalText(parsed.run.query, 1024) ||
      !canonicalText(parsed.run.started_at, 64) ||
      !canonicalText(parsed.run.completed_at, 64) ||
      !canonicalIsoDate(parsed.run.started_at) ||
      !canonicalIsoDate(parsed.run.completed_at) ||
      parsed.run.sources.some((source) => !canonicalText(source, 64)) ||
      Array.from(parsed.run.query).length > 256 ||
      Buffer.byteLength(parsed.run.query, "utf8") > 1024
    ) {
      throw new AppError(
        "REPORT_TEXT_UNSAFE",
        "Report query contains unsafe or non-canonical text.",
        EXIT.OUTPUT,
      );
    }
    for (const result of parsed.data.results) {
      const canonical = canonicalizeOnionUrl(result.canonical_url);
      if (
        canonical.canonicalUrl !== result.canonical_url ||
        canonical.serviceId !== result.onion_service_id ||
        resultId(canonical.canonicalUrl) !== result.id
      ) {
        throw new AppError(
          "REPORT_RESULT_TAMPERED",
          "Report contains a non-canonical or inconsistent result.",
          EXIT.OUTPUT,
        );
      }
      if (
        !canonicalText(result.title, 240) ||
        !canonicalText(result.snippet, 600) ||
        result.provenance.some(
          (item) =>
            !canonicalText(item.source_id, 64) ||
            !canonicalText(item.retrieved_at, 64) ||
            !canonicalIsoDate(item.retrieved_at) ||
            (item.indexed_at !== undefined &&
              (!canonicalText(item.indexed_at, 64) ||
                !canonicalIsoDate(item.indexed_at))),
        ) ||
        (result.verification.safe_title !== undefined &&
          !canonicalText(result.verification.safe_title, 240)) ||
        (result.verification.evidence_snippet !== undefined &&
          !canonicalText(result.verification.evidence_snippet, 400)) ||
        (result.verification.checked_at !== undefined &&
          (!canonicalText(result.verification.checked_at, 64) ||
            !canonicalIsoDate(result.verification.checked_at))) ||
        (result.verification.content_type !== undefined &&
          !canonicalText(result.verification.content_type, 128)) ||
        (result.verification.error_code !== undefined &&
          !canonicalText(result.verification.error_code, 128))
      ) {
        throw new AppError(
          "REPORT_TEXT_UNSAFE",
          "Report contains unsafe or non-canonical result text.",
          EXIT.OUTPUT,
        );
      }
      if (result.verification.final_url !== undefined) {
        const finalUrl = canonicalizeOnionUrl(result.verification.final_url);
        if (
          finalUrl.canonicalUrl !== result.verification.final_url ||
          finalUrl.hostname !== canonical.hostname
        ) {
          throw new AppError(
            "REPORT_RESULT_TAMPERED",
            "Report contains an inconsistent verification URL.",
            EXIT.OUTPUT,
          );
        }
      }
    }
    for (const status of parsed.data.source_status) {
      if (
        !canonicalText(status.source_id, 64) ||
        (status.error_code !== undefined &&
          !canonicalText(status.error_code, 128)) ||
        (status.message !== undefined && !canonicalText(status.message, 1000))
      ) {
        throw new AppError(
          "REPORT_TEXT_UNSAFE",
          "Report contains unsafe or non-canonical source status text.",
          EXIT.OUTPUT,
        );
      }
    }
    for (const issue of [...parsed.warnings, ...parsed.errors]) {
      if (
        !canonicalText(issue.code, 128) ||
        !canonicalText(issue.message, 1000) ||
        (issue.source_id !== undefined && !canonicalText(issue.source_id, 64))
      ) {
        throw new AppError(
          "REPORT_TEXT_UNSAFE",
          "Report contains unsafe or non-canonical issue text.",
          EXIT.OUTPUT,
        );
      }
    }
    return parsed as SearchReport;
  } catch (error) {
    if (error instanceof AppError) throw error;
    const message =
      error instanceof Error ? error.message : "Unknown report error";
    throw new AppError(
      "REPORT_INVALID",
      `Could not read report: ${message}`,
      EXIT.OUTPUT,
    );
  }
}

export async function writeFileExclusive(
  outputPath: string,
  content: string,
  force = false,
): Promise<string> {
  const resolved = path.resolve(outputPath);
  try {
    await fs.mkdir(path.dirname(resolved), { recursive: true });
    await fs.writeFile(resolved, content, {
      encoding: "utf8",
      flag: force ? "w" : "wx",
    });
    return resolved;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "EEXIST") {
      throw new AppError(
        "OUTPUT_EXISTS",
        `Output already exists: ${resolved}. Use --force to replace it.`,
        EXIT.OUTPUT,
      );
    }
    const message =
      error instanceof Error ? error.message : "Unknown output error";
    throw new AppError(
      "OUTPUT_WRITE_FAILED",
      `Could not write output: ${message}`,
      EXIT.OUTPUT,
    );
  }
}
