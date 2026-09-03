import { createHash } from "node:crypto";
import * as cheerio from "cheerio";
import type { CheerioAPI } from "cheerio";
import { parseLoopbackSocksProxy } from "./config.js";
import { AppError, EXIT, asAppError } from "./errors.js";
import { getOnionText, probeTcp, type OnionTextResponse } from "./http.js";
import { sanitizeText } from "./sanitize.js";
import type { FootprintResult, SearchReport, Verification } from "./types.js";

export interface VerifyOptions {
  proxy: string;
  max: number;
  timeoutMs: number;
  now?: () => Date;
  fetcher?: (
    url: string,
    proxy: string,
    timeoutMs: number,
  ) => Promise<OnionTextResponse>;
}

export function extractSafeText(
  body: Buffer,
  contentType: string,
  query: string,
): {
  title: string;
  text: string;
  keywordPresent: boolean;
  evidenceSnippet: string;
} {
  let title = "";
  let text = "";
  if (contentType === "text/plain") {
    text = sanitizeText(body.toString("utf8"), 100_000);
  } else {
    let $: CheerioAPI;
    try {
      $ = cheerio.loadBuffer(body);
    } catch {
      throw new AppError(
        "ONION_PARSE_ERROR",
        "Could not parse onion HTML safely.",
        EXIT.POLICY,
      );
    }
    $("script,style,noscript,svg,iframe,object,embed,form").remove();
    title = sanitizeText($("title").first().text(), 240);
    text = sanitizeText($("body").text(), 100_000);
  }
  const needle = query.toLocaleLowerCase("en-US");
  const haystack = text.toLocaleLowerCase("en-US");
  const index = haystack.indexOf(needle);
  const start = Math.max(0, index - 160);
  const end = index < 0 ? 0 : Math.min(text.length, index + query.length + 160);
  return {
    title,
    text,
    keywordPresent: index >= 0,
    evidenceSnippet:
      index >= 0 ? sanitizeText(text.slice(start, end), 400) : "",
  };
}

async function verifyOne(
  result: FootprintResult,
  report: SearchReport,
  options: VerifyOptions,
): Promise<FootprintResult> {
  const fetcher = options.fetcher ?? getOnionText;
  const now = options.now ?? (() => new Date());
  try {
    const response = await fetcher(
      result.canonical_url,
      options.proxy,
      options.timeoutMs,
    );
    const extracted = extractSafeText(
      response.body,
      response.contentType,
      report.run.query,
    );
    const verification: Verification = {
      state: "reachable",
      checked_at: now().toISOString(),
      http_status: response.status,
      content_type: response.contentType,
      bytes_read: response.body.length,
      elapsed_ms: response.elapsedMs,
      final_url: response.finalUrl,
      ...(extracted.title ? { safe_title: extracted.title } : {}),
      raw_sha256: createHash("sha256").update(response.body).digest("hex"),
      text_sha256: createHash("sha256").update(extracted.text).digest("hex"),
      keyword_present: extracted.keywordPresent,
      ...(extracted.evidenceSnippet
        ? { evidence_snippet: extracted.evidenceSnippet }
        : {}),
    };
    return { ...result, verification };
  } catch (error) {
    const appError = asAppError(error);
    const blockedCodes = new Set([
      "INVALID_ONION_URL",
      "CONTENT_TYPE_BLOCKED",
      "RESPONSE_TOO_LARGE",
      "CROSS_ONION_REDIRECT_BLOCKED",
      "TOO_MANY_REDIRECTS",
    ]);
    return {
      ...result,
      verification: {
        state: blockedCodes.has(appError.code)
          ? "blocked"
          : appError.code === "ONION_PARSE_ERROR"
            ? "parse_error"
            : "unreachable",
        checked_at: now().toISOString(),
        error_code: appError.code,
      },
    };
  }
}

export async function verifyReport(
  report: SearchReport,
  options: VerifyOptions,
): Promise<SearchReport> {
  if (!Number.isInteger(options.max) || options.max < 1 || options.max > 20) {
    throw new AppError(
      "MAX_VERIFY_INVALID",
      "--max must be between 1 and 20.",
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
  const proxy = parseLoopbackSocksProxy(options.proxy);
  if (!options.fetcher && !(await probeTcp(proxy.host, proxy.port, 1000))) {
    throw new AppError(
      "TOR_UNAVAILABLE",
      `No Tor SOCKS listener is reachable on ${proxy.host}:${proxy.port}.`,
      EXIT.CONFIG,
    );
  }

  const selected = report.data.results.slice(0, options.max);
  const updated = new Map<string, FootprintResult>();
  for (let index = 0; index < selected.length; index += 2) {
    const batch = selected.slice(index, index + 2);
    const verified = await Promise.all(
      batch.map((result) => verifyOne(result, report, options)),
    );
    for (const result of verified) updated.set(result.id, result);
  }

  const results = report.data.results.map(
    (result) => updated.get(result.id) ?? result,
  );
  const failed = [...updated.values()].filter(
    (result) => result.verification.state !== "reachable",
  ).length;
  const nextWarnings = [...report.warnings];
  if (failed) {
    nextWarnings.push({
      code: "ONION_VERIFICATION_PARTIAL",
      message: `${failed} selected onion result(s) could not be safely verified.`,
    });
  }
  const now = options.now ?? (() => new Date());
  return {
    ...report,
    command: "onion.verify",
    partial: report.partial || failed > 0,
    run: { ...report.run, completed_at: now().toISOString() },
    data: { ...report.data, results },
    warnings: nextWarnings,
  };
}
