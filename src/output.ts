import { codeSpan, escapeMarkdown } from "./sanitize.js";
import type {
  FootprintResult,
  SearchReport,
  SourceDescriptor,
} from "./types.js";

export type OutputFormat = "human" | "json" | "jsonl" | "markdown";

export function parseOutputFormat(value: string): OutputFormat {
  if (new Set(["human", "json", "jsonl", "markdown"]).has(value))
    return value as OutputFormat;
  throw new Error(`Unsupported output format: ${value}`);
}

function verificationLabel(result: FootprintResult): string {
  if (result.verification.state === "not_requested")
    return "indexed / not verified";
  if (result.verification.state === "reachable") {
    return result.verification.keyword_present
      ? "reachable / keyword present"
      : "reachable / keyword absent";
  }
  return result.verification.state;
}

export function renderReport(
  report: SearchReport,
  format: OutputFormat,
): string {
  if (format === "json") return `${JSON.stringify(report, null, 2)}\n`;
  if (format === "jsonl") {
    const records = [
      JSON.stringify({
        type: "run",
        schema_version: report.schema_version,
        command: report.command,
        ok: report.ok,
        partial: report.partial,
        run: report.run,
      }),
      ...report.data.source_status.map((source) =>
        JSON.stringify({ type: "source_status", source }),
      ),
      ...report.data.results.map((result) =>
        JSON.stringify({ type: "result", result }),
      ),
      JSON.stringify({
        type: "run_end",
        warnings: report.warnings,
        errors: report.errors,
      }),
    ];
    return `${records.join("\n")}\n`;
  }
  if (format === "markdown") {
    const lines = [
      `# Dark-web footprint search: ${escapeMarkdown(report.run.query)}`,
      "",
      `- Run: ${codeSpan(report.run.id)}`,
      `- Generated: ${escapeMarkdown(report.run.completed_at)}`,
      `- Sources: ${report.run.sources.map(codeSpan).join(", ")}`,
      `- Results: ${report.data.results.length}`,
      `- Partial: ${report.partial ? "yes" : "no"}`,
      "",
      "> Indexed matches are investigative leads, not proof of identity, authenticity, compromise, or attribution.",
      "",
    ];
    report.data.results.forEach((result, index) => {
      lines.push(`## ${index + 1}. ${escapeMarkdown(result.title)}`);
      lines.push("");
      lines.push(`- URL: ${codeSpan(result.canonical_url)}`);
      lines.push(`- ID: ${codeSpan(result.id)}`);
      lines.push(`- State: ${verificationLabel(result)}`);
      lines.push(`- Relevance: ${result.relevance_score ?? "n/a"}`);
      if (result.snippet) {
        lines.push("");
        lines.push(escapeMarkdown(result.snippet));
      }
      lines.push("");
    });
    return `${lines.join("\n")}\n`;
  }

  const lines = [
    `Query: ${report.run.query}`,
    `Results: ${report.data.results.length} | partial: ${report.partial ? "yes" : "no"}`,
    "Indexed matches are leads, not proof of authenticity or attribution.",
  ];
  report.data.results.forEach((result, index) => {
    lines.push("");
    lines.push(`${index + 1}. ${result.title}`);
    lines.push(`   ${result.canonical_url}`);
    lines.push(
      `   ${verificationLabel(result)} | relevance ${result.relevance_score ?? "n/a"}`,
    );
    if (result.snippet) lines.push(`   ${result.snippet}`);
  });
  if (report.errors.length) {
    lines.push("");
    lines.push("Errors:");
    for (const error of report.errors)
      lines.push(
        `- ${error.source_id ?? "tool"}: ${error.code} — ${error.message}`,
      );
  }
  return `${lines.join("\n")}\n`;
}

export function renderSources(
  sources: SourceDescriptor[],
  format: "human" | "json",
): string {
  if (format === "json") {
    return `${JSON.stringify({ schema_version: "1.0", command: "sources.list", ok: true, data: { sources } }, null, 2)}\n`;
  }
  const lines = sources.map(
    (source) =>
      `${source.id.padEnd(18)} ${source.mode.padEnd(7)} ${source.automated ? "automated" : "manual   "}  ${source.description}`,
  );
  return `${lines.join("\n")}\n`;
}
