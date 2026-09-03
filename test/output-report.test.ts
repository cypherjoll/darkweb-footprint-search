import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { AppError } from "../src/errors.js";
import { parseOutputFormat, renderReport } from "../src/output.js";
import { readReport, writeFileExclusive } from "../src/report.js";
import { makeSearchReport } from "./helpers.js";

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof AppError && error.code === code;
}

test("base report rendering is deterministic in every machine-readable format", () => {
  const report = makeSearchReport(1);

  const json = renderReport(report, "json");
  assert.equal(json, `${JSON.stringify(report, null, 2)}\n`);
  assert.equal(renderReport(report, "json"), json);

  const records = renderReport(report, "jsonl")
    .trimEnd()
    .split("\n")
    .map((line) => JSON.parse(line) as { type: string });
  assert.deepEqual(
    records.map((record) => record.type),
    ["run", "source_status", "result", "run_end"],
  );
  assert.equal(renderReport(report, "jsonl"), renderReport(report, "jsonl"));
});

test("human and Markdown rendering have a stable minimal structure", () => {
  const report = makeSearchReport(1);
  const result = report.data.results[0];
  assert.ok(result);

  const expectedHuman = [
    "Query: APT10",
    "Results: 1 | partial: no",
    "Indexed matches are leads, not proof of authenticity or attribution.",
    "",
    `1. ${result.title}`,
    `   ${result.canonical_url}`,
    `   indexed / not verified | relevance ${result.relevance_score}`,
    `   ${result.snippet}`,
    "",
  ].join("\n");
  assert.equal(renderReport(report, "human"), expectedHuman);

  const markdown = renderReport(report, "markdown");
  assert.match(markdown, /^# Dark-web footprint search: APT10\n/);
  assert.match(markdown, /- Results: 1\n/);
  assert.match(markdown, /indexed \/ not verified/);
  assert.equal(markdown, renderReport(report, "markdown"));
});

test("Markdown rendering encodes raw HTML from untrusted result text", () => {
  const report = makeSearchReport(1);
  const result = report.data.results[0];
  assert.ok(result);
  report.run.completed_at = "<img src=https://tracker.invalid/generated>";
  result.title = "Signal <img src=https://tracker.invalid/pixel>";
  result.snippet = "Context & <script>alert(1)</script>";

  const markdown = renderReport(report, "markdown");
  assert.doesNotMatch(markdown, /<img|<script|<\/script>/i);
  assert.equal(
    markdown.includes("&lt;img src=https://tracker\\.invalid/pixel&gt;"),
    true,
  );
  assert.match(markdown, /Context &amp; &lt;script&gt;/);
});

test("output format parsing accepts the public formats and rejects unknown values", () => {
  for (const format of ["human", "json", "jsonl", "markdown"] as const) {
    assert.equal(parseOutputFormat(format), format);
  }
  assert.throws(() => parseOutputFormat("xml"), /Unsupported output format/);
});

test("reports round-trip through exclusive files and require force to overwrite", async (context) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "darkfootprint-report-test-"),
  );
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "report.json");
  const report = makeSearchReport(2);
  const serialized = renderReport(report, "json");

  assert.equal(
    await writeFileExclusive(outputPath, serialized),
    path.resolve(outputPath),
  );
  assert.deepEqual(await readReport(outputPath), report);
  await assert.rejects(
    writeFileExclusive(outputPath, "replacement"),
    hasErrorCode("OUTPUT_EXISTS"),
  );

  await writeFileExclusive(outputPath, serialized, true);
  assert.equal(await readFile(outputPath, "utf8"), serialized);
});

test("readReport wraps invalid JSON and invalid schemas as REPORT_INVALID", async (context) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "darkfootprint-invalid-report-test-"),
  );
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "invalid.json");
  await writeFileExclusive(outputPath, '{"schema_version":"0.0"}');

  await assert.rejects(readReport(outputPath), hasErrorCode("REPORT_INVALID"));
});

test("readReport rejects terminal controls in human-visible report text", async (context) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "darkfootprint-unsafe-report-test-"),
  );
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "unsafe.json");
  const report = makeSearchReport(1);
  const first = report.data.results[0];
  assert.ok(first);
  first.title =
    "Trusted title\u001b]8;;https://example.invalid\u0007click\u001b]8;;\u0007";
  await writeFileExclusive(outputPath, JSON.stringify(report));

  await assert.rejects(
    readReport(outputPath),
    hasErrorCode("REPORT_TEXT_UNSAFE"),
  );
});

test("readReport rejects undeclared report fields", async (context) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "darkfootprint-extra-report-test-"),
  );
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "extra.json");
  const report = {
    ...makeSearchReport(1),
    unexpected: "not part of schema 1.0",
  };
  await writeFileExclusive(outputPath, JSON.stringify(report));

  await assert.rejects(readReport(outputPath), hasErrorCode("REPORT_INVALID"));
});

test("readReport rejects files larger than its fixed input bound", async (context) => {
  const directory = await mkdtemp(
    path.join(tmpdir(), "darkfootprint-large-report-test-"),
  );
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "large.json");
  await writeFileExclusive(outputPath, "x".repeat(5 * 1024 * 1024 + 1));

  await assert.rejects(
    readReport(outputPath),
    hasErrorCode("REPORT_SIZE_INVALID"),
  );
});
