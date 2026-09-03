#!/usr/bin/env node

import process from "node:process";
import { Command, CommanderError, InvalidArgumentError } from "commander";
import {
  loadConfig,
  parseLoopbackSocksProxy,
  publicDefaultConfig,
  resolveConfigPath,
} from "./config.js";
import {
  AppError,
  EXIT,
  asAppError,
  errorEnvelope,
  redactSecrets,
} from "./errors.js";
import { getProviderJson, probeTcp } from "./http.js";
import { renderReport, renderSources, type OutputFormat } from "./output.js";
import { sourceDescriptors } from "./providers/registry.js";
import { readReport, writeFileExclusive } from "./report.js";
import { normalizeQuery, runSearch } from "./search.js";
import { sanitizeJsonValue, sanitizeText } from "./sanitize.js";
import { SCHEMA_VERSION, type SearchReport } from "./types.js";
import { verifyReport } from "./verify.js";

const program = new Command();

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function integer(value: string): number {
  if (!/^\d+$/.test(value))
    throw new InvalidArgumentError("Expected a positive integer.");
  return Number(value);
}

function boundedTimeout(value: number): number {
  if (!Number.isInteger(value) || value < 1000 || value > 60000) {
    throw new AppError(
      "TIMEOUT_INVALID",
      "--timeout must be between 1000 and 60000 ms.",
      EXIT.USAGE,
    );
  }
  return value;
}

function nodeVersionSupported(version: string): boolean {
  const [major = 0, minor = 0] = version.split(".").map(Number);
  return major > 22 || (major === 22 && minor >= 19);
}

function displayText(value: string, maxLength = 4096): string {
  return (
    redactSecrets(sanitizeText(value, 1_000_000)).slice(0, maxLength) ||
    "[unprintable]"
  );
}

function jsonRequested(command?: Command): boolean {
  return (
    Boolean(command?.optsWithGlobals().json) || process.argv.includes("--json")
  );
}

function formatFor(
  options: { format?: string },
  command: Command,
): OutputFormat {
  if (jsonRequested(command)) return "json";
  const value = options.format ?? "human";
  if (
    value === "human" ||
    value === "json" ||
    value === "jsonl" ||
    value === "markdown"
  )
    return value;
  throw new AppError(
    "FORMAT_INVALID",
    `Unsupported output format: ${value}.`,
    EXIT.USAGE,
  );
}

function printError(
  commandName: string,
  error: unknown,
  asJson: boolean,
): void {
  const appError = asAppError(error);
  if (asJson) {
    process.stdout.write(
      `${JSON.stringify(errorEnvelope(commandName, appError), null, 2)}\n`,
    );
  } else {
    process.stderr.write(
      `Error [${appError.code}]: ${displayText(appError.message, 2000)}\n`,
    );
  }
  process.exitCode = appError.exitCode;
}

async function guarded(
  commandName: string,
  command: Command,
  action: () => Promise<void>,
): Promise<void> {
  try {
    await action();
  } catch (error) {
    printError(commandName, error, jsonRequested(command));
  }
}

async function emitReport(
  report: SearchReport,
  format: OutputFormat,
  outputPath: string | undefined,
  force: boolean,
): Promise<void> {
  const content = renderReport(report, format);
  if (!outputPath) {
    process.stdout.write(content);
    return;
  }
  const resolved = await writeFileExclusive(outputPath, content, force);
  if (format === "json") {
    process.stdout.write(
      `${JSON.stringify({ schema_version: SCHEMA_VERSION, command: "output.write", ok: true, data: { path: resolved, result_count: report.data.results.length } }, null, 2)}\n`,
    );
  } else {
    process.stdout.write(
      `Wrote ${report.data.results.length} result(s) to ${displayText(resolved)}\n`,
    );
  }
}

function chooseExitCode(report: SearchReport, allowPartial: boolean): number {
  if (!report.ok) {
    if (
      report.errors.some(
        (issue) =>
          issue.code.includes("API_KEY") || issue.code.includes("AUTH"),
      )
    )
      return EXIT.CONFIG;
    return EXIT.SOURCE_FAILED;
  }
  if (report.partial && !allowPartial) return EXIT.PARTIAL;
  return EXIT.OK;
}

program
  .name("darkfootprint")
  .description(
    "Defensive search of indexed dark-web footprints; results are leads, not attribution.",
  )
  .version("0.1.0")
  .option("--json", "emit stable JSON to stdout")
  .showHelpAfterError();

program
  .command("doctor")
  .description(
    "Check local configuration, provider authentication, and the Tor SOCKS listener.",
  )
  .option("--config <path>", "configuration file path")
  .option("--offline", "skip even local Tor socket probing")
  .action(async (options, command: Command) => {
    await guarded("doctor", command, async () => {
      const state = await loadConfig(options.config);
      const supportedNode = nodeVersionSupported(process.versions.node);
      let proxyValid = true;
      let proxyError: string | undefined;
      let torReachable: boolean | null = null;
      try {
        const proxy = parseLoopbackSocksProxy(state.config.tor.proxy);
        if (!options.offline)
          torReachable = await probeTcp(proxy.host, proxy.port);
      } catch (error) {
        proxyValid = false;
        proxyError = asAppError(error).code;
      }
      const payload = {
        schema_version: SCHEMA_VERSION,
        command: "doctor",
        ok: proxyValid && supportedNode,
        data: {
          node: {
            version: process.version,
            supported: supportedNode,
          },
          config: {
            path: state.path,
            exists: state.exists,
            contains_secrets: false,
          },
          providers: {
            onionsearchengine: {
              enabled: state.config.providers.onionsearchengine.enabled,
              api_key: state.secrets.onionSearchEngineApiKey
                ? "available"
                : "missing",
              api_key_source: state.secrets.onionSearchEngineApiKeySource,
            },
            fixture: { enabled: true, network_required: false },
          },
          tor: {
            proxy: proxyValid ? state.config.tor.proxy : "[invalid proxy]",
            valid: proxyValid,
            reachable: torReachable,
            ...(proxyError ? { error_code: proxyError } : {}),
          },
        },
        warnings: [
          ...(state.secrets.onionSearchEngineApiKey
            ? []
            : [
                "Set DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY for live indexed search.",
              ]),
          ...(torReachable === false
            ? [
                "Tor is not reachable; indexed search still works, direct verification does not.",
              ]
            : []),
          ...(supportedNode ? [] : ["Node.js 22.19 or later is required."]),
        ],
      };
      if (jsonRequested(command))
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
      else {
        process.stdout.write(
          `Node: ${payload.data.node.version} (${payload.data.node.supported ? "supported" : "unsupported"})\n`,
        );
        process.stdout.write(
          `Config: ${displayText(state.exists ? state.path : `not found (${state.path})`)}\n`,
        );
        process.stdout.write(
          `Onion Search Engine key: ${payload.data.providers.onionsearchengine.api_key}\n`,
        );
        process.stdout.write(
          `Tor proxy: ${proxyValid ? "valid" : "invalid"}; reachable: ${torReachable === null ? "not checked" : torReachable ? "yes" : "no"}\n`,
        );
      }
      if (!proxyValid || !supportedNode) process.exitCode = EXIT.CONFIG;
    });
  });

program
  .command("init")
  .description(
    "Create a non-secret local configuration file; never stores API keys.",
  )
  .option("--config <path>", "configuration file path")
  .option("--proxy <url>", "loopback socks5h Tor proxy")
  .option("--dry-run", "print the configuration without writing it")
  .option("--force", "replace an existing configuration file")
  .action(async (options, command: Command) => {
    await guarded("init", command, async () => {
      const config = publicDefaultConfig();
      if (options.proxy) {
        parseLoopbackSocksProxy(options.proxy);
        config.tor.proxy = options.proxy;
      }
      const content = `${JSON.stringify(config, null, 2)}\n`;
      if (options.dryRun) {
        process.stdout.write(content);
        return;
      }
      const resolved = await writeFileExclusive(
        resolveConfigPath(options.config),
        content,
        Boolean(options.force),
      );
      const result = {
        schema_version: SCHEMA_VERSION,
        command: "init",
        ok: true,
        data: { path: resolved, contains_secrets: false },
      };
      process.stdout.write(
        jsonRequested(command)
          ? `${JSON.stringify(result, null, 2)}\n`
          : `Created ${displayText(resolved)}\n`,
      );
    });
  });

const sources = program
  .command("sources")
  .description("Discover available search sources and their requirements.");

sources
  .command("list")
  .description("List automated, offline, and manual sources.")
  .action(async (_options, command: Command) => {
    await guarded("sources.list", command, async () => {
      process.stdout.write(
        renderSources(
          sourceDescriptors(),
          jsonRequested(command) ? "json" : "human",
        ),
      );
    });
  });

sources
  .command("check")
  .description("Validate source prerequisites without performing a search.")
  .option("--config <path>", "configuration file path")
  .action(async (options, command: Command) => {
    await guarded("sources.check", command, async () => {
      const state = await loadConfig(options.config);
      const descriptors = sourceDescriptors().map((source) => ({
        ...source,
        ready:
          source.id === "onionsearchengine"
            ? Boolean(state.secrets.onionSearchEngineApiKey)
            : source.id === "fixture",
      }));
      const payload = {
        schema_version: SCHEMA_VERSION,
        command: "sources.check",
        ok: true,
        data: { sources: descriptors },
      };
      if (jsonRequested(command))
        process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
      else
        for (const source of descriptors)
          process.stdout.write(
            `${source.id}: ${source.ready ? "ready" : source.mode === "manual" ? "manual only" : "missing API key"}\n`,
          );
    });
  });

program
  .command("search")
  .description(
    "Search authorized indexes; never contacts result onion services unless explicitly requested.",
  )
  .argument("<keyword>", "keyword or phrase to search")
  .option("-s, --source <id>", "source id (repeatable)", collect, [])
  .option("--limit <n>", "maximum normalized results (1-100)", integer)
  .option("--max-pages <n>", "maximum provider pages (1-5)", integer)
  .option("--timeout <ms>", "per-request timeout in milliseconds", integer)
  .option("--config <path>", "configuration file path")
  .option("--format <format>", "human, json, jsonl, or markdown", "human")
  .option("--out <path>", "write output to a new file")
  .option("--force", "replace an existing output file")
  .option("--allow-partial", "exit zero when at least one source succeeds")
  .option(
    "--verify-onion",
    "after indexed search, verify a bounded subset through Tor",
  )
  .option("--max-verify <n>", "maximum onion results to verify (1-20)", integer)
  .option("--proxy <url>", "loopback socks5h Tor proxy")
  .option(
    "--acknowledge-risk",
    "confirm that direct onion verification may expose harmful content",
  )
  .action(async (keyword: string, options, command: Command) => {
    await guarded("search", command, async () => {
      const state = await loadConfig(options.config);
      const report = await runSearch(keyword, {
        sources: options.source as string[],
        limit: options.limit ?? state.config.limits.result_limit,
        maxPages: options.maxPages ?? state.config.limits.max_pages,
        timeoutMs: options.timeout ?? state.config.limits.timeout_ms,
        configState: state,
      });
      let finalReport = report;
      if (options.verifyOnion) {
        if (!options.acknowledgeRisk) {
          throw new AppError(
            "RISK_ACK_REQUIRED",
            "Use --acknowledge-risk with --verify-onion.",
            EXIT.POLICY,
          );
        }
        finalReport = await verifyReport(report, {
          proxy: options.proxy ?? state.config.tor.proxy,
          max: options.maxVerify ?? state.config.limits.max_verify,
          timeoutMs: options.timeout ?? state.config.limits.timeout_ms,
        });
      }
      await emitReport(
        finalReport,
        formatFor(options, command),
        options.out,
        Boolean(options.force),
      );
      process.exitCode = chooseExitCode(
        finalReport,
        Boolean(options.allowPartial),
      );
    });
  });

const onion = program
  .command("onion")
  .description("Explicit, bounded Tor verification of prior search results.");

onion
  .command("verify")
  .description(
    "Verify results from a report through a loopback Tor SOCKS proxy.",
  )
  .requiredOption("--input <path>", "JSON search report")
  .option("--max <n>", "maximum results to verify (1-20)", integer)
  .option("--timeout <ms>", "per-request timeout in milliseconds", integer)
  .option("--config <path>", "configuration file path")
  .option("--proxy <url>", "loopback socks5h Tor proxy")
  .option("--format <format>", "human, json, jsonl, or markdown", "human")
  .option("--out <path>", "write output to a new file")
  .option("--force", "replace an existing output file")
  .requiredOption(
    "--acknowledge-risk",
    "confirm that direct onion verification may expose harmful content",
  )
  .action(async (options, command: Command) => {
    await guarded("onion.verify", command, async () => {
      const state = await loadConfig(options.config);
      const report = await readReport(options.input);
      const verified = await verifyReport(report, {
        proxy: options.proxy ?? state.config.tor.proxy,
        max: options.max ?? state.config.limits.max_verify,
        timeoutMs: options.timeout ?? state.config.limits.timeout_ms,
      });
      await emitReport(
        verified,
        formatFor(options, command),
        options.out,
        Boolean(options.force),
      );
      process.exitCode = chooseExitCode(verified, false);
    });
  });

const results = program
  .command("results")
  .description("Inspect or export a previously saved JSON report.");

results
  .command("show")
  .description("Show one normalized result by stable ID.")
  .argument("<result-id>", "stable dfp_ result ID")
  .requiredOption("--input <path>", "JSON report")
  .action(async (resultId: string, options, command: Command) => {
    await guarded("results.show", command, async () => {
      const report = await readReport(options.input);
      const result = report.data.results.find((item) => item.id === resultId);
      if (!result)
        throw new AppError(
          "RESULT_NOT_FOUND",
          `Result not found: ${resultId}.`,
          EXIT.USAGE,
        );
      if (jsonRequested(command)) {
        process.stdout.write(
          `${JSON.stringify({ schema_version: SCHEMA_VERSION, command: "results.show", ok: true, data: { result } }, null, 2)}\n`,
        );
      } else {
        process.stdout.write(
          `${result.title}\n${result.canonical_url}\n${result.snippet}\nState: ${result.verification.state}\n`,
        );
      }
    });
  });

results
  .command("export")
  .description("Convert a saved JSON report to JSONL or Markdown.")
  .requiredOption("--input <path>", "JSON report")
  .requiredOption("--out <path>", "new output file")
  .requiredOption("--format <format>", "jsonl or markdown")
  .option("--force", "replace an existing output file")
  .action(async (options, command: Command) => {
    await guarded("results.export", command, async () => {
      if (options.format !== "jsonl" && options.format !== "markdown") {
        throw new AppError(
          "FORMAT_INVALID",
          "Export format must be jsonl or markdown.",
          EXIT.USAGE,
        );
      }
      const report = await readReport(options.input);
      const resolved = await writeFileExclusive(
        options.out,
        renderReport(report, options.format),
        Boolean(options.force),
      );
      const payload = {
        schema_version: SCHEMA_VERSION,
        command: "results.export",
        ok: true,
        data: { path: resolved, format: options.format },
      };
      process.stdout.write(
        jsonRequested(command)
          ? `${JSON.stringify(payload, null, 2)}\n`
          : `Exported ${displayText(resolved)}\n`,
      );
    });
  });

const request = program
  .command("request")
  .description(
    "Read-only provider escape hatch with fixed origin and parameters.",
  );

request
  .command("get")
  .description(
    "Issue one raw GET to the documented Onion Search Engine search endpoint.",
  )
  .requiredOption("--source <id>", "must be onionsearchengine")
  .requiredOption("--query <keyword>", "search query")
  .option("--page <n>", "page number", integer, 1)
  .option("--timeout <ms>", "request timeout in milliseconds", integer)
  .option("--config <path>", "configuration file path")
  .action(async (options, command: Command) => {
    await guarded("request.get", command, async () => {
      if (options.source !== "onionsearchengine") {
        throw new AppError(
          "SOURCE_UNKNOWN",
          "Raw requests are supported only for onionsearchengine.",
          EXIT.USAGE,
        );
      }
      if (options.page < 1 || options.page > 5)
        throw new AppError(
          "PAGE_INVALID",
          "--page must be between 1 and 5.",
          EXIT.USAGE,
        );
      const query = normalizeQuery(options.query);
      const state = await loadConfig(options.config);
      const key = state.secrets.onionSearchEngineApiKey;
      if (!key)
        throw new AppError(
          "PROVIDER_API_KEY_MISSING",
          "Set DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY.",
          EXIT.CONFIG,
        );
      const url = new URL("https://onionsearchengine.com/api.php");
      url.searchParams.set("q", query);
      url.searchParams.set("page", String(options.page));
      const response = await getProviderJson(
        url,
        key,
        boundedTimeout(options.timeout ?? state.config.limits.timeout_ms),
      );
      const payload = {
        schema_version: SCHEMA_VERSION,
        command: "request.get",
        ok: true,
        data: sanitizeJsonValue(response.data, [key]),
        meta: {
          status: response.status,
          headers: sanitizeJsonValue(response.headers, [key]),
          elapsed_ms: response.elapsedMs,
        },
      };
      process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    });
  });

program.exitOverride();

try {
  await program.parseAsync(process.argv);
} catch (error) {
  if (error instanceof CommanderError) {
    if (
      error.code === "commander.helpDisplayed" ||
      error.code === "commander.version"
    ) {
      process.exitCode = EXIT.OK;
    } else {
      printError(
        "cli",
        new AppError("USAGE_ERROR", error.message, EXIT.USAGE),
        process.argv.includes("--json"),
      );
    }
  } else {
    printError("cli", error, process.argv.includes("--json"));
  }
}
