import { promises as fs } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { z } from "zod";
import { AppError, EXIT } from "./errors.js";

const PartialConfigSchema = z
  .object({
    schema_version: z.literal(1).optional(),
    providers: z
      .object({
        onionsearchengine: z
          .object({ enabled: z.boolean().optional() })
          .strict()
          .optional(),
      })
      .strict()
      .optional(),
    tor: z.object({ proxy: z.string().optional() }).strict().optional(),
    limits: z
      .object({
        result_limit: z.number().int().min(1).max(100).optional(),
        max_pages: z.number().int().min(1).max(5).optional(),
        timeout_ms: z.number().int().min(1000).max(60000).optional(),
        max_verify: z.number().int().min(1).max(20).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export interface AppConfig {
  schema_version: 1;
  providers: {
    onionsearchengine: { enabled: boolean };
  };
  tor: { proxy: string };
  limits: {
    result_limit: number;
    max_pages: number;
    timeout_ms: number;
    max_verify: number;
  };
}

export interface ConfigState {
  config: AppConfig;
  path: string;
  exists: boolean;
  secrets: {
    onionSearchEngineApiKey?: string;
    onionSearchEngineApiKeySource: "env" | "missing";
  };
}

export const DEFAULT_CONFIG: AppConfig = {
  schema_version: 1,
  providers: { onionsearchengine: { enabled: true } },
  tor: { proxy: "socks5h://127.0.0.1:9050" },
  limits: {
    result_limit: 25,
    max_pages: 1,
    timeout_ms: 15000,
    max_verify: 5,
  },
};

export function defaultConfigPath(): string {
  return path.join(homedir(), ".darkfootprint", "config.json");
}

export function resolveConfigPath(explicitPath?: string): string {
  return path.resolve(
    explicitPath ?? process.env.DARKFOOTPRINT_CONFIG ?? defaultConfigPath(),
  );
}

function mergeConfig(partial: z.infer<typeof PartialConfigSchema>): AppConfig {
  return {
    schema_version: 1,
    providers: {
      onionsearchengine: {
        enabled:
          partial.providers?.onionsearchengine?.enabled ??
          DEFAULT_CONFIG.providers.onionsearchengine.enabled,
      },
    },
    tor: {
      proxy:
        process.env.DARKFOOTPRINT_TOR_PROXY ??
        partial.tor?.proxy ??
        DEFAULT_CONFIG.tor.proxy,
    },
    limits: {
      result_limit:
        partial.limits?.result_limit ?? DEFAULT_CONFIG.limits.result_limit,
      max_pages: partial.limits?.max_pages ?? DEFAULT_CONFIG.limits.max_pages,
      timeout_ms:
        partial.limits?.timeout_ms ?? DEFAULT_CONFIG.limits.timeout_ms,
      max_verify:
        partial.limits?.max_verify ?? DEFAULT_CONFIG.limits.max_verify,
    },
  };
}

export async function loadConfig(explicitPath?: string): Promise<ConfigState> {
  const configPath = resolveConfigPath(explicitPath);
  let parsed: z.infer<typeof PartialConfigSchema> = {};
  let exists = false;

  try {
    const raw = await fs.readFile(configPath, "utf8");
    exists = true;
    parsed = PartialConfigSchema.parse(JSON.parse(raw));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "ENOENT") {
      const message =
        error instanceof Error ? error.message : "Unknown configuration error";
      throw new AppError(
        "CONFIG_INVALID",
        `Could not load configuration: ${message}`,
        EXIT.CONFIG,
      );
    }
  }

  const apiKey = process.env.DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY?.trim();
  return {
    config: mergeConfig(parsed),
    path: configPath,
    exists,
    secrets: {
      ...(apiKey ? { onionSearchEngineApiKey: apiKey } : {}),
      onionSearchEngineApiKeySource: apiKey ? "env" : "missing",
    },
  };
}

export function publicDefaultConfig(): AppConfig {
  return structuredClone(DEFAULT_CONFIG);
}

export interface ParsedProxy {
  url: URL;
  host: string;
  port: number;
}

export function parseLoopbackSocksProxy(value: string): ParsedProxy {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AppError(
      "TOR_PROXY_INVALID",
      "Tor proxy URL is invalid.",
      EXIT.CONFIG,
    );
  }

  if (url.protocol !== "socks5h:") {
    throw new AppError(
      "TOR_PROXY_INVALID",
      "Tor proxy must use socks5h so onion names are resolved by Tor.",
      EXIT.CONFIG,
    );
  }
  if (url.username || url.password) {
    throw new AppError(
      "TOR_PROXY_INVALID",
      "Proxy credentials are not supported.",
      EXIT.CONFIG,
    );
  }
  if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
    throw new AppError(
      "TOR_PROXY_INVALID",
      "Tor proxy URL must not contain a path, query, or fragment.",
      EXIT.CONFIG,
    );
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!new Set(["127.0.0.1", "localhost", "::1"]).has(host)) {
    throw new AppError(
      "TOR_PROXY_INVALID",
      "Tor proxy must be bound to loopback.",
      EXIT.POLICY,
    );
  }
  const port = Number(url.port || "9050");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new AppError(
      "TOR_PROXY_INVALID",
      "Tor proxy port is invalid.",
      EXIT.CONFIG,
    );
  }
  return { url, host, port };
}
