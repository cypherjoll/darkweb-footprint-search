import http from "node:http";
import https from "node:https";
import net from "node:net";
import { performance } from "node:perf_hooks";
import { SocksProxyAgent } from "socks-proxy-agent";
import { parseLoopbackSocksProxy } from "./config.js";
import { AppError, EXIT } from "./errors.js";
import { canonicalizeOnionUrl } from "./onion.js";
import { sanitizeSecretText } from "./sanitize.js";

export interface JsonResponse {
  status: number;
  headers: Record<string, string>;
  data: unknown;
  elapsedMs: number;
}

async function readFetchBody(
  response: Response,
  maxBytes: number,
): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new AppError(
          "RESPONSE_TOO_LARGE",
          "Provider response exceeded the byte limit.",
          EXIT.SOURCE_FAILED,
        );
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

export async function getProviderJson(
  url: URL,
  apiKey: string,
  timeoutMs: number,
  maxBytes = 2 * 1024 * 1024,
): Promise<JsonResponse> {
  if (
    url.protocol !== "https:" ||
    url.origin !== "https://onionsearchengine.com"
  ) {
    throw new AppError(
      "PROVIDER_ORIGIN_BLOCKED",
      "Provider request origin is not allowlisted.",
      EXIT.POLICY,
    );
  }

  const started = performance.now();
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        Accept: "application/json",
        "Accept-Encoding": "identity",
        "User-Agent": "darkfootprint/0.1 (+defensive-osint)",
        "X-API-Key": apiKey,
      },
    });
  } catch (error) {
    if (error instanceof AppError) throw error;
    const cause = error instanceof Error ? error.name : "unknown";
    throw new AppError(
      "PROVIDER_NETWORK_ERROR",
      `Provider request failed (${cause}).`,
      EXIT.SOURCE_FAILED,
    );
  }

  const body = await readFetchBody(response, maxBytes);
  const elapsedMs = Math.round(performance.now() - started);
  const headers: Record<string, string> = {};
  for (const [key, value] of response.headers.entries()) {
    if (
      new Set([
        "content-type",
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
      ]).has(key)
    ) {
      headers[key] = sanitizeSecretText(value, [apiKey], 512);
    }
  }

  let data: unknown;
  try {
    data = JSON.parse(body.toString("utf8"));
  } catch {
    throw new AppError(
      "PROVIDER_INVALID_JSON",
      "Provider returned invalid JSON.",
      EXIT.SOURCE_FAILED,
    );
  }

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    if (
      typeof data === "object" &&
      data &&
      "message" in data &&
      typeof data.message === "string"
    ) {
      detail = sanitizeSecretText(data.message, [apiKey], 200) || detail;
    }
    const code =
      response.status === 401 || response.status === 403
        ? "PROVIDER_AUTH_FAILED"
        : response.status === 429
          ? "PROVIDER_RATE_LIMITED"
          : "PROVIDER_HTTP_ERROR";
    throw new AppError(
      code,
      `Provider rejected the request: ${detail}`,
      response.status === 401 || response.status === 403
        ? EXIT.CONFIG
        : EXIT.SOURCE_FAILED,
    );
  }

  return { status: response.status, headers, data, elapsedMs };
}

export async function probeTcp(
  host: string,
  port: number,
  timeoutMs = 750,
): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;
    const finish = (value: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

export interface OnionTextResponse {
  status: number;
  contentType: string;
  body: Buffer;
  finalUrl: string;
  elapsedMs: number;
}

function headerValue(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
}

async function onionGetOnce(
  target: URL,
  agent: SocksProxyAgent,
  timeoutMs: number,
  maxBytes: number,
): Promise<{
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  elapsedMs: number;
}> {
  const started = performance.now();
  const transport = target.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    let finished = false;
    const finishReject = (error: unknown): void => {
      if (finished) return;
      finished = true;
      clearTimeout(deadline);
      reject(error);
    };
    const deadline = setTimeout(() => {
      request.destroy(
        new AppError("ONION_TIMEOUT", "Onion request timed out.", EXIT.CONFIG),
      );
    }, timeoutMs);
    const request = transport.request(
      target,
      {
        method: "GET",
        agent,
        headers: {
          Accept: "text/html,application/xhtml+xml,text/plain;q=0.9",
          "Accept-Encoding": "identity",
          "User-Agent": "darkfootprint/0.1 (+defensive-osint; no-subresources)",
          Connection: "close",
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        let total = 0;
        response.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBytes) {
            response.destroy(
              new AppError(
                "RESPONSE_TOO_LARGE",
                "Onion response exceeded the byte limit.",
                EXIT.POLICY,
              ),
            );
            return;
          }
          chunks.push(Buffer.from(chunk));
        });
        response.on("end", () => {
          if (finished) return;
          finished = true;
          clearTimeout(deadline);
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks, total),
            elapsedMs: Math.round(performance.now() - started),
          });
        });
        response.on("error", finishReject);
      },
    );

    request.once("error", finishReject);
    request.end();
  });
}

export async function getOnionText(
  inputUrl: string,
  proxyUrl: string,
  timeoutMs: number,
  maxBytes = 512 * 1024,
  maxRedirects = 2,
): Promise<OnionTextResponse> {
  const initial = canonicalizeOnionUrl(inputUrl);
  const proxy = parseLoopbackSocksProxy(proxyUrl);
  const agent = new SocksProxyAgent(proxy.url);
  let current = new URL(initial.canonicalUrl);
  let elapsedMs = 0;

  for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
    const response = await onionGetOnce(current, agent, timeoutMs, maxBytes);
    elapsedMs += response.elapsedMs;
    const location = headerValue(response.headers.location);

    if (response.status >= 300 && response.status < 400 && location) {
      if (redirect === maxRedirects) {
        throw new AppError(
          "TOO_MANY_REDIRECTS",
          "Onion redirect limit exceeded.",
          EXIT.POLICY,
        );
      }
      const next = new URL(location, current);
      const canonical = canonicalizeOnionUrl(next.toString());
      if (canonical.hostname !== initial.hostname) {
        throw new AppError(
          "CROSS_ONION_REDIRECT_BLOCKED",
          "Redirect to another onion service was blocked.",
          EXIT.POLICY,
        );
      }
      current = new URL(canonical.canonicalUrl);
      continue;
    }

    const contentType =
      headerValue(response.headers["content-type"])
        .split(";", 1)[0]
        ?.trim()
        .toLowerCase() ?? "";
    if (
      !new Set(["text/html", "application/xhtml+xml", "text/plain"]).has(
        contentType,
      )
    ) {
      throw new AppError(
        "CONTENT_TYPE_BLOCKED",
        `Onion content type is not allowed: ${contentType || "unknown"}.`,
        EXIT.POLICY,
      );
    }
    return {
      status: response.status,
      contentType,
      body: response.body,
      finalUrl: current.toString(),
      elapsedMs,
    };
  }

  throw new AppError(
    "TOO_MANY_REDIRECTS",
    "Onion redirect limit exceeded.",
    EXIT.POLICY,
  );
}
