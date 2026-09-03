import { createHash, timingSafeEqual } from "node:crypto";
import { AppError, EXIT } from "./errors.js";

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const ONION_CHECKSUM_PREFIX = Buffer.from(".onion checksum", "ascii");

function decodeBase32(value: string): Buffer {
  let bits = 0;
  let accumulator = 0;
  const output: number[] = [];

  for (const char of value) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0)
      throw new AppError(
        "INVALID_ONION",
        "Invalid v3 onion alphabet.",
        EXIT.USAGE,
      );
    accumulator = (accumulator << 5) | index;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
  }

  return Buffer.from(output);
}

function encodeBase32(value: Buffer): string {
  let bits = 0;
  let accumulator = 0;
  let output = "";

  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> bits) & 31];
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}

export function isValidV3OnionHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (!host.endsWith(".onion")) return false;
  const label = host.slice(0, -6);
  if (!/^[a-z2-7]{56}$/.test(label)) return false;

  try {
    const decoded = decodeBase32(label);
    if (decoded.length !== 35) return false;
    const publicKey = decoded.subarray(0, 32);
    const checksum = decoded.subarray(32, 34);
    const version = decoded.subarray(34, 35);
    if (version[0] !== 3) return false;
    const expected = createHash("sha3-256")
      .update(Buffer.concat([ONION_CHECKSUM_PREFIX, publicKey, version]))
      .digest()
      .subarray(0, 2);
    return timingSafeEqual(checksum, expected);
  } catch {
    return false;
  }
}

export function createSyntheticV3OnionHost(seed: string): string {
  const publicKey = createHash("sha256")
    .update(`darkfootprint-fixture:${seed}`)
    .digest();
  const version = Buffer.from([3]);
  const checksum = createHash("sha3-256")
    .update(Buffer.concat([ONION_CHECKSUM_PREFIX, publicKey, version]))
    .digest()
    .subarray(0, 2);
  return `${encodeBase32(Buffer.concat([publicKey, checksum, version]))}.onion`;
}

export interface CanonicalOnionUrl {
  canonicalUrl: string;
  serviceId: string;
  hostname: string;
}

export function canonicalizeOnionUrl(value: string): CanonicalOnionUrl {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AppError(
      "INVALID_ONION_URL",
      "Result URL is not a valid absolute URL.",
      EXIT.POLICY,
    );
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new AppError(
      "INVALID_ONION_URL",
      "Only HTTP(S) onion URLs are allowed.",
      EXIT.POLICY,
    );
  }
  if (url.username || url.password) {
    throw new AppError(
      "INVALID_ONION_URL",
      "Credentials in onion URLs are not allowed.",
      EXIT.POLICY,
    );
  }
  const authority =
    value.slice(value.indexOf("://") + 3).split(/[/?#]/, 1)[0] ?? "";
  if (/[A-Z]/.test(authority) || !isValidV3OnionHost(url.hostname)) {
    throw new AppError(
      "INVALID_ONION_URL",
      "Only checksum-valid v3 .onion hosts are allowed.",
      EXIT.POLICY,
    );
  }
  if (url.port && url.port !== "80" && url.port !== "443") {
    throw new AppError(
      "INVALID_ONION_URL",
      "Only ports 80 and 443 are allowed for onion verification.",
      EXIT.POLICY,
    );
  }

  url.hash = "";
  const hostname = url.hostname;
  return {
    canonicalUrl: url.toString(),
    serviceId: hostname.slice(0, -6),
    hostname,
  };
}

export function resultId(canonicalUrl: string): string {
  return `dfp_${createHash("sha256").update(canonicalUrl).digest("hex").slice(0, 24)}`;
}
