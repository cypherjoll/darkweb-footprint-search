import assert from "node:assert/strict";
import test from "node:test";
import { parseLoopbackSocksProxy } from "../src/config.js";
import { AppError } from "../src/errors.js";
import {
  canonicalizeOnionUrl,
  createSyntheticV3OnionHost,
  isValidV3OnionHost,
  resultId,
} from "../src/onion.js";
import {
  sanitizeJsonValue,
  sanitizeSecretText,
  sanitizeText,
  stripTerminalControls,
} from "../src/sanitize.js";

function hasErrorCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean =>
    error instanceof AppError && error.code === code;
}

test("synthetic v3 onion hosts are deterministic and checksum-valid", () => {
  const host = createSyntheticV3OnionHost("unit-test-service");
  const repeated = createSyntheticV3OnionHost("unit-test-service");
  const other = createSyntheticV3OnionHost("other-unit-test-service");

  assert.equal(host, repeated);
  assert.notEqual(host, other);
  assert.match(host, /^[a-z2-7]{56}\.onion$/);
  assert.equal(isValidV3OnionHost(host), true);

  const replacement = host[0] === "a" ? "b" : "a";
  assert.equal(isValidV3OnionHost(`${replacement}${host.slice(1)}`), false);
  assert.equal(isValidV3OnionHost("abcdefghijklmnop.onion"), false);
  assert.equal(isValidV3OnionHost("example.com"), false);
});

test("canonicalizeOnionUrl strips fragments and returns a stable service identity", () => {
  const host = createSyntheticV3OnionHost("canonical-service");
  const canonical = canonicalizeOnionUrl(
    `http://${host}:80/reports/APT10?q=one#section`,
  );

  assert.deepEqual(canonical, {
    canonicalUrl: `http://${host}/reports/APT10?q=one`,
    serviceId: host.slice(0, -6),
    hostname: host,
  });
  assert.equal(
    resultId(canonical.canonicalUrl),
    resultId(canonical.canonicalUrl),
  );
  assert.match(resultId(canonical.canonicalUrl), /^dfp_[a-f0-9]{24}$/);
  assert.notEqual(
    resultId(canonical.canonicalUrl),
    resultId(`http://${host}/other`),
  );
});

test("canonicalizeOnionUrl rejects unsafe schemes, credentials, ports, and hosts", () => {
  const host = createSyntheticV3OnionHost("policy-service");
  assert.throws(
    () => canonicalizeOnionUrl(`ftp://${host}/file`),
    hasErrorCode("INVALID_ONION_URL"),
  );
  assert.throws(
    () => canonicalizeOnionUrl(`http://operator:secret@${host}/`),
    hasErrorCode("INVALID_ONION_URL"),
  );
  assert.throws(
    () => canonicalizeOnionUrl(`http://${host}:8080/`),
    hasErrorCode("INVALID_ONION_URL"),
  );
  assert.throws(
    () => canonicalizeOnionUrl("https://example.com/"),
    hasErrorCode("INVALID_ONION_URL"),
  );
  assert.throws(
    () => canonicalizeOnionUrl("not a URL"),
    hasErrorCode("INVALID_ONION_URL"),
  );
});

test("terminal sanitizer removes ANSI, OSC, control, and bidi sequences", () => {
  const dirty = "A\u001b]0;owned\u0007B\u001b[31mC\u001b[0m\u202eD\u0000";
  assert.equal(stripTerminalControls(dirty), "ABCD");
});

test("sanitizeText normalizes Unicode and whitespace and applies its bound", () => {
  assert.equal(sanitizeText("  ＡＰＴ１０\t cafe\u0301  "), "APT10 café");
  assert.equal(sanitizeText("abcdef", 4), "abcd");
  assert.equal(sanitizeText(42), "");
});

test("Tor proxy parsing permits only a plain loopback socks5h endpoint", () => {
  assert.equal(parseLoopbackSocksProxy("socks5h://127.0.0.1:9050").port, 9050);
  assert.equal(parseLoopbackSocksProxy("socks5h://[::1]:9150").host, "::1");
  for (const proxy of [
    "socks5://127.0.0.1:9050",
    "socks5h://192.0.2.1:9050",
    "socks5h://user:secret@127.0.0.1:9050",
    "socks5h://127.0.0.1:9050/path",
    "socks5h://127.0.0.1:9050/?mode=unsafe",
  ]) {
    assert.throws(
      () => parseLoopbackSocksProxy(proxy),
      hasErrorCode("TOR_PROXY_INVALID"),
    );
  }
});

test("provider sanitation removes exact secrets from text and nested JSON", () => {
  const secret = "opaque-provider-key-123";
  assert.equal(
    sanitizeSecretText(`reflected ${secret}`, [secret]),
    "reflected ***",
  );
  assert.equal(
    sanitizeSecretText("reflected opa\u001b[31mque-provider-key-123", [secret]),
    "reflected ***",
  );
  assert.equal(sanitizeSecretText("ＫＥＹ１２３", ["KEY123"]), "***");
  assert.deepEqual(
    sanitizeJsonValue(
      { message: secret, nested: [`x-${encodeURIComponent(secret)}-y`] },
      [secret],
    ),
    { message: "***", nested: ["x-***-y"] },
  );
});
