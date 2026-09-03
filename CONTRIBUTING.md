# Contributing

Thank you for helping improve `darkfootprint`. Contributions must preserve its
defensive, read-only purpose and its separation between indexed search and
explicit Tor verification.

## Ground rules

- Work only with systems, accounts, and data you are authorized to access.
- Use the `fixture` provider and synthetic content for development and tests.
- Do not commit real onion addresses, live-search output, credentials, cookies,
  breach data, personal data, malware, or screenshots of sensitive material.
- Do not add crawling, authentication, form submission, purchases, CAPTCHA
  bypass, access-control bypass, attachment downloads, or page-script execution.
- Do not automate a source whose terms or `robots.txt` disallow it. Ahmia must
  remain manual-only unless maintainers have documented permission and reviewed
  the design change.
- Treat provider output, imported reports, and onion content as hostile input.

Security-sensitive changes should explain the affected trust boundary and add
tests for both the allowed path and rejection path. Report suspected
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Development setup

Requirements:

- Node.js 22.19 or later
- pnpm with lockfile v9 support

```console
corepack enable
pnpm install --frozen-lockfile
pnpm build
node dist/src/cli.js search APT10 --source fixture
```

No API key or Tor process is needed for the ordinary development workflow.
Tests and pull-request checks must not depend on live network access.

## Quality checks

Run the same commands used by continuous integration:

```console
pnpm format:check
pnpm typecheck
pnpm test
pnpm pack:check
```

Use `pnpm format` to format intentional changes before committing. Do not update
the lockfile unless dependencies actually changed.

## Adding or changing a provider

A provider contribution must include:

- a documented, authorized API or other access mechanism compatible with the
  source's current terms;
- a fixed, reviewable destination rather than a caller-controlled base URL;
- read-only requests, explicit timeouts, byte/page/result limits, and no
  automatic redirect widening;
- runtime validation of the upstream schema and safe handling of individual
  malformed results;
- sanitation of untrusted text before terminal or Markdown rendering;
- provenance that identifies the source and retrieval time;
- deterministic offline fixtures and tests for success, zero results, malformed
  responses, timeouts, rate limits, and upstream schema changes;
- updates to source descriptors, README, architecture, and threat model when a
  trust boundary changes.

Do not include a live API response as a fixture. Construct the minimum synthetic
shape required by the test.

## Onion-verification changes

Changes to verification must retain all of these fail-closed properties:

- explicit `--acknowledge-risk` at the CLI boundary;
- `socks5h` and loopback-only proxy validation, with no direct fallback;
- checksum-valid v3 onion URLs, no URL credentials, and only ports 80/443;
- validation of every redirect and confinement to the original onion service;
- `GET` only, no browser or subresource loading, narrow content types, and
  bounded response sizes/timeouts;
- bounded concurrency and result counts;
- synthetic transports in automated tests, never live onion connections.

Any proposal to relax one of these controls needs a focused security rationale
and explicit maintainer agreement before implementation.

## Pull requests

Keep changes focused and describe:

1. the user problem and intended behavior;
2. network, privacy, and data-retention effects;
3. tests run and any test gaps;
4. provider terms or authorization considerations;
5. documentation changes for new commands, output fields, or trust boundaries.

By submitting a contribution, you agree that it is provided under the
repository's [Apache License 2.0](LICENSE).
