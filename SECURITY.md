# Security policy

## Supported versions

This project is pre-1.0. Security fixes are made on the current default branch
and, when releases exist, in the latest release. Older snapshots are not
maintained separately.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue, discussion,
pull request, sample report, or social post.

If GitHub private vulnerability reporting is enabled for this repository, use
**Security → Advisories → Report a vulnerability**. If that option is not
available, open a public issue containing only a request for a private contact
channel—do not include technical details, credentials, real onion addresses,
collected content, or personal data.

Include only what is necessary to reproduce the issue safely:

- affected version or commit;
- operating system and Node.js version;
- the violated security invariant and likely impact;
- minimal reproduction steps using the offline fixture or a synthetic test
  double;
- whether credentials, direct network traffic, or investigation data may have
  been exposed;
- a suggested mitigation, if known.

Never test a report against a live onion service, a third-party account, or the
production provider without explicit authorization. Do not attach breach data,
malware, tokens, cookies, API keys, or screenshots containing sensitive data.

Maintainers will validate scope, coordinate a fix and disclosure when warranted,
and credit reporters who request attribution. No response-time SLA is currently
promised.

## Security invariants

The following properties define the intended security boundary:

1. Indexed search does not contact returned onion services. The current API
   transport is a direct HTTPS `GET` to the compiled-in
   `https://onionsearchengine.com` origin, rejects redirects, applies a timeout,
   and limits each response to 2 MiB.
2. Direct onion verification is opt-in and requires an explicit risk
   acknowledgement. It must reject a missing Tor listener rather than fall back
   to the direct network.
3. Verification accepts only checksum-valid v3 onion hosts over HTTP(S), ports
   80 or 443, without URL credentials. Every redirect is revalidated and must
   remain on the original onion host.
4. The verification proxy must use `socks5h`, be bound to loopback, and contain
   no credentials. The application relies on the local Tor process and
   `socks-proxy-agent` to perform remote onion-name resolution.
5. Onion responses are treated as hostile. Only text/HTML content types are
   accepted, each response is bounded to 512 KiB, no browser or subresource
   loader is used, selected active elements are removed before text extraction,
   and terminal/bidirectional control characters are stripped from normalized
   content.
6. The Onion Search Engine API key is read only from
   `DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY`. `init` creates a non-secret JSON
   file and diagnostic output reports only whether the key is available.
7. Ahmia remains manual-only. No code in this project sends automated requests
   to its search endpoint.
8. Output is not evidence of attribution. A result marked `reachable` records
   only that an HTTP response was received; relevance and keyword presence are
   not trust scores.
9. Imported reports must be regular files no larger than 5 MiB. Strict schemas,
   bounded arrays and text, and canonical URL/identifier checks make them safer
   to process, but reports are unsigned and their provenance remains untrusted.
10. `providers.onionsearchengine.enabled` controls the implicit search default,
    not authorization. Explicit provider selection and `request get` remain
    available when the flag is false.

See [THREAT_MODEL.md](THREAT_MODEL.md) for boundary details and documented
assumptions.

## Findings that are in scope

Examples include:

- a way to make onion verification use direct DNS or direct HTTP instead of the
  approved local Tor path;
- bypassing v3 onion validation, loopback proxy enforcement, port restrictions,
  or same-onion redirect enforcement;
- causing the provider transport to contact an attacker-selected origin or an
  internal/metadata service;
- exposing the API key through output, errors, reports, or configuration files;
- executing code, loading subresources, submitting requests, or writing files
  as a consequence of hostile provider/onion content without an operator's
  explicit file choice;
- terminal or Markdown injection that survives the intended output sanitation
  and creates a concrete security impact;
- bypassing request, page, result, redirect, concurrency, or response-size
  limits in a way that creates material resource exhaustion;
- a dependency or release-workflow weakness that can compromise published
  artifacts.

## Reports that are generally out of scope

Unless accompanied by a software security boundary failure, the following are
not vulnerabilities in this project:

- false positives, stale results, missing results, provider ranking quality, or
  an onion service being unavailable;
- the fact that an API provider sees a query submitted to it—this is an explicit
  privacy tradeoff, not an anonymity guarantee;
- content, legality, or security of a third-party onion service;
- upstream provider downtime, schema changes, rate limits, or terms disputes;
- social engineering that requires an operator to ignore explicit warnings and
  intentionally open or execute external content;
- an operator intentionally choosing an arbitrary input/output path or using
  `--force` under the same local account;
- misuse of the tool for an unauthorized investigation.

## Handling secrets and investigation data

Use synthetic values in tests and reports. Rotate a provider key immediately if
it might have been exposed. Search reports can contain queries, onion addresses,
snippets, timestamps, and short verification evidence; handle them according to
your organization's investigation-data policy and never commit them to this
public repository.
