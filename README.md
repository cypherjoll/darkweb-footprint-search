# darkfootprint

`darkfootprint` is a defensive command-line tool for finding keyword mentions in
authorized dark-web indexes. It turns provider results into normalized,
traceable leads and can optionally perform a small, explicit reachability check
through a local Tor proxy.

It is designed for defenders, incident responders, threat-intelligence teams,
and researchers working with authorization. It is **not** an attribution
engine, a breach validator, a crawler, or a way to obtain illicit material.

> An indexed match is a lead, not proof of identity, authenticity, compromise,
> ownership, or attribution. Corroborate every result with independent,
> lawful evidence.

## Safety model

The two network operations are intentionally separate:

1. **Indexed search** asks an authorized HTTPS API for references it has
   already indexed. It does not contact the returned onion services. The query
   and API usage are visible to that third-party provider. Reports classify the
   index route as `offline`, `direct`, or `mixed`, based on selected sources.
2. **Onion verification** is off by default. When explicitly enabled, it checks
   only a bounded subset through a caller-supplied local `socks5h` Tor listener.
   It requires a separate risk acknowledgement and never falls back to a direct
   connection.

The repository includes a deterministic `fixture` provider for demonstrations
and tests. It creates synthetic, checksum-valid v3 onion addresses and performs
no network activity. No live onion address appears in this documentation.

## Sources

| Source              | Mode        | Network            | Notes                                                                                                                                                                                                                |
| ------------------- | ----------- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fixture`           | Offline     | None               | Synthetic, deterministic demo data.                                                                                                                                                                                  |
| `onionsearchengine` | API         | Direct HTTPS       | Requires `DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY`; see the provider's [API documentation](https://onionsearchengine.com/api_documentation.php) and review its current terms before use.                             |
| `ahmia-manual`      | Manual only | None from this CLI | Listed for operator awareness. The CLI does not automate Ahmia because its [terms](https://ahmia.fi/terms/) prohibit scraping without permission; review its live [robots.txt](https://ahmia.fi/robots.txt) as well. |

Run `darkfootprint sources list` to see the descriptors shipped with the
installed version. Only `fixture` and `onionsearchengine` are selectable search
providers. `sources check` reports local prerequisites such as key presence; it
does not contact the API to authenticate a key.

## Requirements

- Node.js 22.19 or later
- pnpm with lockfile v9 support for development from source
- An Onion Search Engine API key for live indexed searches
- A separately installed and running Tor client only for optional onion
  verification

The tool does not install, configure, or start Tor.

## Build from source

```console
corepack enable
pnpm install --frozen-lockfile
pnpm build
node dist/src/cli.js --help
```

During source development, the examples below use
`node dist/src/cli.js`. After installing the package as a command, use
`darkfootprint` in its place.

## Offline quick start

This example is safe to run without credentials, Tor, or network access:

```console
node dist/src/cli.js sources list
node dist/src/cli.js search APT10 --source fixture
node dist/src/cli.js --json search APT10 --source fixture
```

The returned records are synthetic examples. They are not intelligence about
APT10 and do not point to live services.

To save a structured report without replacing an existing file:

```console
node dist/src/cli.js search APT10 --source fixture --format json --out reports/apt10-fixture.json
```

Use `--force` only when intentionally replacing the selected output file.

## Live indexed search

Obtain an API key through the provider's official process and expose it only in
the environment of the current process. The application does not read API keys
from its JSON configuration file, and it does not automatically load `.env`
files.

PowerShell:

```powershell
$env:DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY = "<your-api-key>"
node dist/src/cli.js --json sources check
node dist/src/cli.js search APT10 --source onionsearchengine --limit 10
```

POSIX shells:

```sh
export DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY='<your-api-key>'
node dist/src/cli.js --json sources check
node dist/src/cli.js search APT10 --source onionsearchengine --limit 10
```

If `--source` is omitted, `onionsearchengine` is the default while its
configuration flag is enabled (the built-in default). The API request is a
bounded `GET` to a fixed HTTPS origin, with redirects disabled and a 2 MiB
response limit per page. It is not routed through the Tor setting. Never use a
secret, password, private token, or unnecessary personal data as a query.

The advanced `request get` command emits provider-shaped JSON through the same
fixed endpoint and origin controls. It recursively removes terminal and
bidirectional control characters and redacts exact API-key occurrences from the
payload and selected response headers, but it does not normalize the payload
into a search report. Treat that output as untrusted third-party data.

## Optional Tor verification

Verification directly contacts result onion services and can expose the
operator to disturbing, deceptive, illegal, or malicious content. Confirm that
the investigation is authorized, use an isolated environment, and follow your
organization's evidence-handling policy.

1. Install and run Tor separately. Tor documents that its SOCKS listener is
   [local by default](https://support.torproject.org/little-t-tor/getting-started/tor-client-central-server/)
   and provides a procedure for
   [checking SOCKS DNS leaks](https://support.torproject.org/little-t-tor/troubleshooting/check-for-leaks/).
2. Identify its local SOCKS listener. The default expected by this tool is
   `socks5h://127.0.0.1:9050`.
3. Check local readiness:

   ```console
   node dist/src/cli.js doctor
   ```

4. Create a JSON report from an authorized indexed search.
5. Verify a bounded subset only after reviewing the report:

   ```console
   node dist/src/cli.js onion verify --input search-report.json --max 2 --acknowledge-risk
   ```

Alternatively, `search` accepts `--verify-onion --max-verify 2
--acknowledge-risk` for a combined run. The separate workflow is easier to
review before any onion connection occurs.

The verifier accepts only a loopback `socks5h` proxy, checksum-valid v3 onion
hosts, HTTP or HTTPS, and ports 80 or 443. It performs `GET` requests with no
browser, JavaScript, cookies, forms, authentication, or subresource loading.
Each response is limited to 512 KiB, only text/HTML media types are accepted,
and at most two redirects are followed to the same onion service. These controls
reduce risk; they do not make unknown content safe or prove that the listener is
really Tor.

Set a different local listener for the current process with
`DARKFOOTPRINT_TOR_PROXY`, or pass `--proxy` to a verification command. Remote
proxies, proxy credentials, and plain `socks5` are rejected.

## Configuration

Create a non-secret configuration file:

```console
node dist/src/cli.js init --dry-run
node dist/src/cli.js init
```

The default path is `.darkfootprint/config.json` below the current user's home
directory. `--config <path>` or `DARKFOOTPRINT_CONFIG` selects another file.
The file contains limits and the Tor proxy URL, but never the API key.

Default limits:

| Setting                       |    Default | Accepted range |
| ----------------------------- | ---------: | -------------: |
| Results                       |         25 |          1–100 |
| Provider pages                |          1 |            1–5 |
| Search/config request timeout | 15 seconds |   1–60 seconds |
| Onion verifications           |          5 |           1–20 |

Command-line values override the corresponding configuration values. For the
Tor proxy, `--proxy` overrides the environment, which overrides the JSON file,
which overrides the built-in default.

The 1–60 second validation applies to the JSON setting and every command's
network timeout option, including `search`, `onion verify`, and `request get`.

`providers.onionsearchengine.enabled: false` removes the API provider from the
implicit default search, but an explicit `--source onionsearchengine` still runs
it. `sources check` and `request get` also do not use the flag as a deny control.
Treat it as a default-selection preference, not authorization enforcement.

## Commands and output

```text
darkfootprint doctor [--offline]
darkfootprint init [--dry-run] [--proxy socks5h://127.0.0.1:9050]
darkfootprint sources list
darkfootprint sources check
darkfootprint search <keyword> [--source <id>] [--format human|json|jsonl|markdown]
darkfootprint onion verify --input <report.json> --acknowledge-risk
darkfootprint results show <result-id> --input <report.json>
darkfootprint results export --input <report.json> --out <file> --format jsonl|markdown
darkfootprint request get --source onionsearchengine --query <keyword>
```

Use `darkfootprint <command> --help` for all bounds and options. Structured
search reports use schema version `1.0`. Normalized results include a stable
identifier, canonical onion URL, sanitized title and snippet, provenance,
relevance score, and verification state. Relevance is a search-ordering signal,
not a risk or attribution score.

Search and report commands write to stdout unless `--out` is supplied. The
separate `init` command intentionally creates its non-secret configuration file
unless `--dry-run` is used. Saved reports contain the query, result URLs,
snippets, timestamps, and provider provenance. A verified report can also
contain a short evidence snippet and response hashes. Protect these files as
investigation data; the repository ignores the `reports/` directory plus JSONL
and common database extensions by default. Arbitrary JSON files outside
`reports/` are not ignored.

Exit codes are stable for automation:

| Code | Meaning                                                                            |
| ---: | ---------------------------------------------------------------------------------- |
|    0 | Complete success, including zero results                                           |
|    2 | Invalid input or command usage                                                     |
|    3 | Configuration, credential, or Tor availability error                               |
|    4 | Partial result; `--allow-partial` can make a successful mixed-source search exit 0 |
|    5 | All selected sources failed                                                        |
|    6 | Report or output file error                                                        |
|    7 | Safety policy blocked the operation                                                |
|   70 | Unexpected internal error                                                          |

## Privacy and interpretation

- API providers can observe the query, API account, timing, and source IP. HTTPS
  protects the connection in transit but does not hide data from the provider.
- Tor verification hides the destination from the local network, assuming the
  local listener is genuine and correctly configured. The network can still
  observe Tor use, and traffic analysis remains possible.
- Shell history, terminal capture, CI logs, exported reports, and backups may
  retain queries or results. Use the minimum data necessary.
- Indexes can be stale, incomplete, manipulated, duplicated, or wrong. A keyword
  can refer to an unrelated person, group, product, or quoted article.
- `reachable` means an HTTP response was received. `keyword_present` means a
  literal text match was found in the bounded response. Neither establishes
  authenticity, control of the service, maliciousness, compromise, or
  attribution.
- Absence of results is not evidence that no footprint exists.

## Deliberate limitations

`darkfootprint` does not crawl onion services, follow arbitrary links, download
attachments, execute page scripts, submit forms, log in, solve CAPTCHAs, bypass
access controls, purchase data, collect credentials, or automate Ahmia. It does
not provide comprehensive dark-web coverage, continuous monitoring, actor
attribution, legal advice, or incident notification.

Operators remain responsible for authorization, applicable law, provider terms,
data minimization, retention, and safe escalation of credible findings.

## Development and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the offline-first development rules,
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the implementation boundaries,
[THREAT_MODEL.md](THREAT_MODEL.md) for security assumptions, and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

Licensed under the [Apache License 2.0](LICENSE).
