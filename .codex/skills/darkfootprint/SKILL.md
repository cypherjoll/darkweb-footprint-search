---
name: darkfootprint
description: Search authorized dark-web indexes for defensive digital-footprint research with the darkfootprint CLI, and optionally verify previously returned onion results through a local Tor proxy. Do not use for arbitrary onion browsing, credential acquisition, or access to illegal content.
---

# Darkfootprint

Use the installed `darkfootprint` command as a read-only, bounded research tool.

Start by checking availability and configuration:

```powershell
Get-Command darkfootprint
darkfootprint --json doctor
darkfootprint --json sources list
```

The live `onionsearchengine` provider reads its key only from
`DARKFOOTPRINT_ONIONSEARCHENGINE_API_KEY`. Never print, persist, or pass that key
as a command-line flag. Provider queries disclose the keyword to that provider,
so do not submit passwords, secrets, or unnecessary personal data.

For indexed research, search first and save JSON only when the user wants an
artifact:

```powershell
darkfootprint --json search "APT10" --source onionsearchengine
darkfootprint search "APT10" --source onionsearchengine --format json --out .\reports\apt10.json
```

Use `--source fixture` only for offline demos and tests; its results are
synthetic. Treat every indexed match as an unverified lead, never as proof of
identity, compromise, authenticity, or attribution.

Direct onion verification is a separate step. Run it only when the user has
authorized contacting the returned services and accepts the content risk. Tor
must expose a loopback `socks5h` proxy; the CLI does not install or start Tor.

```powershell
darkfootprint onion verify --input .\reports\apt10.json --max 3 --acknowledge-risk --format json --out .\reports\apt10-verified.json
```

Do not use verification to crawl, follow links, authenticate, submit forms, or
download files. The restricted raw escape hatch is
`darkfootprint --json request get --source onionsearchengine --query "APT10"`;
it permits only the documented provider search GET and does not justify broader
requests.
