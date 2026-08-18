# Changelog

All notable changes to Spyglass are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-08-17

### Added

- **Dark web module** (`darkweb`): keyless onion-index search via Ahmia, breached-password
  checking via Pwned Passwords k-anonymity, and breach attribution reusing the existing
  breach sources — with opt-in keyed layers for IntelX and HaveIBeenPwned.
- **Report/dossier generator** (`--report`): persistent Markdown dossiers for every module
  and investigation, with structured section rendering.
- **Case store** (`--store` + `cases` subcommand): opt-in SQLite persistence with entity
  indexing, `cases list/diff/timeline/export`, and a stable JSON profile export.
- **Version metadata** (`--version`) and `__version__`.
- **`--password` flag** (`darkweb`): reads a password via `getpass` (never argv) and returns
  only a pwned/count verdict — the password and hash are never logged or written.
- **Website recon rebuild**: 4 passive subdomain sources (crt.sh, HackerTarget, CertSpotter,
  Wayback CDX), security-header/tech-stack/TLS/cookie/CSP/favicon fingerprinting, content
  discovery (robots, sitemap, exposure checks, JS secrets), Wayback history, and DNS depth
  (SPF/DMARC/CAA/DNSSEC, reverse PTR, /24 sweep).
- **WHOIS domain support**: domain and registry formats with referral-following (macOS/Linux).

### Changed

- **Parallel execution**: investigations run email/username/phone/website concurrently, and
  the website module runs its independent phases concurrently.
- **Per-run memoization**: DNS answers and HTTP bodies are cached within a run, eliminating
  duplicate lookups/fetches.

### Fixed

- CSV export crash on mixed scalar/nested results, and lost scalar-list field names.
- Empty WHOIS on macOS (IANA thin data) — now parses domain formats and follows referrals.
- Uncaught tool-timeout crashes in username/email modules (sherlock, holehe, etc.) now
  degrade gracefully.
- Website correctness bugs: duplicate `Set-Cookie` parsing, exposure-check redirect
  false-positives, favicon hashing of non-image responses, CNAME targets counted as IPs,
  `dig` error text read as data, and discarded passive subdomain IPs.
- Registry domain IDs misreported as phone numbers.
- Rich markup eating `[word]`-style brackets in output.
- Unregistered domains showing misleading TLD-level WHOIS data.

### Security

- OPSEC gating: native DNS resolution only runs without a proxy; all HTTP routes through
  `curl` over the configured proxy.
- Dark web searches report onion URLs and metadata only — no `.onion` connection is made.

## [0.1.0] - 2026-06-10

### Added

- Initial release: unified OSINT CLI with email, username, phone, website, IP, metadata, and
  OPSEC modules, Rich TUI, proxy routing, cross-module correlation, and JSON/CSV export.
