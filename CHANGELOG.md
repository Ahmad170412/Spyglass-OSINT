# Changelog

All notable changes to Spyglass are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Gravatar lookup** in the email module: md5 of the trimmed, lowercased address checked against
  Gravatar's `?d=404` avatar route, then the profile JSON if an avatar exists. Keyless and cheap —
  one hash and at most two requests. Its value is the `accounts` array, which links an opaque address
  to handles on other services that the registration checkers do not return, so those handles feed
  straight back into the username module. Ten tests covering hash normalisation, the not-found
  contract, and account extraction.
- **subfinder wired into the website module's passive discovery** (52 sources, replacing crt.sh and
  CertSpotter as the primary when installed — both are kept as the fallback for machines without it).
  - **All passive results are now resolution-filtered before being reported.** Measured against
    `example.com`, subfinder returns 22,250 names and the sampled ones have no DNS record at all:
    certificate-transparency and archive entries for hostnames that were never live. Unfiltered,
    that is a list nobody can triage. After filtering, the same target reports 1.
  - The resolution pass is capped at 1,500 lookups, and names corroborated by more than one source
    are checked first, so a capped run keeps the best evidence. Anything not checked is reported as
    `unchecked_truncated` rather than dropped silently.
  - A wildcard-domain canary is probed before any bulk resolution; a target that answers for every
    name suppresses its own subdomain list.
  - On `github.com`: 194 raw names versus 118 from the existing three sources, so 77 genuinely new
    subdomains. That is a real but more modest gain than the raw source counts suggest, because much
    of the extra is certificate entries for CDN edge hosts.
  - Fixed a scope bug this exposed: subdomain matching used a string suffix, so `notgithub.com` was
    accepted as a subdomain of `github.com` and someone else's host was attributed to the target.
    Matching now requires a label boundary.
- **Known-vulnerability lookup** (`cve.py`): the website module's fingerprint phase now captures product
  *versions* rather than only product names, and resolves them against the NIST NVD. Reports CVE ID,
  severity, CVSS score, the authoritative affected version range, and references.
  - Queries use NVD's `virtualMatchString` rather than a plain CPE lookup, because a plain CPE
    lookup cannot express the version *ranges* most advisories are written as.
  - **NVD's matching is verified rather than trusted.** `virtualMatchString` does not always apply
    a recorded range: a query for nginx 1.31.3 returned CVE-2009-3555, whose range ends at 0.8.22.
    Every hit is re-checked against the bounds NVD itself recorded and dropped if it does not
    cover the detected version. There is no wildcard-version fallback, so a current nginx reports
    zero CVEs and nginx 1.13.2 reports ten. The trade favours missing an advisory over falsely
    claiming one.
  - The affected range is printed beside every advisory. NVD widens ranges after publication while the
    description text keeps its original wording, so a PHP 7.4.3 host is correctly flagged for an
    advisory whose prose still reads "through 7.1.5" — the structured range is the authoritative one.
  - Rate-limit aware: anonymous NVD allows 5 requests per rolling 30 seconds, so calls are spaced
    rather than parallelised and the product count is capped (default 3, server-side components
    ranked ahead of front-end libraries). `NVD_API_KEY` raises the ceiling to 50.
  - Skipped entirely when no versioned component is detected, which is the common case for a
    CDN-fronted site since the origin's version is not exposed.
- **`--no-vulns`, `--cve-cap N` and `--nvd-key KEY`** flags for the website module.
- 37 unit tests covering detection, version-range evaluation, CPE construction, NVD parsing and
  result ordering — all offline.

### Fixed

- **URL verification no longer treats HTTP 200 as proof a profile exists.** `_verify()` accepted any
  2xx/3xx, so a username search reported profiles that were not there. Measured against a handle whose
  six candidates were all bogus: a 6KB client-rendered app shell, two bot-challenge interstitials
  ("Security Verification", "Client Challenge"), a 1.4KB empty frame, a catch-all route serving a
  *different* user's profile, and one page that never mentioned the handle. All six are now rejected
  and the search correctly reports nothing.
  - Verification now follows redirects and inspects the body: bot-challenge markers are matched
    anywhere in the body, a `<title>` that says the page does not exist is rejected, and a body-size
    floor catches empty SPA frames.
  - `expect` adds a content check — the response must actually mention the searched handle, which is
    what catches an app whose shell contains no profile data.
  - Not caught, and documented as such: catch-all profile routes that serve a genuinely valid
    profile for a different identity. No generic signal distinguishes those; it needs per-platform
    knowledge.
  - Rejections are now reported by reason rather than silently shrinking the result set.
  - Fetches send a browser User-Agent; a default curl UA is rejected outright by some platforms and
    was indistinguishable from a missing profile.
- **`phone()` no longer raises `NameError`** (also fixed in 1.1.1's successor): the `def _ignorant`
  header had been lost, leaving the body unreachable after `return` in `_phoneinfoga`.

### Fixed

- **Tool discovery no longer depends on PATH.** pip's `--user` scheme and the
  python.org Framework installers put console scripts in per-version directories that are often absent
  from PATH. Sherlock, maigret, holehe and ignorant all land in `~/Library/Python/3.13/bin` on macOS,
  and with that directory missing from PATH every one of them was silently skipped — the username
  module reported "user-scanner only" because three installed, working engines could not be found.
  `utils._which()` now falls back to the user-site, Framework, pyenv and Homebrew script directories.
  Verified: 16/16 tools resolve with a near-empty PATH.
- **URL verification rejects a bare echo of the search term.** `expect` accepted any page containing
  the term once, which a soft-404 satisfies trivially: `mastodon.social/@<handle>` returns 200 with
  50KB, no error marker, and reproduces the requested handle exactly once. A real profile mentions it
  133 times. `expect_min` (default 2) now requires more than an echo, which removes that class of
  false positive while keeping genuine profiles. A dotted handle is unaffected — the term is matched
  as a plain substring.
- **URL verification no longer rejects real profiles.** The bot-challenge check was a whole-body
  substring scan, and a bare `captcha` matched GitHub's own feature flag
  `octocaptcha_origin_optimization` in the JS payload — so every genuine GitHub profile was rejected.
  Challenge detection is now title-based (an interstitial names itself) with a short list of
  specific body markers. Positive control: three real pages that contain the search term now survive,
  having all failed before.

### Changed

- **maigret now runs once per search instead of twice.** It was invoked separately to collect
  profile URLs and again to collect the extracted fields, which doubled its wall clock and risked
  the two passes describing different searches. The ndjson report carries both, so one run now
  produces the hits and their data together. The stdout parser is kept as a fallback for maigret
  builds that write no report, so a half-working tool cannot read as "no accounts found".
- **`--top-sites 50` was a 200x restriction on a 6,206-site database.** Measured on a live handle,
  unique domains found: 50 -> 4.8s/6 domains, 200 -> 12.2s/7, 500 -> 15.2s/12, 1000 -> 27.0s/16,
  3000 -> 58.0s/24. The cap is now 1000, about 10% of a full four-engine search, and it roughly
  triples maigret's contribution. That change is what surfaced `pscp.tv` and Snapchat's profile
  metadata on a handle that previously showed neither.
- **maigret no longer leaks `reports/` into the working directory at all.** The main invocation
  never had `--folderoutput`; only the details pass did. Writing both to a temp directory covers
  the main call now, so no search leaves an unencrypted dossier behind.
- **Verification retries transient failures.** It fans 30 requests out at once across every
  candidate, and several candidates are usually the same host, which is enough to earn a 429 or a
  dropped connection. A throttled real profile was being recorded as a missing one — the exact
  failure this filter exists to prevent. 429, 5xx and dropped connections are now retried twice
  with a linear backoff. Real verdicts (registration prompt, not-found title, body too small) are
  not retried, because they come back identical.
- **The checkout directory name is no longer hardcoded anywhere.** The package name *is* the directory
  name, so a rename previously broke the test suite silently (`Ran 0 tests`) and the `setup.sh`
  launcher outright. `tests/helpers.py`, `tests/test_no_shadowing.py` and `setup.sh` now derive it
  from the filesystem. Verified against `spyglass-osint`, `spyglass_osint` and `osint-tool`: 205 tests
  pass in each.
- **The web console no longer scans the parent directory for its own package.** It did so to survive
  a rename, but since `webapp.py` lives inside the package the basename is exact — the scan was both
  more code and capable of matching an unrelated sibling package.
- **README documents that `python -m <pkg>` must run from the parent of the checkout.** The quick
  start told users to `cd` into the directory and then run `-m`, which cannot work; the `spyglass`
  launcher from `setup.sh` has no such constraint.
- Generated output (`--json`, `--csv`, `--report`) is now gitignored. It is written to the working
  directory and recon results are sensitive, so it should not be staged by accident.
- **Section labels for the username agreement tiers now live in one place.** `username.SECTION_LABELS`
  is the single source, used by the CLI, the Markdown dossier and the web console. Three separate
  copies had drifted apart, and the console's fallback of prettifying raw keys produced headings like
  "us only" — which reads as *United States* only, not user-scanner only.
- `website()` gained `vulns`, `nvd_key` and `cve_cap` keyword arguments. `vulns` defaults to on; the
  previous single-argument call signature is unchanged.
- Console text ramp lifted for legibility: the two dimmest tokens sat at 2.79:1 and 1.80:1 against the
  background, below the 4.5:1 AA threshold for normal text. All four steps now pass AA while staying
  ordered, so hierarchy is preserved. Section headers were also separated from table column headers,
  which were previously styled almost identically.

### Removed

- **Full-investigation mode** (`investigation.py`, the `[3] Full investigation` menu entry, the
  `investigation` CLI keyword and the `/api/investigation` route). It correlated every module's
  entities in one pass, but its output depended on all four identity modules returning clean data,
  and identity-module results carry known false positives — a correlation built on unverified hits
  presents them as confirmed. Removed pending verification work in `_verify`. Module runs are
  unaffected, and the case store's per-module `cases diff`/`timeline` still track change over time.

- **Flask web console** (`webapp.py` + `index.html`): a browser front end over the same modules the CLI
  calls. Every route returns the module's own dict, so there is no second implementation of any recon
  logic. Binds to loopback by default and warns when told to bind wider, because it runs recon with the
  operator's credentials and has no authentication.
- **`modules.py`**: the module registry, served to the page over `/api/modules`. A tab can no longer
  exist for a module that is not in the CLI, which is how the console shipped advertising Reverse
  Image and Audio tabs for modules that were never built. The page also gained the real modules that
  had no tab at all — website, IP and OPSEC.
- `email.py` renamed to **`email_recon.py`**. The filename shadowed the standard library `email`
  module, which broke anything importing it — Werkzeug does so through `http.server`, and the Flask
  console could not start until this was fixed. The public function name and the `email` CLI keyword
  are unchanged. `tests/test_no_shadowing.py` guards against a recurrence.

## [1.1.1] - 2026-08-27

### Fixed

- **Directory wordlists**: `website` now prefers a local SecLists
  `directory-list-2.3-medium` when one is present instead of always falling back to the small bundled list.
- **`--top-ports`**: top-port selection is honoured again on the IP module.
- **File hashes**: `metadata` reports MD5 and SHA-256 for the inspected file.
- **Case store encryption**: stored snapshots are encrypted at rest rather than written as plaintext JSON.
- **PhoneInfoga JSON parsing**: output is parsed as structured JSON instead of scraped, so a field
  appearing in more than one section no longer overwrites the earlier value.
- **URL verification**: dead-link re-verification no longer discards every result on a single failure.

### Known issues found in this release

- `phone()` raised `NameError` because the `def _ignorant(number)` header was lost, leaving the
  function body unreachable after the `return` in `_phoneinfoga`. The function is restored; the
  module-level entry point had been unusable since this commit.

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
