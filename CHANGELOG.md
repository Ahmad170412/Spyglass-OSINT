# Changelog

All notable changes to Spyglass are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Three sources, closing the three gaps that mattered.** All keyless, all
  verified against live responses before being written, and all added because
  the audit found a whole *category* missing rather than one more of what was
  already there.
  - **RapidDNS — passive DNS, which the module did not have at all.** Every
    existing subdomain source answers "what names are published somewhere".
    This one answers "what did these names actually resolve to, and when did
    anyone last see them", as `(name, ip, record type, last-seen)` — which is
    what surfaces a host still pointing at a former owner's cloud bucket.
    Reported per name with its date, so a record that has not moved in four
    years is visible *as* a four-year-old record. Indexed into the store's `ip`
    entities, because a name moving to a new address is exactly the change
    `cases diff` should notice, and the one a live re-scan would miss.
    - **AlienVault OTX was the intended source and is no longer keyless**: its
      `passive_dns` endpoint now answers `Anonymous access to this endpoint is
      limited. Please authenticate.` OTX has better coverage and is worth adding
      as a *keyed* optional alongside IntelX and HIBP; RapidDNS needs nothing
      and is an HTML scrape, which this module already does for crt.sh and
      CertSpotter.
    - Names outside the target's own domain are rejected, and matching requires
      a label boundary — a RapidDNS table lists the registrable domain and its
      siblings, and a suffix match would attribute a stranger's host to the
      target, which is the bug the subdomain scope check once had.
  - **urlscan.io — passive page observations, historical tech, and mentions.**
    Free, no key. Contributes three things nothing else here produces: addresses
    and ASNs a third party's crawler saw, timestamped; **historical `Server`
    headers**, which is a passive tech fingerprint and is most valuable exactly
    when the live one is hidden behind a CDN; and `referenced_by`.
    - **`referenced_by` is kept separate from assets and never merged into
      them.** urlscan's `domain:` operator also matches pages that *link to* the
      target, so results whose `page.domain` is someone else are third-party
      mentions — a status page, a paste, a review, a directory listing. Filing
      those as the target's infrastructure is the same class of misattribution
      the suffix-matching subdomain bug was.
    - Repeated scans of one URL collapse to a single row keeping the most recent
      scan and summarising the addresses seen. Reported raw, the table opens on
      the same link four times against four anycast addresses.
  - **ipwho.is — a second geolocation opinion.** `ip-api.com` was the *only*
    place the `ip` module got a location from, so a rate-limit, a block or an
    outage removed the entire geo block with no signal that anything had
    failed. It also returns `connection.asn`, a free cross-check on the `asn`
    module. The source now travels with the answer, because the two genuinely
    disagree: on `8.8.8.8` ip-api.com reports Ashburn, Virginia and ipwho.is
    reports San Jose, California, on opposite timezones. Both agree on AS15169.
  - **No keyless second RPKI source was found, and that is the honest result.**
    Cloudflare's RPKI validity API returns 404 on every path tried, BGPView
    returns nothing, and BufferOver is dead. RPKI validity therefore remains
    single-sourced to RIPEStat. `ipwho.is` covers the *origin AS* half with
    redundancy; the validity verdict itself does not, and the `asn` module says
    so rather than implying coverage it does not have.
  - `tests/test_sources.py`, 19 tests. Every fixture is a trimmed real response
    — a fixture that does not match the live shape pins the wrong contract.

- **Spyglass is now a real, installable Python distribution** (`pyproject.toml`).
  It could not be installed at all before: there was no packaging metadata, and
  the checkout directory was `Spyglass-OSINT`, which is not a valid Python
  identifier. `import Spyglass-OSINT` is a syntax error, so the only supported
  invocation was `python -m Spyglass-OSINT` from the *parent* of the checkout.
  That ruled out pip, pipx, CI, Docker, and use as a library by anything else.
  - The distribution is **`spyglass-osint`** on PyPI and the import package is
    **`spyglass/`**. The two names are deliberately different — the PyPI name
    carries the `-osint` suffix the import name does not need, the same shape as
    `beautifulsoup4`/`bs4`. The checkout directory name no longer has to match
    anything.
  - Three entry points, all verified against an installed wheel rather than the
    source tree: the `spyglass` console script, `python -m spyglass`, and
    `import spyglass`. The checkout can now be renamed freely.
  - **Dependencies are split into extras** instead of one flat list. Only
    `rich`, `phonenumbers` and `cryptography` are required; the recon engines
    (`[tools]`), the web console (`[web]`) and the document/EXIF formats
    (`[metadata]`) are opt-in, plus `[all]`. Installing `holehe` and `maigret`
    by default drags in large dependency trees to print a version banner, which
    is how a tool gets uninstalled. Every module already degraded gracefully
    when its tool was missing, so the extras match how the code behaves.
  - `cryptography` is a declared requirement even though `store.py` still
    tolerates its absence. Without it the case store silently falls back to
    plaintext on disk, and a recon tool should not make that trade quietly. The
    guard stays so a minimal install still works.
  - `index.html` is declared as package data. `webapp.py` serves the console
    with `send_from_directory`, so a wheel without it installs a web console
    that 404s on its own front end — a failure no unit test calling a module
    function would ever have caught.
  - `tests/test_packaging.py`, 8 tests. Each pins a way a distribution can be
    silently wrong, and the sharpest one is a guard against **modules left at
    the repository root**: a `.py` file there builds cleanly, imports fine from
    a checkout, and is simply absent from the installed wheel. The guard is
    verified to fail when it should rather than merely passing.

- **`asn` module** (`asn.py`): the BGP layer that sat between `ip` and `website`.
  `ip` answers "where is this address" and `website` answers "what is running
  there"; neither could say *who routes it*, which is what decides whether an
  address belongs to the target, to its host, or to a transit provider three
  hops away. Everything is a keyless GET against RIPEStat, so there is nothing
  to configure and no API key to manage.
  - Accepts an IP, a CIDR prefix, or an AS number in one argument, and reports
    which reading it took in `query_type`. A bare address is kept distinct from
    a prefix: `ipaddress.ip_network` accepts `8.8.8.8` and returns a /32, so
    testing the network form first would report every IP as a prefix and leave
    the `ip` branch unreachable.
  - **RPKI validity is the reason this module exists.** A route whose origin has
    a matching ROA is protected — an upstream receiving a conflicting
    announcement will reject it. A route with `status: invalid` has a ROA naming
    a *different* origin, which is what a hijack looks like. It is the only
    finding in Spyglass that reports a weakness rather than a fact about the
    target, and it is the only output here that is not a lookup.
    - `valid`, `invalid` and `unknown` are kept distinct, and the summary sorts
      worst-first so a conflicting ROA is not buried under prefixes that are
      fine. No ROA is reported as `unknown`, never as safe: absence of RPKI data
      is not evidence of safety.
    - An AS-only query reports **no** RPKI result and says why. Validation is
      defined per prefix against an origin, so an AS alone has nothing to
      validate, and answering "valid" there would be the one result in this tool
      that looks like a safety verdict and is not one.
  - `covering_prefixes` gives the less-specific chain above the matched prefix
    (RIPE's own `related_prefixes`), so the aggregation level is visible rather
    than implied.
  - `announced_prefixes` reports the operator's footprint as a *size*, because
    that is the only honest presentation: AS15169 announces 1,415 prefixes and
    Cloudflare 5,484. The list is sampled, biased towards the address family of
    the input with a few of the other family kept so a dual-stack operator is
    visibly dual-stack, and the true total is always reported. Prefixes that do
    not parse are dropped from the count so `total` always equals the family
    split and the "showing N of M" note adds up.
  - **It joins the entity index on `org`.** The holder is the same organisation
    string WHOIS produces, so an `asn` run and a `website` run on the same
    operator land on a shared value and a cross-module `cases diff` can connect
    them. New kinds: `asn` and `prefix`.
  - RPKI results are sorted by origin, because a thread pool finishes futures in
    arbitrary order and a result that reorders itself between two runs of one
    target reads as a change that never happened.
  - Registered across all six surfaces: CLI one-shot and Infrastructure menu,
    `display.show_asn`, `report._render_asn`, the store, the module registry and
    a `/api/asn` route. It reuses the existing `net` icon; there is no routing
    glyph in the console's sprite.
  - 29 offline tests. Every fixture is a real RIPEStat response — a fixture that
    does not match the live shape pins the wrong contract — covering target
    parsing, message preservation on an `ok`-but-empty response, MOAS, the
    origin cap, stable ordering, footprint sampling, and the refusal to invent
    an RPKI verdict.

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
- **Registry consistency is now tested.** `modules.py` exists so a console tab
  cannot exist for a module the CLI lacks — the failure it was written to
  prevent, where the page advertised Reverse Image and Audio tabs for modules
  that were never built. Nothing enforced that, so it was one forgotten row away
  from recurring. Five tests now check that ids and ordinals are unique, that
  every module has an `/api/<endpoint>` route, that every route has a registry
  row, and that every module is in the CLI's one-shot whitelist. The whitelist is
  parsed out of `__main__.py` rather than restated, so the test cannot drift from
  the code it checks.
- **`--help` / `-h`** prints usage, the module list, and every flag, then exits 0. Previously the flag
  was unrecognised, so it fell through to the positional branch and dropped the user into the
  interactive menu instead of printing anything — and `setup.sh` advertised the very invocation that
  hung. It now also documents the flags that had no reference anywhere: `--top-ports`, `--no-vulns`,
  `--cve-cap`, `--nvd-key`.
- **`spyglass opsec` works as a one-shot command.** `opsec` was a full `_run_query` branch reachable
  from the Utilities menu, but was missing from the non-interactive module list, so the only way to run
  it was interactively. It is keyless, so it needed its own branch rather than the two-positional form.
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

- **`/api/modules` returned HTTP 500 whenever the console was imported rather
  than executed.** The route did `from modules import MODULES` — a bare
  absolute import, while every other module in the package imports relatively.
  It resolved only because `python webapp.py` puts the script's own directory on
  `sys.path`, so the flat layout made the bug invisible. Any other way of
  loading the console — `python -m`, a WSGI server, the test suite, or simply an
  installed copy, where the package directory is not a top-level name — 500'd on
  the one request the page makes on load. Now a relative import.

- **`--version` and `--help` required the `phonenumbers` package.** `__main__.py`
  imported `phone` at module scope and `phone.py` imports `phonenumbers`
  unconditionally, so on any install without it both flags exited 1 with a
  `ModuleNotFoundError` instead of printing anything. That is also why
  `test_version.py` failed in a bare checkout. The import is now local to the
  phone branch, so a missing engine breaks the phone module alone — the same
  rule `webapp.py` already documented for its own handlers, which the CLI should
  not have been laxer about.

- **`python spyglass/webapp.py` 500'd on the console's first request.** Making the
  `/api/modules` import relative (see above) fixed the installed console but broke
  the script form the README documented: a script run sets `__name__` to
  `"__main__"` with no parent package, so the handlers' relative imports raise
  `ImportError: attempted relative import with no known parent package` — at
  *request* time, not import time, so the console booted, served its HTML, and
  then failed the one request the page makes on load. The `__main__` guard now
  puts the package's parent on `sys.path` and re-imports under the real name.
  Both `python -m spyglass.webapp` and `python spyglass/webapp.py` are verified
  to return 200 on `/api/modules`; the README now leads with `-m`.

- **`ignorant>=2.0` is not a version that exists.** The newest release is 1.2,
  which is the last one shipping the `ignorant` console script `phone.py`
  invokes, so the pin was unsatisfiable. `pip install -r requirements.txt` failed
  on the line, and `setup.sh` reported the failure as a warning and continued —
  meaning the phone module has been running without its footprint source for the
  entire time it was listed. Corrected to `>=1.2` in `pyproject.toml`,
  `requirements.txt` and `setup.sh`.

- **`test_no_shadowing.py` could not fail.** It scanned
  `os.path.dirname(_PKG_DIR)` — the directory *containing* the package — which
  has never held a `.py` file in any layout this project has used, so the
  offender list was always empty and the guard would have passed with `email.py`
  sitting right beside it. It now scans the package directory, and a second test
  asserts the scan found the modules at all, so pointing it at the wrong
  directory again is caught rather than assumed.

- **The case store indexed only 5 of 8 modules.** `_entities` was an `if/elif`
  chain with branches for email, username, website, ip and darkweb, so `phone`,
  `metadata` and `opsec` stored a run with an empty entity index. `cases diff` and
  `cases timeline` then reported zero entities for those targets and were
  indistinguishable from a target that had not changed — the commands worked and
  said nothing. All three now produce a real index:
  - **`phone`** indexes the number in E.164 and, more usefully, the sites
    `ignorant` reports it registered on — a set that grows, and watching it grow
    is the reason to re-run a phone target.
  - **`metadata`** indexes file digests and GPS. Digests are the valuable half:
    the same file under two case targets links those cases, and a changed digest
    between two runs says the evidence was swapped. GPS latitude/longitude are
    signed by their hemisphere ref, since exiftool reports the magnitude
    unsigned and an unrefed southern position lands on the wrong side of the
    equator.
  - **`opsec`** indexes the operator's own addresses under a new `operator_ip`
    kind rather than `ip`. opsec reports the machine running Spyglass, and a
    cross-module `cases diff` on a target would otherwise show the operator's
    address appearing and disappearing alongside the target's own infrastructure
    — the same misattribution as the suffix-matched subdomain bug above.
- **Adding a module no longer requires touching the store.** Extraction is now a
  per-module registry plus a bounded shape-inference fallback, so a module that
  ships without a rule is diffable from day one. A rule is worth writing only
  where inference is wrong or too noisy, which turns the entity index from a
  per-module chore into a default. The walker unwraps URLs to their host and
  splits comma-joined fields, so it reaches the same values the explicit rules
  do, and skips `_`-prefixed phase-handoff keys.
  - Inference cannot distinguish a domain from a filename — `evidence.pdf`
    satisfies every structural rule — so a bounded list of extensions that are
    also valid TLDs is excluded. This only constrains inference; an explicit
    extractor is never second-guessed.
  - The walk budget is a per-pass cell threaded through the recursion, not a
    module global. As a global, the first result walked exhausted it and every
    later walk indexed nothing, which in the long-running web console would
    have silently emptied the index from the second `--store` run onward. A
    regression test covers it, because only a *second* call can catch it.
  - `ip` runs now also index reverse-DNS names from `a_records`. This is additive:
    existing `ip` diffs will show these once, on the first run after upgrading.

- **`phoneinfoga` no longer contributes nothing.** `phone.py` called `json.loads` without importing
  `json`. The resulting `NameError` was swallowed by the bare `except` around the parse, so the probe
  returned `{}` on every run and the engine was invisible rather than broken — it read as "PhoneInfoga
  found nothing" on every number. The test suite missed it because `test_phone.py` only covered
  `_phonenumbers_info` and `_ignorant`; it now covers the JSON parse path, including the
  array-shaped output PhoneInfoga emits in some versions.
- **`--cve-cap N` is no longer a lookup failure.** The flag's value stayed a string all the way into
  `ranked[:cap]`, raising `TypeError`, which the caller swallowed into `{"vulns": {"status": "error"}}`.
  Asking for a cap of 8 produced a CVE error block instead of eight products' worth of results. Numeric
  flags are now coerced once at the parse boundary; a non-numeric value is treated as a typo and falls
  back to the default rather than failing the run. `--top-ports` had the same shape and is fixed with
  it (it happened to survive, because `ip.py` re-stringified it).
- **`NVD_API_KEY` now works on the command line.** The variable lifts the NVD rate limit from 5
  requests per 30 seconds to 50, and both the README and this module's docstring promise it. It was
  only ever read as a function argument, and the CLI never supplied one — the web console happened to
  wire up the environment, so the documented variable silently did nothing in the terminal and every
  lookup ran at the anonymous ceiling. `cve.check()` now falls back to the environment; an explicit
  `--nvd-key` still wins.
- This changelog listed the web console, `modules.py`, and the `email_recon.py` rename under
  **  Removed** when all three are present and current, and carried two separate `### Fixed` headings.
  The headings now match their contents.
- **Tool discovery no longer depends on PATH.** pip's `--user` scheme and the
  python.org Framework installers put console scripts in per-version directories that are often absent
  from PATH. Sherlock, maigret, holehe and ignorant all land in `~/Library/Python/3.13/bin` on macOS,
  and with that directory missing from PATH every one of them was silently skipped — the username
  module reported "user-scanner only" because three installed, working engines could not be found.
  `utils._which()` now falls back to the user-site, Framework, pyenv and Homebrew script directories.
  Verified: 16/16 tools resolve with a near-empty PATH.
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
    what catches an app whose shell contains no profile data. The handle must appear more than once,
    because a single mention is what a soft-404 serves trivially: `mastodon.social/@<handle>`
    answers 200 with 50KB, no error marker, and reproduces the requested handle exactly once, while a
    real profile mentions it 133 times. A dotted handle is unaffected — the term is matched as a plain
    substring.
  - **URL verification no longer rejects real profiles.** The bot-challenge check was a whole-body
    substring scan, and a bare `captcha` matched GitHub's own feature flag
    `octocaptcha_origin_optimization` in the JS payload — so every genuine GitHub profile was rejected.
    Challenge detection is now title-based (an interstitial names itself) with a short list of
    specific body markers. Positive control: three real pages that contain the search term now survive,
    having all failed before.
  - Not caught, and documented as such: catch-all profile routes that serve a genuinely valid
    profile for a different identity. No generic signal distinguishes those; it needs per-platform
    knowledge.
  - Rejections are now reported by reason rather than silently shrinking the result set.
  - Fetches send a browser User-Agent; a default curl UA is rejected outright by some platforms and
    was indistinguishable from a missing profile.
- **`phone()` no longer raises `NameError`** (also fixed in 1.1.1's successor): the `def _ignorant`
  header had been lost, leaving the body unreachable after `return` in `_phoneinfoga`.

### Changed

- **Spyglass is passive. It no longer probes the target.** `nmap` and `gobuster`
  are gone, and so is the dead `nuclei` probe. Nothing in the package sends a
  port scan, a directory brute-force, or a vulnerability template at a host.
  Every finding is now something already published or already scanned by someone
  else. This is a deliberate posture change, and it is the reason the removals
  below are mostly cheap.
  - **Open ports did not disappear, and got better.** `nmap` is replaced by
    **Shodan InternetDB** (`internetdb.shodan.io`), which needs no API key and
    has no rate limit. This is strictly more available than what it replaced:
    the Shodan *CLI* the ip module already used requires `shodan init`, so on a
    machine where nobody had configured a key the module reported no ports while
    appearing to have worked. InternetDB returns ports, hostnames, product CPEs
    and tags — for 1.1.1.1 that is nine ports, four hostnames, a CPE, and for a
    Tor exit node the tags `tor` and `self-signed`.
  - **The honest cost: ports are now a historical record.** InternetDB reports
    what Shodan's own scan saw, so a port closed since then still reads as open,
    and an address Shodan has never scanned reports nothing at all — which is
    kept distinct from "no open ports" so the two never look alike in a dossier.
    The nmap `-sV` pass in the website module also read the live banner and gave
    a service *and version* per port; InternetDB identifies the product via CPE
    but not its build. Nothing downstream depended on that version —
    `cve.scan()` is fed HTTP headers and page body only and never sees
    port-scan output, so **no CVE coverage moves**.
  - **Directory brute-forcing is replaced by archived paths, which is a better
    source for the same data type.** `_phase_dirs` used to run gobuster against
    a SecLists wordlist and report whatever returned a status code. It now
    derives paths from the Wayback CDX result the module was already fetching:
    distinct first segments as `directories`, plus a capped `archived_paths`
    sample. A gobuster hit was a wordlist guess that got a response; an archived
    path is a URL that genuinely existed. Coverage is narrower — the archive
    only knows what a crawler reached — and the trade is that nothing is sent to
    the target. Paths are taken from the exact host only, so a subdomain's
    layout is never attributed to the target.
  - **The wordlist DNS resolve stays, and is the last active probe.** It resolves
    `word.host` for every entry, so the nameserver sees the lookups. gobuster
    did the identical thing as a subprocess, so removing gobuster does not make
    this passive — it just removes the subprocess. It is kept because passive
    sources genuinely miss hosts that were never published anywhere, which is
    the exact class a wordlist finds. Unchanged: it is skipped when a proxy is
    set, because in-process resolution would bypass torsocks and leak the
    operator's resolver.
  - **`--top-ports N` is removed**, and now warns instead of being silently
    accepted. It tuned the nmap scan and controlled nothing afterwards; a flag
    that parses and does nothing is how an operator ends up believing they ran a
    top-1000 port scan. `--help` gained a REMOVED section naming the
    replacement. `ip.address()` keeps the parameter only so existing callers do
    not break, and it is documented as ignored.
  - Removed with the gobuster path: `_DIR_LIST` and `_dir_wordlist()`, which
    existed only to feed it a wordlist. The nmap constant is gone from
    `opsec`'s Tor-safety check and from the `torsocks` proxy-routing set, and
    `_NUCLEI` — a `_which()` probe for a tool nothing ever called, which implied
    a capability the tool did not have.
  - **`subfinder` is now installed by `setup.sh`** on both platforms. It is the
    primary passive subdomain source and the README leads with its "52 sources",
    but setup was not installing it, so a fresh user got the crt.sh/CertSpotter
    fallback with no signal that the headline feature never ran. It is in the
    Homebrew list and a new `go install` branch on Debian, alongside httpx.
  - **The website docstring claimed AlienVault OTX as a source and it was never
    implemented.** The listed sources are now the ones that exist: crt.sh,
    CertSpotter, HackerTarget, subfinder, Wayback CDX and InternetDB.
  - The store's `ip` extractor now indexes InternetDB hostnames. A vhost on the
    same address is an asset neither the target's own DNS nor a subdomain sweep
    of its domain would surface.

- **All modules moved into a `spyglass/` package directory.** Every file used
  relative imports already, so no module body changed — but the layout is now a
  conventional one, which is what makes the distribution installable. The one
  real consequence: `tests/test_no_shadowing.py` and `tests/helpers.py` had to be
  pointed at the new location, and `helpers.py`'s reason for existing at all
  (importlib, because the old name was not a valid identifier) is now largely
  historical. It is kept because `tests/` is deliberately not shipped, so the
  suite still has to put the repository root on `sys.path` itself.
- **`requirements.txt` is now a reference file pointing at the extras** rather
  than an independent list that could drift. The authoritative set is
  `pyproject.toml`; the old `pip install -r requirements.txt` form still works.
  `shodan` was removed from it — `website.py` shells out to the Shodan *command
  line client*, it never imports the Python library of the same name, so the pip
  package satisfied nothing. `setup.sh` still handles the CLI via brew/apt.
- **`setup.sh` installs the package into its venv** (editable, `--no-deps`, so a
  single unavailable engine cannot fail the install) and the `~/.local/bin`
  launcher calls the `spyglass` console script, falling back to
  `python -m spyglass` from the checkout if the editable install did not take.
  The per-package install loop is unchanged and still best-effort by design.
- **README examples use `spyglass`, not `python -m <checkout-name>`.** The long
  note explaining that the checkout had to run from its own parent directory is
  gone, because the constraint it described no longer exists. The GitHub URLs and
  `git clone` lines still say `Spyglass-OSINT` — that is the repository name,
  which is correct.
- **`python -m unittest discover -s tests -t tests` runs the whole suite** — 320
  tests in about six seconds. It could not run before the rename, because
  discovery could not import a directory whose name was not a valid identifier,
  which is why the suite had to be run one file at a time.

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
