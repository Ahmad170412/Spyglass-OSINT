# 🔭 Spyglass

> **The OSINT unified CLI — email, username, phone, website, IP, metadata, dark web, and OPSEC, all in one place.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OSINT](https://img.shields.io/badge/OSINT-recon-purple)](https://github.com/Ahmad170412/Spyglass-OSINT)
[![Tools](https://img.shields.io/badge/tools-20%2B-orange)](https://github.com/Ahmad170412/Spyglass-OSINT)
[![Modules](https://img.shields.io/badge/modules-9-success)](https://github.com/Ahmad170412/Spyglass-OSINT)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](https://github.com/Ahmad170412/Spyglass-OSINT)

Hey there. OSINT usually means juggling 15 different tools across 5 terminals, each with its own output format, its own flags, its own way of doing things. Spyglass fixes that.

It wraps **holehe, user-scanner, sherlock, maigret, blackbird, PhoneInfoga, Ignorant, Shodan, nmap, dig, whois, curl, gobuster, httpx, exiftool, LeakCheck, Scylla, ip-api.com, crt.sh, HackerTarget, CertSpotter, the Wayback Machine, Ahmia, and Pwned Passwords** into a **single, unified CLI** — one interface, one output format, one place to run everything.

No more context switching. No more copy-pasting between tools. Just pick a target and go.

---

## 🔭 Quick start

**One command (recommended):**

```bash
git clone https://github.com/Ahmad170412/Spyglass-OSINT.git
cd Spyglass-OSINT
./setup.sh
```

`setup.sh` installs the external tools (brew on macOS, apt on Debian/Ubuntu), creates a venv with the Python tool packages, clones blackbird, and adds a `spyglass` launcher to `~/.local/bin`. It's safe to re-run.

**Manual:**

```bash
cd Spyglass-OSINT
pip install -r requirements.txt
cd ..          # -m needs the directory that *contains* the package
python -m Spyglass-OSINT
```

> The package name is the checkout directory name, so it must match. It is also
> not a valid Python identifier, which is why every invocation goes through
> `python -m <dir-name>` rather than a plain `import`. That also means it has to
> run from the *parent* of the checkout — `python -m Spyglass-OSINT` from inside
> the directory fails with `No module named`, which is expected rather than a
> broken install. The `spyglass` launcher from `setup.sh` has no such constraint.
> Renaming the checkout is supported; the test suite reads the name from the
> filesystem and follows a rename without edits.

Pick a module from the menu and go. If something's missing, the tool tells you what to install.

---

## 🔭 What it can do

| Module | What it checks | Engines |
|---|---|---|
| `email` | Where is this email registered? Any breaches? Any public identity? | holehe + user-scanner + blackbird + Gravatar + LeakCheck + Scylla |
| `username` | Which platforms have this profile? | user-scanner + sherlock + maigret + blackbird |
| `phone` | Who owns this number? Carrier? Region? Any footprints? | phonenumbers + PhoneInfoga + Ignorant |
| `website` | Deep recon: DNS, subdomains, ports, headers, tech stack, TLS, content, WHOIS, history, **known CVEs** | dig + curl + nmap + whois + gobuster + crt.sh + HackerTarget + CertSpotter + Wayback CDX + Shodan + NVD |
| `ip` | Where is this IP? Reverse DNS? Open ports? | ip-api.com + dig + whois + Shodan + nmap |
| `metadata` | What's hidden in this file? GPS, camera, document author? | exiftool + Pillow + PyPDF2 + python-docx/openpyxl |
| `darkweb` | Search the .onion index; check breaches and breached passwords | Ahmia + Pwned Passwords + LeakCheck + Scylla (+ IntelX / HIBP optional) |
| `opsec` | Am I leaking my real IP? Is my proxy working? | dig + curl + ip-api.com + torsocks |

### The website module, in depth

`website` goes well beyond the old "DNS + headers" pass:

- **Subdomain discovery** — subfinder (52 passive sources) plus crt.sh, HackerTarget, CertSpotter and the Wayback Machine CDX index, then active wordlist brute (gobuster, or a native resolver), wildcard-DNS detection, and an AXFR zone-transfer attempt.
  Every passively-discovered name is **DNS-resolved before it is reported**. This matters more than the source count: subfinder returns 22,250 names for `example.com` and they are almost entirely certificate-log and archive entries for hostnames that were never live. Unfiltered that is noise; filtered, the same target reports 1. A canary probe suppresses the list entirely on a wildcard domain, and the resolution pass is capped at 1,500 lookups with the remainder reported as unchecked rather than dropped.
- **Fingerprinting** — security-headers audit, cookie-flag analysis, CSP domain extraction, ~40-signature tech-stack detection, a Shodan-compatible favicon hash, and TLS certificate analysis (subject, issuer, SANs, expiry, version, cipher).
- **Known vulnerabilities** — the fingerprint phase now captures *versions*, not just product names, and asks the NVD which published CVEs actually cover them. Reports severity, CVSS score, affected range, and references. Opt out with `--no-vulns`, widen with `--cve-cap N`, or supply `--nvd-key KEY` to lift the rate limit.
- **Content discovery** — robots.txt and sitemap parsing, exposed-file checks (`.git/config`, `.env`, `.DS_Store`, backups), and JS endpoint + hardcoded-secret extraction.
- **History** — Wayback CDX snapshots: first/last seen, count, and historical subdomains.
- **DNS depth** — SPF/DMARC/CAA/DNSSEC parsing (reveals third-party email senders), reverse PTR, and adjacent `/24` host sweeps.

Every probe is independent and best-effort: a missing tool, an offline API, or a refused connection degrades to "not present" instead of crashing the run.

### The CVE lookup, and why it reports ranges

`cve.py` resolves the versions the fingerprint phase found against the NIST
National Vulnerability Database. Two details are worth knowing, because both
change how the output should be read.

**NVD's matching is verified, not trusted.** Queries use NVD's `virtualMatchString`
rather than a plain CPE lookup, because most advisories are written as a version
*range* (`versionStartIncluding` / `versionEndExcluding`) and a plain CPE query
cannot express one.

But `virtualMatchString` does not always apply those bounds. Measured during
development: a query for **nginx 1.31.3** came back with CVE-2009-3555, whose
recorded range stops at 0.8.22. So every hit is re-checked against the bounds NVD
itself recorded and dropped if it does not demonstrably cover the detected
version. There is deliberately **no wildcard-version fallback** — matching every
advisory ever published for a product is the exact failure being avoided. A
current nginx reports zero CVEs; nginx 1.13.2 reports ten.

This is a trade in the conservative direction. A missed advisory is recoverable
by reading the vendor's own release notes; a false CVE claim in a dossier is not
distinguishable from a real one without checking it by hand.

**The affected range is authoritative; the advisory prose is not.** NVD
routinely *widens* a version range after publication while the description text
keeps its original wording. A PHP 7.4.3 install is correctly flagged for
CVE-2017-8923, whose description still reads "PHP through 7.1.5" — the
structured data says the real range is `< 7.4.24`. Spyglass prints that range
next to every advisory precisely so the result does not look like a false
positive.

**Rate limits are the constraint.** Anonymous NVD allows 5 requests per rolling
30 seconds, so requests are spaced rather than parallelised and the number of
queried products is capped (default 3, server-side components first). An
`NVD_API_KEY` raises the ceiling to 50. This is also why the lookup is skipped
entirely when no versioned component was detected — a CDN-fronted site hides the
origin's version, and there is nothing to match.

Coverage is limited to products with a version visible in a header or the page
body, and to the CPE vendors listed in `cve.py`. A wrong vendor returns nothing
rather than something unrelated, so the table errs toward silence.

### The web console

`webapp.py` is a Flask front end over the same modules the CLI calls. It is a
transport, not a second implementation: every route calls the module function
the terminal calls and returns the same dict, so the browser can never see a
shape the CLI cannot.

```bash
pip install flask
python webapp.py                 # http://127.0.0.1:5000
python webapp.py --port 8080
```

The module list lives in `modules.py` and is served to the page over
`/api/modules`, so a tab cannot exist for a module that is not in the CLI. Adding
a tab means adding a row there and a route in `webapp.py`; the page needs no
change, because the result renderer is a generic walker over the nested dicts
every module already returns.

Binds to loopback by default. The console runs recon against arbitrary targets
with the operator's own network and credentials and has no authentication, so
`--host 0.0.0.0` prints a warning and should not be used casually. Nothing is
cached and nothing is written, which keeps the case store's opt-in contract
intact. `--no-vulns` matters more here than on the CLI: a website pass with the
NVD lookup can exceed a minute once rate limiting is accounted for.

### The dark web module

`darkweb` searches the *index* of the dark web without ever connecting to an `.onion` service:

- **Ahmia** — search the Tor hidden-service index (clearnet, keyless). Returns `.onion` URLs plus title/description/last-seen metadata only.
- **Pwned Passwords** — k-anonymity breach check. Only the first 5 chars of the SHA-1 hash leave your machine; the password is never logged, stored, or shown.
- **Breach attribution** — LeakCheck + Scylla for email / username / phone.

Two optional, keyed layers (skipped cleanly unless the env var is set): **IntelX** (`INTELX_API_KEY`, free tier) and **HaveIBeenPwned** (`HIBP_API_KEY`). The keyless path works out of the box.

### Why you'd use this

Spyglass isn't another OSINT tool — it's a **unified command center** for the ones that already exist.

- **One interface** — Every tool speaks the same language. Same flags (`--json`, `--csv`, `--report`, `--store`, `--proxy`), same output format, same menu.
- **Parallel execution** — Running holehe + user-scanner + blackbird + LeakCheck + Scylla for one email? That happens simultaneously, not sequentially. Each module's independent probes are run concurrently, and website recon runs its phases in parallel.
- **Smart merging** — Results are deduplicated and ranked by cross-tool agreement. If all username tools found the same profile, that goes to the top. Agreement tiers are labelled with the tools that matched (`Sherlock + Maigret`, `user-scanner only`) rather than raw bucket keys, since `us_only` reads as *United States* only.
- **Verified, not just reachable** — Username and email hits are re-fetched and checked against bot-challenge interstitials, not-found titles, empty app shells, and whether the page actually mentions the handle being searched. A 200 is not treated as proof a profile exists.
- **Persistent dossiers** — `--report` writes every module's findings to a clean Markdown dossier you can save, compare, and hand off between engagements.
- **Privacy-aware** — Built-in proxy/Tor support with OPSEC verification. Check if you're actually anonymous before you start.

---

## 🔭 Usage

All examples below assume you are in the directory that *contains* the checkout
(see the note in Quick start), or that you are using the `spyglass` launcher.

### Interactive menu

```bash
python -m Spyglass-OSINT
```

```
  [1]  Identity              (email, username, phone, dark web)
  [2]  Infrastructure        (website, IP)
  [3]  Utilities             (OPSEC, metadata, help, clear)
  [4]  Exit

Select [1-4]:
```

Each sub-menu has a **Back** option to return here.

### One-shot commands

```bash
python -m Spyglass-OSINT email user@example.com
python -m Spyglass-OSINT ip 1.1.1.1 --json --proxy socks5://127.0.0.1:9050
python -m Spyglass-OSINT username johndoe --csv
python -m Spyglass-OSINT website example.com --report
```

Works with: `email`, `username`, `phone`, `website`, `ip`, `metadata`, `darkweb`, `opsec`.

### Known-vulnerability lookup

```bash
python -m Spyglass-OSINT website example.com                # CVEs on by default
python -m Spyglass-OSINT website example.com --no-vulns     # skip the lookup
python -m Spyglass-OSINT website example.com --cve-cap 8    # query more products
python -m Spyglass-OSINT website example.com --nvd-key KEY   # lift the rate limit
```

| Flag | Effect |
|---|---|
| `--no-vulns` | Skip the NVD lookup entirely (faster, no API calls) |
| `--cve-cap N` | How many products to query (default 3) |
| `--nvd-key KEY` | NVD API key; raises the rate limit from 5 to 50 per 30s |

Check the version:

```bash
python -m Spyglass-OSINT --version
```

### Proxy / Tor

Add `--proxy socks5://127.0.0.1:9050` to any command (or set env var `ALL_PROXY`).
Spyglass routes dig, nmap, and whois through `torsocks` automatically.
The OPSEC module can verify your proxy is actually hiding you.

### Dark web search

```bash
python -m Spyglass-OSINT darkweb user@example.com
python -m Spyglass-OSINT darkweb example.com --type domain --report
```

The target type (`email`, `username`, `phone`, `domain`, or `ip`) is auto-detected, or set it explicitly with `--type`.

Check whether a password has been breached (read from the terminal, never stored):

```bash
python -m Spyglass-OSINT darkweb --password
```

### Export & reports

```bash
python -m Spyglass-OSINT email user@example.com --json
python -m Spyglass-OSINT ip 1.1.1.1 --csv
python -m Spyglass-OSINT website example.com --report
```

`--json` and `--csv` save a timestamped data file; `--report` writes a human-readable Markdown dossier in the current directory. All three can be combined.

### Case store (persistence)

Add `--store` to any query to persist the result to a local SQLite case store (default `~/.spyglass`, override with `SPYGLASS_HOME`). The store keeps a full JSON snapshot per run plus an entity index, which powers time-series queries:

```bash
python -m Spyglass-OSINT website example.com --store   # store a run
python -m Spyglass-OSINT cases list                    # every stored target
python -m Spyglass-OSINT cases diff example.com --type website   # added/removed entities
python -m Spyglass-OSINT cases timeline example.com    # change history
python -m Spyglass-OSINT cases export example.com      # stable JSON profile
```

The store is **opt-in** — nothing is written to disk unless you pass `--store` (recon results are sensitive; ephemeral-by-default is a deliberate choice).

---

## 🔭 Project structure

```
Spyglass-OSINT/
├── __main__.py          CLI entry — state machine, arg parser, menu dispatch
├── display.py           Rich TUI — banner, prompts, show_* functions
├── utils.py             Proxy system, tool paths, subprocess runner, extraction helpers
├── email_recon.py        Email recon (named to avoid shadowing stdlib `email`)
├── username.py          Username recon
├── phone.py             Phone recon
├── website.py           Website recon (subdomains, fingerprinting, content, history, CVEs)
├── cve.py               NVD version-to-CVE matching for detected components
├── webapp.py           Flask web console
├── modules.py           Module registry shared by the console and its API
├── index.html           Web console front end
├── ip.py                IP recon
├── metadata.py          Metadata extraction
├── darkweb.py           Dark web index search + breach/password checks
├── breach.py            Breach checking — LeakCheck + Scylla
├── opsec.py             OPSEC health check
├── export.py            JSON / CSV export
├── report.py            Markdown dossier generation (--report)
├── store.py             SQLite case store (--store, cases diff/timeline/export)
├── tests/               Unit tests (stdlib unittest, no network needed)
├── requirements.txt     Python dependencies
├── README.md            This file
├── LICENSE              MIT license
└── .gitignore           Git ignore rules
```

---

## 🔭 Requirements

Python 3.9+ and `pip install -r requirements.txt`. External tools are auto-detected — install whatever modules you need. The tool tells you what's missing.

Spyglass targets **macOS and Linux only** — it leans on POSIX tools (`dig`, `curl`, `whois`, `nmap`, `gobuster`, and friends) that are standard on those platforms. **Windows is not supported.** `curl` is required for the network-based modules.

---

## 🔭 Legal disclaimer

This tool is for **authorized security research and educational purposes only**.
You are responsible for complying with all applicable laws in your jurisdiction.
Do not use this tool against targets without explicit permission.

---

## 🔭 Found this useful?

If Spyglass saved you time or helped you learn something, consider **starring the repo** — it lets me know people find this useful and helps others discover it.

Contributions, ideas, and bug reports are welcome.

---

## 🔭 License

MIT — use it, learn from it, build on it.
