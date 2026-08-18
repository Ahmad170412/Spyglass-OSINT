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
pip install -r requirements.txt
python -m Spyglass-OSINT
```

Pick a module from the menu and go. If something's missing, the tool tells you what to install.

---

## 🔭 What it can do

| Module | What it checks | Engines |
|---|---|---|
| `email` | Where is this email registered? Any breaches? | holehe + user-scanner + blackbird + LeakCheck + Scylla |
| `username` | Which platforms have this profile? | user-scanner + sherlock + maigret + blackbird |
| `phone` | Who owns this number? Carrier? Region? Any footprints? | phonenumbers + PhoneInfoga + Ignorant |
| `website` | Deep recon: DNS, subdomains, ports, headers, tech stack, TLS, content, WHOIS, history | dig + curl + nmap + whois + gobuster + crt.sh + HackerTarget + CertSpotter + Wayback CDX + Shodan |
| `ip` | Where is this IP? Reverse DNS? Open ports? | ip-api.com + dig + whois + Shodan + nmap |
| `metadata` | What's hidden in this file? GPS, camera, document author? | exiftool + Pillow + PyPDF2 + python-docx/openpyxl |
| `darkweb` | Search the .onion index; check breaches and breached passwords | Ahmia + Pwned Passwords + LeakCheck + Scylla (+ IntelX / HIBP optional) |
| `opsec` | Am I leaking my real IP? Is my proxy working? | dig + curl + ip-api.com + torsocks |
| `investigation` | Everything above, cross-correlated | Runs all modules, connects the dots |

### The website module, in depth

`website` goes well beyond the old "DNS + headers" pass:

- **Subdomain discovery** — four passive sources in parallel (crt.sh, HackerTarget, CertSpotter, Wayback CDX) plus active wordlist brute (gobuster, or a native resolver), wildcard-DNS detection, and an AXFR zone-transfer attempt.
- **Fingerprinting** — security-headers audit, cookie-flag analysis, CSP domain extraction, ~40-signature tech-stack detection, a Shodan-compatible favicon hash, and TLS certificate analysis (subject, issuer, SANs, expiry, version, cipher).
- **Content discovery** — robots.txt and sitemap parsing, exposed-file checks (`.git/config`, `.env`, `.DS_Store`, backups), and JS endpoint + hardcoded-secret extraction.
- **History** — Wayback CDX snapshots: first/last seen, count, and historical subdomains.
- **DNS depth** — SPF/DMARC/CAA/DNSSEC parsing (reveals third-party email senders), reverse PTR, and adjacent `/24` host sweeps.

Every probe is independent and best-effort: a missing tool, an offline API, or a refused connection degrades to "not present" instead of crashing the run.

### The dark web module

`darkweb` searches the *index* of the dark web without ever connecting to an `.onion` service:

- **Ahmia** — search the Tor hidden-service index (clearnet, keyless). Returns `.onion` URLs plus title/description/last-seen metadata only.
- **Pwned Passwords** — k-anonymity breach check. Only the first 5 chars of the SHA-1 hash leave your machine; the password is never logged, stored, or shown.
- **Breach attribution** — LeakCheck + Scylla for email / username / phone.

Two optional, keyed layers (skipped cleanly unless the env var is set): **IntelX** (`INTELX_API_KEY`, free tier) and **HaveIBeenPwned** (`HIBP_API_KEY`). The keyless path works out of the box.

### Why you'd use this

Spyglass isn't another OSINT tool — it's a **unified command center** for the ones that already exist.

- **One interface** — Every tool speaks the same language. Same flags (`--json`, `--csv`, `--report`, `--store`, `--proxy`), same output format, same menu.
- **Parallel execution** — Running holehe + user-scanner + blackbird + LeakCheck + Scylla for one email? That happens simultaneously, not sequentially. Investigation mode runs all four identity modules concurrently, and website recon runs its independent phases in parallel.
- **Smart merging** — Results are deduplicated and ranked by cross-tool agreement. If all username tools found the same profile, that goes to the top.
- **Cross-correlation** — In investigation mode, Spyglass connects email domains to WHOIS orgs, phone regions to countries, username platforms to email platforms. It finds links you'd miss manually.
- **Persistent dossiers** — `--report` writes every module's findings to a clean Markdown dossier you can save, compare, and hand off between engagements.
- **Privacy-aware** — Built-in proxy/Tor support with OPSEC verification. Check if you're actually anonymous before you start.

---

## 🔭 Usage

### Interactive menu

```bash
python -m Spyglass-OSINT
```

```
  [1]  Identity              (email, username, phone, dark web)
  [2]  Infrastructure        (website, IP)
  [3]  Full investigation    (correlate everything)
  [4]  Utilities             (OPSEC, metadata, help, clear)
  [5]  Exit

Select [1-5]:
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

Check the version:

```bash
python -m Spyglass-OSINT --version
```

### Proxy / Tor

Add `--proxy socks5://127.0.0.1:9050` to any command (or set env var `ALL_PROXY`).
Spyglass routes dig, nmap, and whois through `torsocks` automatically.
The OPSEC module can verify your proxy is actually hiding you.

### Full investigation

Enter everything you know about a target:

```
> email: user@example.com, username: jdoe, phone: +6585260980
```

Or positional:

```
> user@example.com, jdoe, +6585260980, example.com
```

Spyglass runs every applicable module, extracts entities, and highlights cross-module connections.

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
├── email.py             Email recon
├── username.py          Username recon
├── phone.py             Phone recon
├── website.py           Website recon (subdomains, fingerprinting, content, history)
├── ip.py                IP recon
├── metadata.py          Metadata extraction
├── darkweb.py           Dark web index search + breach/password checks
├── breach.py            Breach checking — LeakCheck + Scylla
├── opsec.py             OPSEC health check
├── investigation.py     Full investigation orchestration + correlation
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
