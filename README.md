# Spyglass

> **Multi-tool reconnaissance — email, username, phone & website intelligence from your terminal.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Overview

Spyglass is a modular OSINT swiss-army knife that orchestrates **15+ external tools** in parallel, cross-references their results, and surfaces only what matters. Every query type runs multiple engines simultaneously and highlights **tool agreement** so you know which findings are reliable.

### What it can do

| Command | Engines | Output |
|---|---|---|
| `email` | holehe + user-scanner + blackbird + leakcheck.io | Sites registered + breach data, grouped by tool consensus |
| `username` | user-scanner + sherlock + maigret + blackbird + leakcheck.io | Social profiles across 400+ platforms, with 4-way agreement scoring |
| `phone` | phonenumbers lib + PhoneInfoga + Ignorant + leakcheck.io | Validation, carrier, location, web footprint, platform registrations |
| `website` | dig + Shodan + nmap + curl + whois + gobuster + httpx | DNS, open ports, HTTP headers, WHOIS, subdomains, directory busting |

### Why this exists

Running 4–5 OSINT tools manually and comparing their output is tedious. This wrapper **runs them concurrently**, **deduplicates results**, **verifies live URLs**, and **ranks findings by cross-tool agreement**. You get one answer instead of five spreadsheets.

---

## Installation

### 1. Clone

```bash
git clone https://github.com/yourusername/spyglass.git
cd spyglass
```

### 2. Python dependencies

```bash
pip install -r requirements.txt
```

### 3. External tools

The toolkit shells out to several industry-standard tools. Install what you need:

| Tool | Purpose | Install |
|---|---|---|
| [holehe](https://github.com/megadose/holehe) | Email registration check | `pip install holehe` |
| [user-scanner](https://github.com/megadose/user-scanner) | Email/username lookup | `pip install user-scanner` |
| [sherlock](https://github.com/sherlock-project/sherlock) | Username search | `pip install sherlock` |
| [maigret](https://github.com/soxoj/maigret) | Username search | `pip install maigret` |
| [blackbird](https://github.com/p1ngul1n0/blackbird) | Username/email search | `git clone https://github.com/p1ngul1n0/blackbird` |
| [PhoneInfoga](https://github.com/sundowndev/phoneinfoga) | Phone number recon | `brew install phoneinfoga` / [releases](https://github.com/sundowndev/phoneinfoga/releases) |
| [ignorant](https://github.com/megadose/ignorant) | Phone platform check | `pip install ignorant` |
| [Shodan](https://shodan.io) | IP intelligence | `pip install shodan` + `shodan init YOUR_API_KEY` |
| [nmap](https://nmap.org) | Port scanning | `brew install nmap` / `apt install nmap` |
| [gobuster](https://github.com/OJ/gobuster) | Subdomain & dir busting | `brew install gobuster` / `apt install gobuster` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing | `brew install httpx` / [releases](https://github.com/projectdiscovery/httpx/releases) |
| dig / curl / whois | System utilities | Pre-installed on macOS/Linux |

> **Tip:** Run the tool — if something's missing, it'll tell you exactly what and how to install it.

---

## Usage

```bash
python -m osint
```

Then type a query at the `>` prompt:

```
> email person@example.com
> username johndoe
> phone +15551234567
> website example.com
```

### Example output

```
> username johndoe

[*] Checking username: johndoe (5 tools in parallel)

  All 4 tools agree (4):
    github.com: https://github.com/johndoe
    twitter.com: https://twitter.com/johndoe
    reddit.com: https://reddit.com/user/johndoe
    keybase.io: https://keybase.io/johndoe

  user-scanner + sherlock agree (others missed) (2):
    dev.to: https://dev.to/johndoe
    medium.com: https://medium.com/@johndoe

  Only maigret found (3):
    hackernews: https://news.ycombinator.com/user?id=johndoe
    …

  Breach data: 3 databases (Collection #1 (2019), LinkedIn (2021), HaveIBeenPwned (2022))
  Exposed fields: email, password_hash, username, ip_address
```

---

## Project structure

```
spyglass/
├── __init__.py          # Package marker
├── __main__.py          # CLI entry point
├── email.py             # Email recon engine
├── username.py          # Username recon engine
├── phone.py             # Phone number recon engine
├── website.py           # Website recon engine
├── utils.py             # Shared helpers, tool paths, breach checker
├── requirements.txt     # Python dependencies
├── LICENSE              # MIT license
└── .gitignore           # Git ignore rules
```

---

## License

MIT — use it, learn from it, build on it.
