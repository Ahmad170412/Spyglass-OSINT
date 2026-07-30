# 🔭 Spyglass

> **The OSINT unified CLI — email, username, phone, website, IP, metadata, and OPSEC, all in one place.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OSINT](https://img.shields.io/badge/OSINT-recon-purple)](https://github.com/Ahmad170412/Spyglass-OSINT)
[![Tools](https://img.shields.io/badge/tools-15%2B-orange)](https://github.com/Ahmad170412/Spyglass-OSINT)
[![Modules](https://img.shields.io/badge/modules-8-success)](https://github.com/Ahmad170412/Spyglass-OSINT)

Hey there. OSINT usually means juggling 15 different tools across 5 terminals, each with its own output format, its own flags, its own way of doing things. Spyglass fixes that.

It wraps **holehe, user-scanner, sherlock, maigret, blackbird, PhoneInfoga, Ignorant, Shodan, nmap, dig, whois, curl, gobuster, httpx, exiftool, LeakCheck, Scylla, and ip-api.com** into a **single, unified CLI** — one interface, one output format, one place to run everything.

No more context switching. No more copy-pasting between tools. Just pick a target and go.

---

## 🔭 Quick start

```bash
git clone https://github.com/yourusername/spyglass.git
cd spyglass
pip install -r requirements.txt
python -m Spyglass-OSINT
```

That's it. Pick a module from the menu and go. If something's missing, the tool tells you what to install.

---

## 🔭 What it can do

| Module | What it checks | Engines |
|---|---|---|
| `email` | Where is this email registered? Any breaches? | holehe + user-scanner + blackbird + LeakCheck + Scylla |
| `username` | Which platforms have this profile? | user-scanner + sherlock + maigret + blackbird |
| `phone` | Who owns this number? Carrier? Region? Any footprints? | phonenumbers + PhoneInfoga + Ignorant |
| `website` | Full recon: DNS, ports, headers, WHOIS, subdomains, directories | dig + Shodan + nmap + curl + whois + gobuster + httpx + crt.sh |
| `ip` | Where is this IP? Reverse DNS? Open ports? | ip-api.com + dig + whois + Shodan + nmap |
| `metadata` | What's hidden in this file? GPS, camera, document author? | exiftool + Pillow + PyPDF2 + python-docx/openpyxl |
| `opsec` | Am I leaking my real IP? Is my proxy working? | dig + curl + ip-api.com + torsocks |
| `investigation` | Everything above, cross-correlated | Runs all modules, connects the dots |

### Why you'd use this

Spyglass isn't another OSINT tool — it's a **unified command center** for the ones that already exist.

- **One interface** — Every tool speaks the same language. Same flags (`--json`, `--csv`, `--proxy`), same output format, same menu.
- **Parallel execution** — Running holehe + user-scanner + blackbird + LeakCheck + Scylla for one email? That happens simultaneously, not sequentially.
- **Smart merging** — Results are deduplicated and ranked by cross-tool agreement. If all 4 username tools found the same profile, that goes to the top.
- **Cross-correlation** — In investigation mode, Spyglass connects email domains to WHOIS orgs, phone regions to countries, username platforms to email platforms. It finds links you'd miss manually.
- **Privacy-aware** — Built-in proxy/Tor support with OPSEC verification. Check if you're actually anonymous before you start.

---

## 🔭 Usage

### Interactive menu

```bash
python -m Spyglass-OSINT
```

```
  [1]  Identity              (email, username, phone)
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
```

Works with: `email`, `username`, `phone`, `website`, `ip`, `metadata`, `opsec`.

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

### Export

```bash
python -m Spyglass-OSINT email user@example.com --json
python -m Spyglass-OSINT ip 1.1.1.1 --csv
```

Saves a timestamped file in the current directory.

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
├── website.py           Website recon
├── ip.py                IP recon
├── metadata.py          Metadata extraction
├── breach.py            Breach checking — LeakCheck + Scylla
├── opsec.py             OPSEC health check
├── investigation.py     Full investigation orchestration + correlation
├── export.py            JSON / CSV export
├── requirements.txt     Python dependencies
├── README.md            This file
├── LICENSE              MIT license
└── .gitignore           Git ignore rules
```

---

## 🔭 Requirements

Python 3.9+ and `pip install -r requirements.txt`. External tools are auto-detected — install whatever modules you need. The tool tells you what's missing.

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
