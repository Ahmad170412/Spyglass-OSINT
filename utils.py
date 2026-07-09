#!/usr/bin/env python3
import os
import sys
import subprocess
import re
import json
import concurrent.futures
from urllib.parse import urlparse, quote
import shutil

# ─── tool paths (None if not found) ────────────────────────

_HOLEHE  = shutil.which("holehe")
_US      = shutil.which("user-scanner")
_SH      = shutil.which("sherlock")
_MG      = shutil.which("maigret")
_BB      = shutil.which("blackbird")
_BB_DIR  = os.path.dirname(_BB) if _BB else None
_PHONEINFOGA = shutil.which("phoneinfoga")
_IGNORANT = shutil.which("ignorant")

if not _BB:
    for _p in [
        "/opt/blackbird/blackbird.py",
        os.path.expanduser("~/.local/bin/blackbird/blackbird.py"),
    ]:
        if os.path.isfile(_p):
            _BB = _p
            _BB_DIR = os.path.dirname(_p)
            break

_DIG = shutil.which("dig")
_NMAP = shutil.which("nmap")
_GOBUSTER = shutil.which("gobuster")
_HTPPX = shutil.which("httpx")
_WHOIS = shutil.which("whois")
_CURL = shutil.which("curl")
_SHODAN = shutil.which("shodan")


def _check_tool(name, path):
    if not path:
        print(f"  [!] {name} not found. Install it and ensure it's in your PATH.")
        return False
    return True


# ─── helpers ──────────────────────────────────────────────

def _domain(url):
    p = urlparse(url)
    d = (p.netloc or p.path).lower()
    return d[4:] if d.startswith("www.") else d


def _verify(urls, max_workers=30, timeout=10, silent=False):
    if not urls:
        return set()
    if not silent:
        print(f"  [*] Verifying {len(urls)} URLs with curl...", end=" ", flush=True)

    def _check(u):
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", u],
                capture_output=True, text=True, timeout=timeout,
            )
            return r.stdout.strip() == "200"
        except Exception:
            return False

    valid = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        fm = {pool.submit(_check, u): u for u in urls}
        for f in concurrent.futures.as_completed(fm):
            if f.result():
                valid.add(fm[f])

    if not silent:
        print(f"({len(valid)} alive)")
    return valid


def _pick(*dicts):
    """Return first matching URL for a domain across multiple dicts."""
    def _fn(d):
        for dd in dicts:
            if d in dd:
                return dd[d]
        return d
    return _fn


def _run(cmd, timeout=15, stdin=""):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
        return r.stdout.strip() or r.stderr.strip()
    except Exception as e:
        return str(e)


def _extract_ips(text):
    return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))


def _extract_emails(text):
    return sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))


def _extract_phones(text):
    pats = re.findall(r"\+?\d[\d\s().-]{7,20}", text)
    out = set()
    for p in pats:
        s = p.strip()
        if len(s) < 7:
            continue
        if re.search(r"\d{4}[-/]\d{2}[-/]\d{2}", s):
            continue
        if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", s):
            continue
        digits = re.sub(r"\D", "", s)
        has_plus = s.startswith("+")
        has_sep = bool(re.search(r"[-()]", s))
        if not has_plus and not has_sep and len(digits) < 10:
            continue
        if len(digits) > 15:
            continue
        out.add(s)
    return sorted(out)


def _extract_whois_fields(text):
    keys = ["Name", "Organization", "Address", "City", "State", "PostalCode",
            "Country", "Phone", "Fax", "Email", "Tech Email", "Admin Email",
            "Registrant Name", "Registrant Organization", "Registrant Email",
            "Admin Name", "Admin Organization", "Admin Email",
            "Tech Name", "Tech Organization", "Tech Email"]
    out = {}
    for line in text.split("\n"):
        for k in keys:
            m = re.match(rf"^\s*{re.escape(k)}\s*:\s*(.+)", line, re.IGNORECASE)
            if m:
                out[k] = m.group(1).strip()
    return out


# ─── breach check ─────────────────────────────────────────

def _breach_check(query, qtype="email"):
    if not _CURL:
        return {"found": 0, "sources": [], "fields": []}
    try:
        import json
        from urllib.parse import quote
        url = f"https://leakcheck.io/api/public?check={quote(query)}"
        r = subprocess.run(
            [_CURL, "-s", url],
            capture_output=True, text=True, timeout=15,
        )
        data = json.loads(r.stdout.strip())
        if data.get("success"):
            return {
                "found": data.get("found", 0),
                "sources": data.get("sources", []),
                "fields": data.get("fields", []),
            }
        return {"found": 0, "sources": [], "fields": []}
    except Exception:
        return {"found": 0, "sources": [], "fields": []}


def show_breach(br):
    if br.get("found"):
        top = [f"{s['name']} ({s['date']})" for s in br["sources"][:5]]
        print(f"\n  Breach data: {br['found']} databases ({', '.join(top)})")
        if br.get("fields"):
            print(f"  Exposed fields: {', '.join(br['fields'][:8])}")
