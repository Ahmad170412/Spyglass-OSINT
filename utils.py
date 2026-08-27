#!/usr/bin/env python3
import os
import re
import json
import subprocess
import concurrent.futures
from urllib.parse import urlparse
import shutil


# ─── proxy ─────────────────────────────────────────────────

_PROXY = None


def set_proxy(url):
    global _PROXY
    _PROXY = url


def _proxy_env():
    if not _PROXY:
        return None
    env = os.environ.copy()
    env["ALL_PROXY"] = _PROXY
    env["HTTP_PROXY"] = _PROXY
    env["HTTPS_PROXY"] = _PROXY
    return env


def _proxy_args():
    return ["--proxy", _PROXY] if _PROXY else []


def _proxy_prefix(cmd):
    if not _PROXY or not cmd:
        return cmd
    base = os.path.basename(cmd[0])
    if base in {"dig", "nmap", "whois"} and _TORSOCKS:
        return [_TORSOCKS] + cmd
    return cmd


# ─── tool paths ───────────────────────────────────────────

_TORSOCKS = shutil.which("torsocks")
_HOLEHE  = shutil.which("holehe")
_US      = shutil.which("user-scanner")
_SH      = shutil.which("sherlock")
_MG      = shutil.which("maigret")
_BB      = shutil.which("blackbird") or shutil.which("blackbird.py")
_BB_DIR  = os.path.dirname(_BB) if _BB else None
_PHONEINFOGA = shutil.which("phoneinfoga")
_IGNORANT = shutil.which("ignorant")

if not _BB:
    for _p in [
        "/opt/blackbird/blackbird.py",                        # Linux (git clone)
        os.path.expanduser("~/.local/bin/blackbird/blackbird.py"),  # Linux (pipx-style)
        "/opt/homebrew/bin/blackbird.py",                     # macOS (Apple Silicon)
        "/usr/local/bin/blackbird.py",                        # macOS (Intel)
        os.path.expanduser("~/blackbird/blackbird.py"),       # macOS/Linux (git clone)
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
_EXIFTOOL = shutil.which("exiftool")


# ─── network helpers ──────────────────────────────────────

def _curl_json(url, timeout=15):
    if not _CURL:
        return None
    cmd = [_CURL, "-s", url]
    if _PROXY:
        cmd = cmd[:1] + _proxy_args() + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout.strip())
    except Exception:
        pass
    return None


def _check_tool(name, path):
    if not path:
        from . import display as _ui
        _ui.err(f"{name} not found. Install it and ensure it's in your PATH.")
        return False
    return True


# ─── text / URL helpers ───────────────────────────────────

def safe_name(value) -> str:
    """Make an arbitrary target string safe for use in a filename."""
    s = re.sub(r"[^A-Za-z0-9._+-]+", "_", str(value)).strip("_.")
    return s or "target"


def _domain(url):
    p = urlparse(url)
    d = (p.netloc or p.path).lower()
    if ":" in d:
        d = d.split(":")[0]  # strip the port, keep the hostname
    return d[4:] if d.startswith("www.") else d


def _pick(*dicts):
    def _fn(d):
        for dd in dicts:
            if d in dd:
                return dd[d]
        return d
    return _fn


def _run(cmd, timeout=15, stdin="", proxy=True):
    kwargs = dict(capture_output=True, text=True, timeout=timeout, input=stdin)
    cmd = list(cmd)
    if proxy and _PROXY:
        base = os.path.basename(cmd[0]) if cmd else ""
        if base == "curl":
            cmd = cmd[:1] + _proxy_args() + cmd[1:]
        else:
            cmd = _proxy_prefix(cmd)
            kwargs["env"] = _proxy_env()
    try:
        r = subprocess.run(cmd, **kwargs)
        return r.stdout.strip() or r.stderr.strip()
    except Exception as e:
        return str(e)


def _verify(urls, max_workers=30, timeout=10, silent=False):
    if not urls:
        return set()
    if not silent:
        print(f"  [*] Verifying {len(urls)} URLs with curl...", end=" ", flush=True)

    def _check(u):
        try:
            cmd = ["curl", "-s", "-o", os.devnull, "-w", "%{http_code}", u]
            if _PROXY:
                cmd = cmd[:1] + _proxy_args() + cmd[1:]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            code = r.stdout.strip()
            return code.isdigit() and 200 <= int(code) < 400
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


# ─── extraction helpers ───────────────────────────────────

def _extract_ips(text):
    return sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))


def _extract_emails(text):
    return sorted(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))


def _extract_phones(text):
    # The lookahead rejects digit runs glued to letters/underscores — e.g. a
    # registry domain ID like "1264983250_DOMAIN_COM-VRSN" is not a phone.
    pats = re.findall(r"\+?\d[\d\s().-]{7,20}(?![\w])", text)
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
    """Extract fields from registry (ARIN/RIPE) and domain (IANA/VeriSign) whois.

    Domain registries spell keys differently (``Domain Name``, ``Registrar``,
    ``Creation Date``, ``Name Server``, ``created``, ``organisation``, ...) than
    ARIN/RIPE do. Everything is matched case-insensitively and normalized to a
    canonical display name; repeatable keys (Name Server, Domain Status) are
    joined with commas.
    """
    keys = [
        # registry / IP-whois (ARIN/RIPE)
        "Name", "Organization", "Organisation", "Address", "City", "State",
        "PostalCode", "Country", "Phone", "Fax", "Email", "E-Mail", "Fax No",
        "Tech Email", "Admin Email",
        "Registrant Name", "Registrant Organization", "Registrant Email",
        "Admin Name", "Admin Organization", "Admin Email",
        "Tech Name", "Tech Organization", "Tech Email",
        # domain-whois (IANA thin + VeriSign/PIR full)
        "Domain", "Domain Name", "Registry Domain ID", "Registrar",
        "Registrar IANA ID", "Registrar URL", "Registrar WHOIS Server",
        "Sponsoring Registrar", "Whois Server", "Creation Date", "Updated Date",
        "Registry Expiry Date", "Expiry Date", "Domain Status", "Status",
        "Name Server", "DNSSEC", "Created", "Updated", "Source", "Refer",
    ]
    canon = {
        "Domain Name": "Domain",
        "Organisation": "Organization",
        "E-Mail": "Email",
        "Fax No": "Fax",
        "Created": "Creation Date",
        "Updated": "Updated Date",
        "Expiry Date": "Registry Expiry Date",
    }
    repeat = {"Name Server", "Domain Status"}
    out = {}
    for line in text.split("\n"):
        for k in keys:
            m = re.match(rf"^\s*{re.escape(k)}\s*:\s*(.+)", line, re.IGNORECASE)
            if not m:
                continue
            val = m.group(1).strip()
            key = canon.get(k, k)
            if key in repeat and key in out:
                out[key] = f"{out[key]}, {val}"
            else:
                out[key] = val
            break
    return out
