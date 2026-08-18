"""Dark web reconnaissance for Spyglass.

Searches the *index* of the dark web without ever connecting to an .onion
service. Three distinct, honest capabilities:

1. **Ahmia.fi** — search the Tor hidden-service index (clearnet, keyless).
   Returns .onion URLs plus title/description/last-seen metadata only.
2. **Pwned Passwords** — k-anonymity breach check for a password. Only the
   first 5 hex chars of the SHA-1 hash leave the machine; the password and
   full hash are never logged, returned, or written to disk.
3. **Breach attribution** — reuses ``breach.check`` (LeakCheck + Scylla) for
   email / username / phone.

Two opt-in, keyed layers (never hardcoded, skipped cleanly when the env var
is unset):
4. **IntelX** (``INTELX_API_KEY``, free tier) — breach + paste archive search.
5. **HaveIBeenPwned** (``HIBP_API_KEY``) — authoritative per-account breach list.

Design principles
-----------------
* Default (keyless) path works out of the box; keyed sources are opt-in.
* The module searches and reports metadata only — it never fetches or visits
  an .onion URL, which would require Tor and cross a legal line.
* OPSEC-aware: all HTTP goes through curl, which honors the configured proxy.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import html as _html
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from urllib.parse import quote, unquote, urlencode

from . import utils
from . import breach

# Generic browser UA so probe traffic blends in with normal clients.
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_AHMIA_SEARCH = "https://ahmia.fi/search/"
_PWNED_RANGE = "https://api.pwnedpasswords.com/range/"
_INTELX_PHONEBOOK = "https://2.intelx.io/phonebook/search"
_HIBP_BREACHED = "https://haveibeenpwned.com/api/v3/breachedaccount/"

# Cap the .onion results kept per query so a common token ("user", "example")
# can't flood the display/report with thousands of near-duplicate entries.
_AHMIA_LIMIT = 100

# Query types that each capability understands.
_BREACH_TYPES = {"email", "username", "phone"}
_INTELX_TYPES = {"email", "domain", "ip"}
_HIBP_TYPES = {"email"}


def darkweb(query, qtype=None):
    """Run dark-web recon for a target. ``qtype`` auto-detects when omitted.

    Returns a dict of the form::

        {
          "query": <target>,
          "type":  <email|username|phone|domain|ip>,
          "ahmia": [ {title,url,description,domain,last_seen}, ... ],
          "breach": {...} | None,     # email/username/phone only
          "intelx": {...} | None,     # email/domain/ip, keyed
          "hibp":   {...} | None,     # email, keyed
        }

    Every sub-probe is independent and best-effort; an offline API or a
    missing key yields ``None`` / ``[]`` instead of failing the whole run.
    """
    query = (query or "").strip()
    if not query:
        return {"query": "", "type": qtype or "", "error": "no target given"}
    qtype = (qtype or _detect_type(query)).lower()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        ahmia_f = pool.submit(_ahmia, query)
        breach_f = pool.submit(breach.check, query, qtype) if qtype in _BREACH_TYPES else None
        intelx_f = pool.submit(_intelx, query, qtype) if qtype in _INTELX_TYPES else None
        hibp_f = pool.submit(_hibp_account, query) if qtype in _HIBP_TYPES else None

    result = {
        "query": query,
        "type": qtype,
        "ahmia": ahmia_f.result() or [],
    }
    if breach_f:
        result["breach"] = breach_f.result()
    if intelx_f:
        result["intelx"] = intelx_f.result()
    if hibp_f:
        result["hibp"] = hibp_f.result()
    return result


def _detect_type(query):
    """Best-effort classification of a target string."""
    if "@" in query and "." in query.split("@")[-1]:
        return "email"
    if _looks_like_ip(query):
        return "ip"
    digits = re.sub(r"[^\d]", "", query)
    if digits and len(digits) >= 7 and len(digits) <= 15:
        return "phone"
    if "." in query:
        return "domain"
    return "username"


def _looks_like_ip(s):
    import socket
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, s)
            return True
        except (OSError, ValueError):
            continue
    return False


# ─── Ahmia (.onion index) ────────────────────────────────

def _ahmia(query, timeout=25):
    """Search Ahmia and parse .onion results. Returns a list of dicts.

    Ahmia's search form carries an anti-bot hidden field, so we fetch the form
    first (with a cookie jar), forward its hidden inputs alongside ``q``, and
    then parse the result list. On any failure — Ahmia 502/504s under load —
    this degrades to ``[]`` rather than raising.
    """
    if not utils._CURL:
        return []
    jar = None
    try:
        fd, jar_path = tempfile.mkstemp(prefix="spyglass_ahmia_", suffix=".cookies")
        os.close(fd)
        jar = jar_path

        form = _curl_text(f"{_AHMIA_SEARCH}", jar, timeout=timeout)
        hidden = _parse_hidden_inputs(form or "")

        params = {"q": query}
        params.update(hidden)
        results_html = _curl_text(f"{_AHMIA_SEARCH}?{urlencode(params)}", jar, timeout=timeout)
        return _parse_ahmia_html(results_html or "")
    except Exception:
        return []
    finally:
        if jar:
            try:
                os.unlink(jar)
            except OSError:
                pass


def _curl_text(url, jar, timeout=20):
    """GET ``url`` via curl (proxy-aware), returning stdout text or None."""
    cmd = [utils._CURL, "-sL", "-A", UA, "-b", jar, "-c", jar, url]
    if utils._PROXY:
        cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0:
            return r.stdout
    except Exception:
        pass
    return None


def _parse_hidden_inputs(html_text):
    """Extract ``name=value`` pairs from <input type="hidden"> tags."""
    params = {}
    for tag in re.findall(r"<input\b[^>]*>", html_text, re.I):
        if not re.search(r"type\s*=\s*['\"]?hidden['\"]?", tag, re.I):
            continue
        name = re.search(r"name\s*=\s*['\"]([^'\"]+)['\"]", tag, re.I)
        if not name:
            continue
        value = re.search(r"value\s*=\s*['\"]([^'\"]*)['\"]", tag, re.I)
        params[name.group(1)] = _html.unescape(value.group(1)) if value else ""
    return params


def _parse_ahmia_html(html_text):
    """Parse Ahmia's result list into [{title,url,description,domain,last_seen}].

    Ahmia full-text-searches and tokenizes the query, so common terms can
    return thousands of matches with the same URL repeated. Results are
    deduplicated by URL and capped at ``_AHMIA_LIMIT``.
    """
    results = []
    seen = set()
    ol = re.search(
        r'<ol[^>]*class=["\']searchResults["\'][^>]*>(.*?)</ol>',
        html_text, re.S | re.I,
    )
    if not ol:
        return results
    for block in re.findall(r'<li[^>]*class=["\']result["\'][^>]*>(.*?)</li>', ol.group(1), re.S | re.I):
        if len(results) >= _AHMIA_LIMIT:
            break
        url = None
        m = re.search(r"redirect_url=([^\"]+)", block, re.I)
        if m:
            url = unquote(_html.unescape(m.group(1))).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        if url in seen:
            continue
        seen.add(url)

        title = desc = domain = ""
        t = re.search(r"<h4>\s*<a[^>]*>(.*?)</a>", block, re.S | re.I)
        if t:
            title = _strip_tags(t.group(1))
        d = re.search(r"<p>(.*?)</p>", block, re.S | re.I)
        if d:
            desc = _strip_tags(d.group(1))
        c = re.search(r"<cite>(.*?)</cite>", block, re.S | re.I)
        if c:
            domain = _strip_tags(c.group(1))

        last_seen = ""
        ts = re.search(r"data-timestamp=[\"']([^\"']+)[\"']", block, re.I)
        if ts:
            try:
                last_seen = datetime.fromtimestamp(int(ts.group(1))).strftime("%Y-%m-%d")
            except (ValueError, OSError, OverflowError):
                last_seen = ""

        results.append({
            "title": title,
            "url": url,
            "description": desc,
            "domain": domain,
            "last_seen": last_seen,
        })
    return results


def _strip_tags(s):
    return _html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


# ─── Pwned Passwords (k-anonymity) ───────────────────────

def pwned_password(password):
    """Check a password against HIBP Pwned Passwords via k-anonymity.

    Only the first 5 hex chars of the SHA-1 hash leave the machine; the full
    hash is matched against the response locally. The password and hash are
    never logged, returned, or written anywhere. Returns::

        {"pwned": bool, "count": int}   # plus "error" only on transport failure
    """
    if not password:
        return {"pwned": False, "count": 0, "error": "no password given"}
    if not utils._CURL:
        return {"pwned": False, "count": 0, "error": "curl not found"}
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    cmd = [utils._CURL, "-s", "-A", UA, f"{_PWNED_RANGE}{prefix}"]
    if utils._PROXY:
        cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        for line in (r.stdout or "").splitlines():
            if ":" not in line:
                continue
            body, count = line.split(":", 1)
            if body.strip() == suffix:
                return {"pwned": True, "count": int(count.strip())}
        return {"pwned": False, "count": 0}
    except Exception as e:
        return {"pwned": False, "count": 0, "error": str(e)}


# ─── IntelX (opt-in, free-tier key) ──────────────────────

def _intelx(query, qtype, timeout=20):
    key = os.environ.get("INTELX_API_KEY")
    if not key or not utils._CURL:
        return None
    # IntelX phonebook supports email/domain/ip/url/name/cidr/bitcoin.
    payload = {"term": query, "maxresults": 10, "media": 0, "target": 0}
    cmd = [
        utils._CURL, "-s", "-X", "POST",
        "-A", UA,
        "-H", f"x-key: {key}",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload),
        _INTELX_PHONEBOOK,
    ]
    if utils._PROXY:
        cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        data = _loads(r.stdout)
        if not isinstance(data, dict):
            return None
        selectors = data.get("selectors") or []
        values = []
        for sel in selectors:
            if isinstance(sel, dict) and sel.get("value"):
                values.append(str(sel["value"]))
        return {
            "total": data.get("total", len(values)),
            "results": values[:20],
        }
    except Exception:
        return None


def _loads(text):
    """Parse JSON, returning None on malformed/empty input."""
    try:
        return json.loads(text or "")
    except (ValueError, TypeError):
        return None


# ─── HaveIBeenPwned (opt-in, keyed) ──────────────────────

def _hibp_account(email, timeout=20):
    key = os.environ.get("HIBP_API_KEY")
    if not key or not utils._CURL:
        return None
    cmd = [
        utils._CURL, "-s",
        "-A", UA,
        "-H", f"hibp-api-key: {key}",
        f"{_HIBP_BREACHED}{quote(email)}",
    ]
    if utils._PROXY:
        cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 404:
            return {"breaches": []}
        data = _loads(r.stdout)
        if not isinstance(data, list):
            return None
        breaches = []
        for b in data:
            if isinstance(b, dict):
                breaches.append({
                    "name": b.get("Name", ""),
                    "date": b.get("BreachDate", ""),
                    "domain": b.get("Domain", ""),
                    "data_classes": b.get("DataClasses", []),
                })
        return {"breaches": breaches[:20]}
    except Exception:
        return None
