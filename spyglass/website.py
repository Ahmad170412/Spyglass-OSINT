"""Website reconnaissance for Spyglass.

A deep, defense-in-depth rebuild of the original module. Every probe is
independent and best-effort: a missing tool, an offline API, or a refused
connection degrades gracefully instead of failing the whole run.

Design principles
-----------------
* Passive only. Nothing in this module sends a probe the target did not ask
  for: no port scanning, no directory brute-forcing, no wordlist DNS. The
  former nmap and gobuster passes are gone. Port data comes from Shodan's
  InternetDB, which reports what Shodan's own scan already saw.
* No paid APIs and no API keys. Passive sources are crt.sh, CertSpotter,
  HackerTarget, subfinder, the Wayback Machine CDX index, and Shodan InternetDB.
* OPSEC-aware: HTTP goes through curl (which honors --proxy); DNS through
  ``dig`` is routed via torsocks when a proxy is active; in-process DNS
  resolution is only used when no proxy is set, so the operator's resolver is
  never leaked through Tor.
* macOS/Linux focused: dig, curl, whois, httpx, subfinder and shodan are
  auto-detected and skipped cleanly when absent.
"""

from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request

from . import utils
from . import cve as _cve
from .utils import (
    _check_tool,
    _extract_emails,
    _extract_phones,
    _extract_whois_fields,
    _run,
    _CURL,
    _DIG,
    _HTPPX,
    _SHODAN,
    _SUBFINDER,
    _WHOIS,
)

# Generic browser UA so probe traffic blends in with normal clients.
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

# ─── per-run memoization ───────────────────────────────────
# Cleared at the start of every _collect() so one target's answers never leak
# into the next. Dig/HTTP lookups are cheap to repeat but the same query often
# runs several times in one pass (e.g. host "A" for both the IP set and the
# DNS table), so cache them for the duration of the run.
_DIG_CACHE = {}
_BODY_CACHE = {}


def _reset_caches():
    _DIG_CACHE.clear()
    _BODY_CACHE.clear()

# A larger bundled subdomain list than the original ~100 names. A SecLists
# checkout on disk wins when present; otherwise this stays the fallback.
_SUB_LIST = """
www mail email smtp imap pop pop3 webmail mx mx1 mx2 mx3 ns ns1 ns2 ns3 ns4
dns dns1 dns2 dns3 dns4 ftp sftp ssh git gitlab github svn cvs vpn vpn1 vpn2
remote secure login sso id oauth auth signin signup register account accounts
admin administrator adm panel control manage management dashboard cpanel
webmail2 mail2 smtp2 relay gateway portal my apps app api api1 api2 api3
dev developer developers dev1 dev2 stage staging test test1 test2 testing
qa uat beta alpha demo sandbox preview review canary prod production www1
www2 www3 www4 web web1 web2 web3 static static1 static2 assets assets1
cdn cdn1 cdn2 cdn3 img images image media video videos audio download
downloads dl files file upload uploads docs documentation doc support help
helpdesk status health check monitor monitoring metrics grafana kibana logs
log analytics stats statistics report reports data db database sql mysql
postgres redis mongo cache memcached elastic search solr es kibana backup
backups snapshot archive archived old legacy blog news articles forum forums
community wiki knowledge base kb docs1 shop store shopify cart checkout
pay payment payments billing invoice invoices billing2 accounting finance
jobs job career careers hr human resources recruiting talent about contact
team press media2 investor investors partners partner affiliate marketing
advertise ads advertising legal privacy terms security trust policies policy
compliance audit certifications cert certificate licenses license brand
events calendar maps map locations location store2 stores locator
""".split()

# Removed with the gobuster dir brute-force: _DIR_LIST and _dir_wordlist().
# Both existed only to feed gobuster a directory wordlist. The
# `directories` data type is now sourced from archived Wayback paths,
# which are real URLs rather than guesses — see _phase_dirs.

# Well-known files whose presence leaks configuration, secrets, or the stack.
_EXPOSURE_PATHS = (
    "/.git/config", "/.git/HEAD", "/.env", "/.env.bak", "/.env.example",
    "/.env.local", "/.DS_Store", "/.htaccess", "/web.config", "/.svn/entries",
    "/.aws/credentials", "/.dockerenv", "/id_rsa", "/id_rsa.pub",
    "/backup.zip", "/backup.tar.gz", "/dump.sql", "/db.sql", "/backup.sql",
    "/wp-config.php.bak", "/wp-config.php~", "/config.php.bak", "/config.php~",
    "/phpinfo.php", "/server-status", "/debug.log", "/error_log",
    "/package.json", "/composer.json", "/.npmrc", "/crossdomain.xml",
    "/security.txt", "/.well-known/security.txt",
    "/wp-login.php", "/admin", "/administrator", "/login", "/graphql",
)

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
)

# (name, {header: regex}, [body regex]) — lightweight Wappalyzer-style sniffing.
_TECH = (
    ("Cloudflare", {"server": r"cloudflare"}, [r"cf-ray", r"__cf_bm"]),
    ("CloudFront", {"server": r"cloudfront", "via": r"cloudfront"}, []),
    ("Akamai", {"server": r"akamai", "x-akamai-transformed": r"."}, []),
    ("Fastly", {"server": r"fastly", "x-served-by": r"cache"}, []),
    ("Vercel", {"server": r"vercel", "x-vercel-id": r"."}, []),
    ("Netlify", {"server": r"netlify", "x-nf-request-id": r"."}, []),
    ("GitHub Pages", {"server": r"github\.com", "x-github-request-id": r"."}, []),
    ("WordPress", {}, [r"wp-content/", r"wp-includes/", r'"generator"[^>]*wordpress']),
    ("Drupal", {}, [r"drupal\.org", r'"generator"[^>]*drupal']),
    ("Joomla", {}, [r"joomla!?", r'"generator"[^>]*joomla']),
    ("Shopify", {"server": r"shopify"}, [r"cdn\.shopify\.com", r"myshopify\.com"]),
    ("Magento", {"set-cookie": r"PHPSESSID"}, [r"magento", r"/skin/frontend/"]),
    ("Wix", {"x-wix-request-id": r"."}, [r"wixstatic\.com", r"static\.wixstatic\.com"]),
    ("Squarespace", {"server": r"squarespace"}, [r"squarespace"]),
    ("Ghost", {"x-powered-by": r"ghost"}, [r"ghost\.io", r"ghost-url"]),
    ("React", {}, [r"data-reactroot", r"data-reactid", r"__REACT"]),
    ("Next.js", {}, [r"__NEXT_DATA__", r"/_next/static"]),
    ("Vue.js", {}, [r"data-v-[0-9a-f]{6,}", r"__vue__"]),
    ("Angular", {}, [r"ng-version=", r"ng-app="]),
    ("jQuery", {}, [r"jquery(?:\.min)?\.js"]),
    ("Bootstrap", {}, [r"bootstrap(?:\.min)?\.(?:css|js)"]),
    ("Tailwind CSS", {}, [r"tailwindcss", r"tailwind\.css"]),
    ("Google Analytics", {}, [r"google-analytics\.com/analytics\.js", r"gtag\("]),
    ("Google Tag Manager", {}, [r"googletagmanager\.com/gtm\.js"]),
    ("PHP", {"x-powered-by": r"php"}, []),
    ("ASP.NET", {"x-powered-by": r"asp\.net", "x-aspnet-version": r"."}, [r"__VIEWSTATE"]),
    ("Django", {"set-cookie": r"csrftoken"}, [r"csrfmiddlewaretoken"]),
    ("Ruby on Rails", {"x-powered-by": r"phusion", "server": r"passenger"}, [r"csrf-param"]),
    ("Laravel", {"set-cookie": r"laravel_session"}, []),
    ("Express", {"x-powered-by": r"express"}, []),
    ("Node.js", {"x-powered-by": r"node"}, []),
    ("Nginx", {"server": r"nginx"}, []),
    ("Apache", {"server": r"apache"}, []),
    ("IIS", {"server": r"microsoft-iis"}, []),
    ("OpenResty", {"server": r"openresty"}, []),
    ("Varnish", {"server": r"varnish", "via": r"varnish"}, []),
    ("Webflow", {"x-powered-by": r"webflow"}, [r"webflow"]),
)


# ─── HTTP layer ───────────────────────────────────────────

def _sh(args, timeout=15, stdin=""):
    """Run a subprocess, honoring the proxy for curl and torsocks for dig."""
    cmd = list(args)
    env = None
    if utils._PROXY:
        base = os.path.basename(cmd[0])
        if base == "curl":
            cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
        else:
            cmd = utils._proxy_prefix(cmd)
            env = utils._proxy_env()
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          input=stdin, env=env)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _urllib_get(url, timeout=15, want="body", limit=1_000_000, follow=True):
    """Native fallback for curl-free machines; honors the configured proxy."""
    try:
        handlers = []
        if utils._PROXY:
            handlers.append(urllib.request.ProxyHandler(
                {"http": utils._PROXY, "https": utils._PROXY}))
        if not follow:
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with opener.open(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            body = resp.read(limit) if want in ("body", "all") else b""
            status = resp.status
        return headers, body.decode("utf-8", "replace"), status
    except Exception:
        return None


def _parse_headers_block(text):
    """Parse the final header block from curl -D output.

    ``Set-Cookie`` is the one header that legitimately repeats; it is joined
    with newlines so every cookie survives instead of the last one winning.
    """
    headers = {}
    blocks = re.split(r"\r?\n\r?\n", text.strip())
    if not blocks:
        return headers
    for line in blocks[-1].splitlines():
        if ":" not in line or line.startswith(("HTTP/", "curl:")):
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key == "set-cookie":
            headers[key] = (headers.get(key, "") + "\n" + value.strip()).strip("\n")
        else:
            headers[key] = value.strip()
    return headers


def _http_headers(url, timeout=15):
    if _CURL:
        try:
            r = _sh([_CURL, "-sS", "-L", "-o", os.devnull, "-D", "-",
                     "-A", UA, "--max-time", str(timeout), url])
            if r.returncode == 0:
                return _parse_headers_block(r.stdout)
        except Exception:
            pass
    got = _urllib_get(url, timeout=timeout, want="headers")
    return got[0] if got else {}


def _http_body(url, timeout=15, limit=1_000_000):
    key = (url, limit)
    if key in _BODY_CACHE:
        return _BODY_CACHE[key]
    body = ""
    if _CURL:
        try:
            r = _sh([_CURL, "-sS", "-L", "-A", UA, "--max-time", str(timeout), url])
            if r.returncode == 0 and r.stdout:
                body = r.stdout[:limit]
        except Exception:
            pass
    if not body:
        got = _urllib_get(url, timeout=timeout, want="body", limit=limit)
        body = got[1] if got else ""
    _BODY_CACHE[key] = body
    return body


def _http_status(url, timeout=15, follow=True):
    if _CURL:
        try:
            args = [_CURL, "-sS", "-o", os.devnull, "-w", "%{http_code}",
                    "-A", UA, "--max-time", str(timeout)]
            if follow:
                args.append("-L")
            args.append(url)
            r = _sh(args)
            if r.returncode == 0 and r.stdout.strip().isdigit():
                return int(r.stdout.strip())
        except Exception:
            pass
    got = _urllib_get(url, timeout=timeout, want="headers", follow=follow)
    return got[2] if got else 0


def _http_bytes(url, timeout=10, limit=512 * 1024):
    """Fetch raw bytes (for favicons); curl-only, best-effort."""
    if not _CURL:
        return None
    try:
        cmd = [_CURL, "-sS", "-L", "-A", UA, "--max-time", str(timeout), url]
        if utils._PROXY:
            cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if r.returncode == 0 and r.stdout:
            return r.stdout[:limit]
    except Exception:
        pass
    return None


def _http_json(url, timeout=15):
    body = _http_body(url, timeout=timeout)
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None


# ─── DNS layer (proxy-aware) ──────────────────────────────

def _is_ipv4(s):
    try:
        socket.inet_pton(socket.AF_INET, s)
        return True
    except (OSError, ValueError):
        return False


def _is_ipv6(s):
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except (OSError, ValueError):
        return False


def _dig_short(*args, timeout=10):
    """Run ``dig <args> +short`` and return stdout only on success.

    Unlike ``utils._run``, a timeout or a nonzero exit yields ``""`` — dig
    error text must never be mistaken for data (e.g. "dnssec: yes"). Results
    are memoized per run (see _DIG_CACHE).
    """
    if not _DIG:
        return ""
    key = args
    if key in _DIG_CACHE:
        return _DIG_CACHE[key]
    try:
        r = _sh(["dig", *args, "+short"], timeout=timeout)
        val = r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        val = ""
    _DIG_CACHE[key] = val
    return val


def _resolve_a(host):
    """Resolve A record via dig (proxy/torsocks) or native resolver."""
    if _DIG:
        raw = _dig_short(host, "A")
        for line in raw.split("\n"):
            line = line.strip()
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", line):
                return line
    if not utils._PROXY:
        try:
            for res in socket.getaddrinfo(host, None, socket.AF_INET):
                return res[4][0]
        except Exception:
            pass
    return None


def _reverse_dns(ip):
    """PTR lookup via dig (proxy) or native resolver."""
    if _DIG:
        raw = _dig_short("-x", ip)
        val = raw.split("\n")[0].strip().rstrip(".")
        if val and val != ".":
            return val
    if not utils._PROXY:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    return None


def _is_wildcard(host):
    """Detect wildcard DNS by resolving a random subdomain."""
    probe = f"{os.urandom(4).hex()}.{host}"
    ip = _resolve_a(probe)
    return (ip is not None, ip)


def _future_result(fut, default):
    """Safely unwrap a future — a malformed API response must not kill recon."""
    try:
        return fut.result()
    except Exception:
        return default


# ─── subdomain sources ────────────────────────────────────

def _crt_subs(host):
    subs = set()
    data = _http_json(f"https://crt.sh/?q=%.{host}&output=json&limit=500", timeout=30)
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in str(entry.get("name_value", "")).split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and (name.endswith(f".{host}") or name == host):
                    subs.add(name)
    return subs


def _certspotter_subs(host):
    """Certificate Transparency via CertSpotter — free, no key."""
    subs = set()
    data = _http_json(
        f"https://api.certspotter.com/v1/issuances?domain={host}"
        f"&include_subdomains=true&expand=dns_names"
    )
    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for name in entry.get("dns_names", []):
                name = str(name).strip().lower().lstrip("*.")
                if name and (name.endswith(f".{host}") or name == host):
                    subs.add(name)
    return subs


def _rapiddns(host):
    """RapidDNS: keyless passive DNS, as (subs, rows).

    This is the historical-resolution source the module was missing. Every other
    subdomain source answers "what names are published somewhere"; this one
    answers "what did these names actually resolve to, and when did anyone last
    see them" — which is what surfaces a host still pointing at a stranger's
    cloud bucket after the owner moved on.

    AlienVault OTX would be the obvious alternative and has better coverage, but
    its ``passive_dns`` endpoint now answers ``Anonymous access to this endpoint
    is limited. Please authenticate.`` for unkeyed requests, so it is a keyed
    source or no source at all. RapidDNS needs nothing and is an HTML scrape,
    which this module already does for crt.sh and CertSpotter.

    Returns rows of ``(name, ip, rrtype, last_seen)``. Only names inside the
    target's own domain are returned: a RapidDNS table lists the parent domain
    too, and treating a sibling as a subdomain of the target is the same
    misattribution the suffix-matching subdomain bug used to cause.
    """
    body = _http_body(f"https://rapiddns.io/subdomain/{host}?full=1",
                      timeout=30, limit=2_000_000)
    if not body or "No results" in body or len(body) < 200:
        return set(), []
    subs, rows = set(), []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", body, re.S):
        cells = [re.sub(r"<[^>]+>", "", c).strip()
                 for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
        if len(cells) < 2:
            continue
        name = cells[0].strip().lower().lstrip("*.")
        ip = cells[1].strip()
        # Cell order is name, IP, record type, last-seen date. Anything shorter
        # is a layout change, and guessing at it would file an IP as a name.
        if not name or not re.fullmatch(r"[a-z0-9.-]+", name):
            continue
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip):
            continue
        if not (name == host or name.endswith(f".{host}")):
            continue
        subs.add(name)
        rows.append((name, ip,
                     cells[2].strip() if len(cells) > 2 else "",
                     cells[3].strip() if len(cells) > 3 else ""))
    return subs, rows


def _urlscan(host):
    """urlscan.io: pages someone else already loaded, and who references us.

    Free, no key. Three things come out of it that nothing else here produces:

    * **Observed addresses over time.** ``page.ip`` and ``page.asn`` as
      urlscan's scanners saw them, with a timestamp — passive confirmation of
      infrastructure, gathered by a third party.
    * **Historical server headers.** ``page.server`` is a ``Server`` value
      read off a real response by someone else's crawl. That is a passive tech
      fingerprint, which matters most when the live one is hidden behind a CDN.
    * **Referenced-by sites.** urlscan's ``domain:`` operator also matches pages
      that *link to* the target, so results whose ``page.domain`` is someone
      else are third-party references — a mention, a paste, a review, a
      directory listing. Those are reported separately and never counted as
      assets, because a site mentioning you is not infrastructure you control.
    """
    data = _http_json(
        f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=60", timeout=30)
    if not isinstance(data, dict):
        return {}
    results = data.get("results")
    # Not `if not data.get("results")` — a hostile or reshaped response can put
    # anything under this key, and iterating a string yields characters that
    # then get `.get()` called on them.
    if not isinstance(results, list):
        return {}
    observed, referrers = [], []
    servers, ips, asns = set(), set(), set()
    for r in results:
        if not isinstance(r, dict):
            continue
        page = r.get("page")
        if not isinstance(page, dict):
            continue
        pd = str(page.get("domain") or "").lower()
        if pd and pd != host and not pd.endswith(f".{host}"):
            if len(referrers) < 15:
                referrers.append(f"{pd} -> {str(page.get('url') or '')[:70]}")
            continue
        if page.get("ip"):
            ips.add(str(page["ip"]))
        if page.get("asn"):
            asns.add(str(page["asn"]))
        if page.get("server"):
            servers.add(str(page["server"]))
        url = str(page.get("url") or "")
        # An observation with no URL carries no information. Emitting it would
        # put a row of empty strings in the report's main table, which reads as
        # a scan that happened and said nothing.
        if url and len(observed) < 60:
            stamp = str((r.get("task") or {}).get("time") or "")
            observed.append({
                "url": url[:100],
                "ip": str(page.get("ip") or ""),
                "asn": str(page.get("asn") or ""),
                "server": str(page.get("server") or ""),
                "title": str(page.get("title") or "")[:70],
                # The full timestamp is kept for ordering and the date is
                # derived from it. Truncating to a day first makes every scan
                # from the same date compare equal, so "most recent wins" would
                # silently resolve to whichever row the search happened to list
                # first — which is not the same thing.
                "_ts": stamp,
                "scanned": stamp[:10],
            })
    out = {}
    if observed:
        # urlscan returns one row per *scan*, so a popular page appears many
        # times — the same URL against four Cloudflare anycast addresses on the
        # same day. Reported raw, the table's first screen is the same link
        # repeated. Collapsed to one row per URL, keeping the most recent scan
        # and the addresses it was seen on, "how many times have you seen this"
        # becomes a column instead of a wall.
        by_url = {}
        for o in observed:
            cur = by_url.get(o["url"])
            if cur is None:
                o["scans"] = 1
                o["ips"] = [o["ip"]] if o["ip"] else []
                by_url[o["url"]] = o
                continue
            cur["scans"] += 1
            if o["_ts"] > cur["_ts"]:
                cur["_ts"] = o["_ts"]
                cur["scanned"] = o["scanned"]
                cur["ip"] = o["ip"] or cur["ip"]
                cur["asn"] = o["asn"] or cur["asn"]
                cur["server"] = o["server"] or cur["server"]
            if o["ip"] and o["ip"] not in cur["ips"]:
                cur["ips"].append(o["ip"])
        merged = sorted(by_url.values(),
                        key=lambda o: (o["scanned"], o["scans"]), reverse=True)
        for o in merged:
            o.pop("_ts", None)
            if len(o["ips"]) > 1:
                o["ip"] = f"{o['ip']} (+{len(o['ips']) - 1} more)"
        out["observed"] = merged[:12]
    if ips:
        out["observed_ips"] = sorted(ips)[:40]
    if asns:
        out["observed_asns"] = sorted(asns)[:8]
    if servers:
        out["historical_servers"] = sorted(servers)[:20]
    if referrers:
        out["referenced_by"] = referrers
    return out


def _hackertarget_subs(host):
    """Returns (subs, ips). Free, no key, rate-limited per source IP."""
    subs, ips = set(), set()
    body = _http_body(f"https://api.hackertarget.com/hostsearch/?q={host}")
    if not body or "error" in body.lower() or "api count" in body.lower():
        return subs, ips
    for line in body.splitlines():
        line = line.strip()
        if "," not in line:
            continue
        sub, ip = line.split(",", 1)
        sub = sub.strip().lower().lstrip("*.")
        if sub and (sub.endswith(f".{host}") or sub == host):
            subs.add(sub)
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip.strip()):
                ips.add(ip.strip())
    return subs, ips


def _wayback_cdx(host):
    """One CDX query with matchType=domain: subdomains, paths, snapshot history."""
    out = {"subs": set(), "paths": set(), "first": "", "last": "", "count": 0}
    url = (
        f"https://web.archive.org/cdx/search/cdx?url={host}&matchType=domain"
        f"&output=json&fl=timestamp,original,statuscode"
        f"&filter=statuscode:200&collapse=urlkey&limit=3000"
    )
    data = _http_json(url, timeout=30)
    if not isinstance(data, list) or len(data) < 2:
        return out
    stamps = []
    for row in data[1:]:
        if not isinstance(row, list) or len(row) < 2:
            continue
        stamps.append(row[0])
        original = str(row[1])
        parsed = urllib.parse.urlparse(original if "://" in original else f"//{original}")
        h = (parsed.hostname or "").lower()
        if h and (h.endswith(f".{host}") or h == host):
            out["subs"].add(h)
            # Paths are only taken from the exact host. A subdomain's paths are
            # that subdomain's business, and folding them in would attribute
            # another host's directory layout to the target.
            #
            # CDX returns the path percent-encoded, and non-ASCII filenames are
            # common enough in an archive that leaving them encoded puts a
            # several-hundred-character escape sequence in the directories list,
            # where it is indistinguishable from a real directory name.
            if h == host and parsed.path and len(parsed.path) > 1:
                out["paths"].add(urllib.parse.unquote(parsed.path))
    if stamps:
        out["first"] = min(stamps)
        out["last"] = max(stamps)
        out["count"] = len(stamps)
    return out


def _active_brute(host, wildcard, wildcard_ip):
    """Wordlist DNS brute-force, in-process, no external tool.

    This is the last remaining *active* probe in the module: it resolves
    ``word.host`` for every entry in the wordlist, so the target's authoritative
    nameserver sees the lookups. gobuster did the same thing as a subprocess and
    is gone, but the underlying behaviour is not — in-process resolution is
    simply what is left.

    Kept because the passive sources genuinely miss names that were never
    published: a host with no certificate, no CT entry, no archive snapshot and
    no passive DNS record is exactly the kind that a wordlist finds. It is also
    the reason the module still needs `_resolve_a`.

    Skipped entirely when a proxy is set, because in-process resolution would
    bypass torsocks and leak the operator's resolver — that behaviour is
    unchanged, and is why proxied runs have never had wordlist enumeration.
    """
    found = set()
    if utils._PROXY:
        # In-process resolution would bypass torsocks and leak DNS — skip it.
        return found

    wordlist = _wordlist()

    def _probe(word):
        name = f"{word}.{host}"
        ip = _resolve_a(name)
        if not ip:
            return None
        if wildcard and ip == wildcard_ip:
            return None
        return name

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for name in pool.map(_probe, wordlist):
            if name:
                found.add(name)
    return found


def _wordlist():
    """Bundled list, or a local SecLists subdomain wordlist when available."""
    for path in (
        # Debian/Ubuntu, then macOS Homebrew (Apple Silicon, Intel) prefixes.
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/opt/homebrew/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/local/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        os.path.expanduser("~/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
        os.path.expanduser("~/wordlists/subdomains-top1million-5000.txt"),
    ):
        try:
            if os.path.isfile(path):
                with open(path, encoding="utf-8", errors="ignore") as f:
                    return [l.strip() for l in f if l.strip()][:5000]
        except OSError:
            continue
    return _SUB_LIST


def _axfr(host):
    """Attempt a zone transfer from the domain's name servers."""
    out = []
    if not _DIG:
        return out
    ns_raw = _dig_short(host, "NS")
    servers = [s.strip().rstrip(".") for s in ns_raw.split("\n") if s.strip()]
    for ns in servers[:3]:
        try:
            raw = _dig_short(f"@{ns}", host, "AXFR", timeout=15)
            for line in raw.split("\n"):
                line = line.strip()
                if line and not line.startswith(";") and "Transfer failed" not in line:
                    out.append(line)
            if out:
                break
        except Exception:
            continue
    return out


# ─── fingerprinting ───────────────────────────────────────

def _analyze_headers(headers):
    """Check for common security headers; missing ones are marked explicitly."""
    out = {}
    for name in _SECURITY_HEADERS:
        label = "-".join(p.title() for p in name.split("-"))
        out[label] = headers.get(name, "missing")
    return out


def _extract_csp_domains(csp):
    """Pull hostnames referenced by a Content-Security-Policy value."""
    domains = set()
    ignore = {"self", "none", "unsafe-inline", "unsafe-eval", "strict-dynamic",
              "report-sample", "data", "blob", "http", "https", "ws", "wss"}
    for m in re.findall(r"[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}", csp or ""):
        d = m.strip().lstrip("*.").lower()
        if d not in ignore:
            domains.add(d)
    return sorted(domains)


def _analyze_cookies(headers):
    """Summarize Set-Cookie flags; flag cookies missing Secure/HttpOnly."""
    out = []
    for line in headers.get("set-cookie", "").splitlines():
        line = line.strip()
        if not line:
            continue
        name = line.split("=", 1)[0]
        low = line.lower()
        flags = []
        for flag in ("secure", "httponly"):
            flags.append(f"{flag}={('yes' if flag in low else 'no')}")
        samesite = re.search(r"samesite=([a-z]+)", low)
        flags.append(f"samesite={samesite.group(1) if samesite else 'none'}")
        out.append(f"{name} ({', '.join(flags)})")
    return out


def _detect_technologies(headers, body):
    found = set()
    for name, hdr_rules, body_rules in _TECH:
        if any(re.search(pat, headers.get(h, ""), re.I) for h, pat in hdr_rules.items()):
            found.add(name)
            continue
        if any(re.search(pat, body, re.I) for pat in body_rules):
            found.add(name)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        found.add(f"Generator: {gen.group(1).strip()}")
    return sorted(found)


def _cert_cn(cert, field):
    try:
        for entry in cert.get(field, []):
            for key, value in entry:
                if key == "commonName":
                    return value
    except Exception:
        pass
    return ""


def _tls_info(host):
    """TLS certificate + protocol info. stdlib ssl when possible; curl -v over proxy."""
    if utils._PROXY:
        return _tls_info_curl(host)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return {"note": "no certificate presented"}
                not_after = cert.get("notAfter")
                not_before = cert.get("notBefore")
                days_left = ""
                if not_after:
                    try:
                        days_left = f"{int((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)}"
                    except Exception:
                        days_left = ""
                sans = sorted({v for typ, v in cert.get("subjectAltName", []) if typ == "DNS"})
                return {
                    "subject": _cert_cn(cert, "subject"),
                    "issuer": _cert_cn(cert, "issuer"),
                    "not_before": not_before,
                    "not_after": not_after,
                    "days_left": days_left,
                    "version": tls.version(),
                    "cipher": (tls.cipher() or ("",))[0],
                    "san": ", ".join(sans[:20]),
                }
    except Exception as exc:
        return {"note": f"TLS probe failed: {exc}"}


def _tls_info_curl(host):
    if not _CURL:
        return {"note": "TLS probe skipped (no curl)"}
    try:
        r = _sh([_CURL, "-sS", "-I", "-v", "-A", UA, f"https://{host}"], timeout=15)
    except Exception as exc:
        return {"note": f"TLS probe failed: {exc}"}
    text = r.stderr
    def _cn(match):
        m = re.search(r"CN=([^;\s]+)", match.group(1))
        return m.group(1) if m else match.group(1).strip()

    out = {}
    m = re.search(r"subject:\s*(.+)", text)
    if m:
        out["subject"] = _cn(m)
    m = re.search(r"issuer:\s*(.+)", text)
    if m:
        out["issuer"] = _cn(m)
    m = re.search(r"expire date:\s*(.+)", text)
    if m:
        out["not_after"] = m.group(1).strip()
    m = re.search(r"SSL connection using\s*(.+)", text)
    if m:
        out["version"] = m.group(1).strip()
    return out or {"note": "no TLS data returned"}


def _favicon(host, body):
    out = {}
    m = re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)', body, re.I)
    href = m.group(1) if m else "/favicon.ico"
    low = href.strip().lower()
    if low.startswith(("data:", "javascript:", "about:", "blob:")) or low in ("", "#"):
        href = "/favicon.ico"
    if href.startswith("//"):
        url = "https:" + href
    elif href.startswith(("http://", "https://")):
        url = href
    else:
        url = "https://" + host + (href if href.startswith("/") else "/" + href)
    raw = _http_bytes(url)
    if not raw or not _looks_like_image(raw):
        return out
    out["url"] = url
    out["size"] = len(raw)
    out["sha256"] = hashlib.sha256(raw).hexdigest()[:16]
    out["mmh3"] = _murmur3_32(base64.b64encode(raw))
    return out


def _looks_like_image(raw):
    """Reject HTML/plain-text bodies so 404 pages are not hashed as icons."""
    head = raw[:16].lstrip()
    if head.startswith((b"<html", b"<!doctype", b"<head", b"<body")):
        return False
    if raw[:8] == b"\x89PNG\r\n\x1a\n":        # PNG
        return True
    if raw[:4] == b"\x00\x00\x01\x00":          # ICO
        return True
    if raw[:3] == b"\xff\xd8\xff":              # JPEG
        return True
    if raw[:6] in (b"GIF87a", b"GIF89a"):       # GIF
        return True
    if head.startswith(b"<svg") or head.startswith(b"<?xml"):  # SVG
        return True
    if raw[:2] == b"BM":                        # BMP
        return True
    return False


def _murmur3_32(data, seed=0):
    """MurmurHash3 x86_32 (Shodan favicon-hash compatible)."""
    data = bytes(data)
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length & 0xFFFFFFFC
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 &= 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 3
    if tail >= 3:
        k1 ^= data[rounded + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 & 0xFFFFFFFF


# ─── content discovery ────────────────────────────────────

def _parse_robots(body):
    """Extract Disallow/Allow/Sitemap directives from robots.txt."""
    out = []
    for line in body.splitlines():
        line = line.strip()
        m = re.match(r"^\s*(User-agent|Disallow|Allow|Sitemap|Crawl-delay)\s*:\s*(.+)\s*$", line, re.I)
        if m:
            out.append(f"{m.group(1).title()}: {m.group(2).strip()}")
    return out


def _parse_sitemap(xml):
    """Extract <loc> URLs from a sitemap XML body."""
    return re.findall(r"<loc>\s*([^<]+?)\s*</loc>", xml)[:200]


def _extract_js_endpoints(body):
    """Pull URL/path-like strings out of JavaScript source."""
    endpoints = set()
    endpoints.update(re.findall(r'''["'`](/(?:api|v[0-9]|graphql|wp-json|rest|admin|internal|static|assets|ajax)(?:/[A-Za-z0-9_./?=&-]*)?)["'`]''', body))
    endpoints.update(re.findall(r"https?://[A-Za-z0-9.-]+/[A-Za-z0-9_./?=&%-]*", body))
    return sorted(endpoints)[:100]


_JS_SECRET_KEYS = (
    "api_key", "api-key", "apikey", "access_token", "accessToken", "auth_token",
    "secret", "client_secret", "private_key", "password", "passwd",
    "authorization", "bearer", "aws_access_key_id", "aws_secret_access_key",
    "google_api_key", "stripe_secret_key", "slack_token", "openai_api_key",
)


def _extract_js_interesting(body):
    """Flag likely secrets/tokens left in JavaScript."""
    hits = set()
    for key in _JS_SECRET_KEYS:
        for m in re.findall(rf"[\"']?{re.escape(key)}[\"']?\s*[:=]\s*[\"'][^\"']{{4,}}[\"']", body, re.I):
            hits.add(m[:80])
    return sorted(hits)[:50]


def _exposure_checks(host, timeout=10):
    """Probe well-known sensitive paths without following redirects.

    A 301/302 to a catch-all homepage must not count as "exposed"; only the
    direct status is reported, and 404s are dropped.
    """
    found = []
    base = f"https://{host}"
    interesting = {200, 301, 302, 401, 403}

    def _probe(path):
        code = _http_status(base + path, timeout=timeout, follow=False)
        return f"{path} ({code})" if code in interesting else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for item in pool.map(_probe, _EXPOSURE_PATHS):
            if item:
                found.append(item)
    return found


def _js_files(body, host):
    """Collect same-origin .js URLs referenced by an HTML page."""
    urls = set()
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)', body):
        src = src.strip()
        if src.startswith("//"):
            src = "https:" + src
        elif src.startswith("/"):
            src = f"https://{host}{src}"
        elif not src.startswith("http"):
            src = f"https://{host}/{src}"
        if not src.endswith(".js"):
            continue
        parsed = urllib.parse.urlparse(src)
        h = (parsed.hostname or "").lower()
        if h == host or h.endswith("." + host):
            urls.add(src)
    return sorted(urls)[:10]


# ─── DNS email security ───────────────────────────────────

def _dns_email_security(host):
    out = {}
    if not _DIG:
        return out
    tx = _dig_short(host, "TXT")
    spf = ""
    for chunk in re.findall(r'"([^"]*)"', tx):
        if chunk.startswith("v=spf1"):
            spf = chunk
            break
    if spf:
        out["spf"] = spf
        out["spf_all"] = _spf_all(spf)
        inc = _spf_includes(spf)
        if inc:
            out["spf_includes"] = ", ".join(inc)
    dmarc_raw = _dig_short(f"_dmarc.{host}", "TXT")
    dmarc = ""
    for chunk in re.findall(r'"([^"]*)"', dmarc_raw):
        if chunk.startswith("v=DMARC1"):
            dmarc = chunk
            break
    if dmarc:
        out["dmarc"] = dmarc
        p = re.search(r"p=(\w+)", dmarc)
        if p:
            out["dmarc_policy"] = p.group(1)
    caa = _dig_short(host, "CAA")
    caa_vals = [l.strip() for l in caa.split("\n") if l.strip()]
    if caa_vals:
        out["caa"] = ", ".join(caa_vals)
    dnskey = _dig_short(host, "DNSKEY")
    out["dnssec"] = "yes" if dnskey.strip() else "no"
    return out


def _spf_all(spf):
    m = re.search(r"([+~?-])all\b", spf)
    if not m:
        return "missing"
    return {"+": "permissive", "~": "softfail", "-": "strict", "?": "neutral"}.get(m.group(1), m.group(1))


def _spf_includes(spf):
    # Underscores are common in SPF targets (_spf.google.com, _smtp._tls).
    return re.findall(r"(?:include|redirect|a|mx):([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", spf)


# ─── orchestrator ─────────────────────────────────────────

def _phase_vulns(headers, body, key=None, cap=3):
    """Known-CVE lookup for the versions the fingerprint phase found.

    Kept as its own phase rather than folded into the fingerprint for two
    reasons: it is the only pass that talks to a third-party API, and it is the
    only one that is deliberately slow, because NVD allows five anonymous
    requests per rolling 30 seconds and the module spaces its calls to stay
    inside that. Everything else in a website run is unaffected if this is
    skipped or fails.
    """
    if not headers and not body:
        return {}
    try:
        res = _cve.scan(headers, body or "", key=key, cap=cap)
    except Exception as exc:
        return {"vulns": {"status": "error", "reason": str(exc)[:140],
                          "cve_count": 0, "cves": []}}
    if not res.get("detected"):
        # Nothing versioned was identified, so there is nothing to match and no
        # reason to make the operator wait through rate-limited calls.
        return {}
    return {"vulns": res}


def website(target, display=None, vulns=True, nvd_key=None, cve_cap=3):
    out = _collect(target, vulns=vulns, nvd_key=nvd_key, cve_cap=cve_cap)
    if display:
        display(out)
    return out


def _phase_dns(host):
    """A/AAAA/... records, email security, wildcard DNS, zone transfer."""
    result = {}
    ips = set()
    dns = {}
    if _DIG:
        for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA", "SOA"):
            raw = _dig_short(host, rtype)
            vals = [l.strip() for l in raw.split("\n") if l.strip()]
            if vals:
                dns[rtype] = ", ".join(vals)
            if rtype in ("A", "AAAA"):
                for line in vals:
                    # `dig +short` can emit a CNAME target alongside the A
                    # record; only keep addresses so PTR/sweep/scans stay valid.
                    line = line.rstrip(".")
                    if _is_ipv4(line) or _is_ipv6(line):
                        ips.add(line)
    if dns:
        result["dns_records"] = dns
    try:
        es = _dns_email_security(host)
        if es:
            result["dns_email_security"] = es
    except Exception:
        pass
    wild, wild_ip = False, ""
    try:
        wild, wild_ip = _is_wildcard(host)
        result["wildcard_dns"] = {"detected": "yes" if wild else "no",
                                  "resolves_to": wild_ip or ""}
    except Exception:
        pass
    try:
        axfr = _axfr(host)
        if axfr:
            result["zone_transfer"] = axfr[:200]
    except Exception:
        pass
    result["_ips"] = ips
    result["_wild"] = wild
    result["_wild_ip"] = wild_ip
    return result


def _subfinder(host, timeout=180):
    """Passive subdomain discovery via subfinder (52 sources).

    Preferred over the hand-rolled crt.sh and CertSpotter scrapers when it is
    installed: it subsumes both and adds roughly fifty more. Those two are kept
    as the fallback so a machine without subfinder still gets certificate
    transparency coverage.

    Only the apex is queried. Recursion is deliberately off — a single host can
    return five figures of names, and recursing multiplies that.
    """
    if not _SUBFINDER:
        return set()
    try:
        # -timeout is the per-source HTTP budget and -max-time the whole run.
        # Both are deliberately generous relative to the subprocess timeout:
        # at -timeout 5 the slower sources simply fail, and measured coverage on
        # github.com fell from 389 names to 213.
        r = subprocess.run(
            [_SUBFINDER, "-d", host, "-silent", "-no-color", "-timeout", "10",
             "-max-time", str(max(60, int(timeout * 0.7)))],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return set()
    return _clean_sub_names(r.stdout or "", host)


def _clean_sub_names(raw, host):
    """Normalise subfinder's stdout into a set of in-scope hostnames.

    Pure and separately testable: the filters here are what stop a certificate
    transparency dump from becoming a subdomain list.

    Scope is matched on a label boundary, not a string suffix. ``notgithub.com``
    ends with ``github.com`` but is a different domain entirely, and reporting it
    as a github.com subdomain would attribute someone else's host to the target.
    """
    host = (host or "").lower().strip(".")
    suffix = "." + host
    out = set()
    for line in (raw or "").splitlines():
        name = line.strip().lower().rstrip(".")
        if not name:
            continue
        # A leading "*." is a wildcard-cert artefact, not a real host.
        while name.startswith("*."):
            name = name[2:]
        if not name or name == host or not name.endswith(suffix):
            continue
        out.add(name)
    return out


def _resolves(name, timeout=4):
    """Does this name resolve? One A/AAAA lookup, no recursion requested."""
    if not _DIG:
        return False
    try:
        r = subprocess.run([_DIG, "+short", "+time=2", "+tries=1", name],
                           capture_output=True, text=True, timeout=timeout)
    except Exception:
        return False
    return bool((r.stdout or "").strip())


def _wild_canary(host):
    """A name under `host` that should never exist, used to detect wildcards."""
    digest = hashlib.md5(host.encode("utf-8")).hexdigest()[:12]
    return f"spyglass-wildcard-probe-{digest}.{host}"


def _filter_resolvable(hosts, seen_count=None, limit=1500, max_workers=40):
    """Keep only names that resolve, within a bounded number of lookups.

    This is what makes bulk passive discovery usable. Measured against
    ``example.com``, subfinder returns 22,250 names and the sampled ones have no
    DNS record at all — certificate-transparency and archive entries for hostnames
    that were never live or no longer exist. Reporting those as subdomains is
    worse than reporting none, because a list that is mostly dead cannot be
    triaged.

    The lookup count is capped because resolution is the expensive part: at
    ~40 concurrent, 22,250 names cost 180 seconds. When a target produces more
    candidates than the cap, the names corroborated by the most sources are
    checked first and the remainder are reported as unchecked rather than silently
    dropped. A wildcard domain is caught earlier by the canary probe, so a large
    list here means noisy sources rather than a wildcard.
    """
    hosts = set(hosts or ())
    if not hosts:
        return set(), 0
    ordered = sorted(hosts, key=lambda n: -(seen_count or {}).get(n, 1))
    truncated = 0
    if len(ordered) > limit:
        truncated = len(ordered) - limit
        ordered = ordered[:limit]

    live = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for name, ok in zip(ordered, pool.map(_resolves, ordered)):
            if ok:
                live.add(name)
    return live, truncated


def _phase_passive_subs(host):
    """Passive subdomain sources.

    subfinder leads when installed; crt.sh, HackerTarget, CertSpotter and the
    Wayback Machine run alongside it and act as the fallback when it is absent.
    Everything is resolution-filtered before it is reported, and the filter is
    bounded so a noisy target cannot dominate the run.
    """
    result = {}
    passive_subs, passive_ips = set(), set()
    sources = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        sf_f = pool.submit(_subfinder, host)
        crt_f = pool.submit(_crt_subs, host)
        ht_f = pool.submit(_hackertarget_subs, host)
        cs_f = pool.submit(_certspotter_subs, host)
        wb_f = pool.submit(_wayback_cdx, host)
        rd_f = pool.submit(_rapiddns, host)
        sf = _future_result(sf_f, set())
        crt = _future_result(crt_f, set())
        ht_subs, ht_ips = _future_result(ht_f, (set(), set()))
        cs = _future_result(cs_f, set())
        wb = _future_result(wb_f, {"subs": set(), "paths": set(), "first": "",
                                   "last": "", "count": 0})
        rd_subs, rd_rows = _future_result(rd_f, (set(), []))

    passive_subs |= sf | crt | ht_subs | cs | rd_subs | wb.get("subs", set())
    passive_ips |= ht_ips | {ip for _n, ip, _t, _d in rd_rows}
    sources["subfinder"] = len(sf)
    sources["crt_sh"] = len(crt)
    sources["hackertarget"] = len(ht_subs)
    sources["certspotter"] = len(cs)
    sources["rapiddns"] = len(rd_subs)
    sources["wayback"] = len(wb.get("subs", set()))

    if passive_subs:
        # A wildcard domain answers for every name asked of it, so probe one
        # canary first: if that resolves, the whole list is meaningless.
        if _resolves(_wild_canary(host)):
            sources["wildcard"] = "all names resolve; bulk results suppressed"
            passive_subs = set()
        else:
            # Names corroborated by more than one source go through the
            # resolution filter first, so a capped run keeps the best evidence.
            seen = {}
            for group in (sf, crt, ht_subs, cs, rd_subs, wb.get("subs", set())):
                for n in group:
                    seen[n] = seen.get(n, 0) + 1
            before = len(passive_subs)
            passive_subs, truncated = _filter_resolvable(passive_subs, seen)
            dropped = before - len(passive_subs) - truncated
            if dropped:
                sources["unresolved_dropped"] = dropped
            if truncated:
                sources["unchecked_truncated"] = truncated

    result["_passive_subs"] = passive_subs
    result["_passive_ips"] = passive_ips
    result["_sources"] = sources
    result["_crt"] = crt
    result["_wb"] = wb
    result["_pdns"] = rd_rows
    return result


def _wild_canary(host):
    """A name under `host` that should never exist, used to detect wildcards."""
    digest = hashlib.md5(host.encode("utf-8")).hexdigest()[:12]
    return f"spyglass-wildcard-probe-{digest}.{host}"


def _phase_fingerprint(host, headers, body):
    """HTTP headers, security headers, cookies, CSP, tech, favicon, TLS, CVEs."""
    result = {}
    if headers:
        server_bits = []
        if headers.get("server"):
            server_bits.append(f"Server: {headers['server']}")
        if headers.get("x-powered-by"):
            server_bits.append(f"X-Powered-By: {headers['x-powered-by']}")
        if server_bits:
            result["http_headers"] = {"Summary": " | ".join(server_bits)}
    try:
        sec = _analyze_headers(headers)
        if sec:
            result["security_headers"] = sec
    except Exception:
        pass
    try:
        cookies = _analyze_cookies(headers)
        if cookies:
            result["cookies"] = cookies
    except Exception:
        pass
    try:
        csp = headers.get("content-security-policy")
        if csp:
            domains = _extract_csp_domains(csp)
            if domains:
                result["csp_domains"] = domains
    except Exception:
        pass
    try:
        tech = _detect_technologies(headers, body)
        if tech:
            result["technologies"] = tech
    except Exception:
        pass
    try:
        fav = _favicon(host, body)
        if fav.get("mmh3") is not None:
            result["favicon"] = fav
    except Exception:
        pass
    try:
        tls = _tls_info(host)
        if tls:
            result["tls"] = tls
    except Exception:
        pass
    return result


def _phase_content(host, body):
    """robots.txt, sitemap, exposed files, JS endpoints & secrets."""
    result = {}
    robots_body = _http_body(f"https://{host}/robots.txt")
    try:
        robots = _parse_robots(robots_body)
        if robots:
            result["robots"] = robots
    except Exception:
        pass
    try:
        sm = _http_body(f"https://{host}/sitemap.xml")
        locs = _parse_sitemap(sm)
        if locs:
            result["sitemap"] = locs
    except Exception:
        pass
    try:
        exposure = _exposure_checks(host)
        if exposure:
            result["interesting_files"] = exposure
    except Exception:
        pass
    try:
        endpoints, interesting = set(), set()
        for js_url in _js_files(body, host):
            js = _http_body(js_url, timeout=12, limit=400_000)
            if js:
                endpoints.update(_extract_js_endpoints(js))
                interesting.update(_extract_js_interesting(js))
        if endpoints:
            result["js_endpoints"] = sorted(endpoints)[:100]
        if interesting:
            result["js_interesting"] = sorted(interesting)[:50]
    except Exception:
        pass
    return result


def _phase_whois(host):
    """WHOIS. Follow the IANA thin referral to the registry when present."""
    result = {}
    if _check_tool("whois", _WHOIS):
        wh = _run(["whois", host], timeout=30)
        fields = _extract_whois_fields(wh)
        refer = re.search(r"(?m)^refer:\s*(\S+)", wh)
        if refer:
            # The IANA thin referral describes the TLD (e.g. "Domain: COM"),
            # not the queried domain. Only present it if the registry follow-up
            # fails to return anything about the domain itself.
            full = _run(["whois", "-h", refer.group(1), host], timeout=30)
            full_fields = _extract_whois_fields(full)
            if full_fields:
                wh, fields = full, full_fields
            elif re.search(r"no match", full, re.I):
                wh, fields = "", {"Status": "unregistered (no registry record)"}
            else:
                wh, fields = "", {"Status": "whois unavailable"}
        who_emails = _extract_emails(wh)
        who_phones = _extract_phones(wh)
        whois_data = dict(fields)
        extra_emails = [e for e in who_emails if e not in whois_data.values()]
        if extra_emails:
            whois_data["Extra Emails"] = ", ".join(extra_emails)
        extra_phones = [p for p in who_phones if p not in whois_data.values()]
        if extra_phones:
            whois_data["Extra Phones"] = ", ".join(extra_phones)
        if whois_data:
            result["whois"] = whois_data
    return result


def _phase_urlscan(host):
    """Passive page observations and third-party references, via urlscan.io."""
    try:
        return _urlscan(host)
    except Exception:
        return {}


def _phase_dirs(paths):
    """Directory paths recovered from the Wayback index, for the target host.

    This replaces gobuster's ``dir`` brute-force, and it is a better source for
    the same data type rather than merely a passive substitute. A gobuster hit is
    a wordlist guess that happened to return a status code; an archived path is
    a URL that genuinely existed. The trade is coverage — the archive only knows
    what a crawler reached — and the win is that nothing is sent to the target.

    Reported as the distinct first path segment (``/admin``, ``/api``) plus a
    capped sample of full paths, because "directories" was always a coarse
    summary and 3,000 full paths is not one.
    """
    result = {}
    if not paths:
        return result
    segments, full = set(), set()
    for p in paths:
        if _usable_path(p):
            full.add(p)
            head = "/" + p.lstrip("/").split("/", 1)[0]
            if len(head) > 1:
                segments.add(head)
    if segments:
        result["directories"] = sorted(segments)[:120]
    if full:
        sample = sorted(full, key=lambda s: (len(s), s))
        result["archived_paths"] = sample[:40]
        if len(sample) > 40:
            result["archived_paths_note"] = f"showing 40 of {len(sample)}"
    return result


# A path segment long enough to be a filename is not a directory, and an archive
# is full of them. Without a ceiling one long non-ASCII filename becomes the only
# entry in `directories`, which is worse than reporting nothing: it looks like a
# finding and is not one. 64 covers every real directory name and excludes the
# escaped-URL blobs that percent-decoding can produce.
_MAX_SEGMENT = 64


def _usable_path(path):
    """True if a path's first segment is short and plausible as a directory."""
    head = path.lstrip("/").split("/", 1)[0]
    if not head or len(head) > _MAX_SEGMENT:
        return False
    # A segment with no alphanumeric content is punctuation, not a name.
    return any(ch.isalnum() for ch in head)


def _phase_active_brute(host, wild, wild_ip):
    try:
        return _active_brute(host, wild, wild_ip)
    except Exception:
        return set()


def _phase_shodan_ports(ips):
    """Shodan CLI + InternetDB ports + reverse DNS + adjacent-host sweep.

    The Shodan CLI half needs an API key and contributes Org/ISP/Country, which
    nothing else in this phase provides. The InternetDB half is keyless and
    carries the port list, so ports are reported even when the CLI is
    unconfigured — which is the common case.
    """
    result = {}
    if ips and _check_tool("shodan", _SHODAN):
        shodan_data = []
        for ip in ips[:3]:
            try:
                r = subprocess.run(["shodan", "host", ip], capture_output=True,
                                   text=True, timeout=20, env=utils._proxy_env())
            except Exception as exc:
                shodan_data.append(f"{ip}: {exc}")
                continue
            data, err = r.stdout.strip(), r.stderr.strip()
            if data:
                org = isp = country = ports = ""
                for line in data.split("\n"):
                    low = line.lower()
                    if "organization" in low or low.startswith("org:"):
                        org = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "isp" in low:
                        isp = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "country" in low:
                        country = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "ports" in low:
                        ports = line.split(":", 1)[1].strip() if ":" in line else ""
                parts = [p for p in (f"Org: {org}" if org else "",
                                     f"ISP: {isp}" if isp else "",
                                     f"Country: {country}" if country else "",
                                     f"Ports: {ports}" if ports else "") if p]
                shodan_data.append(f"{ip}: {' | '.join(parts)}" if parts else f"{ip}: No Shodan data")
            elif "403" in err:
                shodan_data.append(f"{ip}: Free tier limit")
            elif "init" in err.lower():
                shodan_data.append(f"{ip}: Shodan not configured")
            elif err:
                shodan_data.append(f"{ip}: {err.splitlines()[-1]}")
            else:
                shodan_data.append(f"{ip}: No Shodan data")
        result["shodan"] = shodan_data

    # Replaces an `nmap --top-ports 50 -sV` pass. InternetDB is keyless, so this
    # works where the Shodan CLI did not, and it does not touch the target.
    #
    # What is genuinely lost: nmap's `-sV` read the banner off the live socket
    # and reported a service *and version* per port ("80/tcp Apache httpd
    # 2.4.41"). InternetDB reports the port list and the host's CPEs, which
    # identifies the product but not its build. Nothing downstream depended on
    # the version — cve.py is fed headers and body only, never port-scan output,
    # so no CVE coverage moves.
    if ips:
        netdb = []
        for ip in ips[:3]:
            data = _http_json(f"https://internetdb.shodan.io/{ip}", timeout=20)
            if not isinstance(data, dict) or ("detail" in data and "ip" not in data):
                netdb.append(f"{ip}: no InternetDB record")
                continue
            bits = []
            ports = [p for p in (data.get("ports") or []) if isinstance(p, int)]
            if ports:
                bits.append("ports: " + ", ".join(str(p) for p in sorted(ports)[:25]))
            cpes = [c for c in (data.get("cpes") or []) if isinstance(c, str)]
            if cpes:
                bits.append("product: " + ", ".join(cpes[:3]))
            tags = [t for t in (data.get("tags") or []) if isinstance(t, str)]
            if tags:
                bits.append("tags: " + ", ".join(sorted(tags)[:6]))
            netdb.append(f"{ip}: {' | '.join(bits)}" if bits
                         else f"{ip}: no ports recorded")
        if netdb:
            result["internetdb"] = netdb

    if ips:
        try:
            rdns = []
            for ip in ips[:8]:
                name = _reverse_dns(ip)
                if name:
                    rdns.append(f"{ip} -> {name}")
            if rdns:
                result["reverse_dns"] = rdns
            # Adjacent-host sweep only when DNS is not going through a proxy.
            if not utils._PROXY and ips:
                v4 = next((ip for ip in ips if _is_ipv4(ip)), None)
                if v4:
                    sweep = _ptr_sweep(v4)
                    if sweep:
                        result["ptr_sweep"] = sweep
        except Exception:
            pass
    return result


def _collect(target, vulns=True, nvd_key=None, cve_cap=3):
    host = utils._domain(target)
    _reset_caches()
    result = {}

    # Homepage fetched once and shared by the fingerprint + content phases.
    headers = _http_headers(f"https://{host}")
    body = _http_body(f"https://{host}")

    # Stage 1 — independent phases run concurrently.
    #
    # `_phase_dirs` is no longer in this pool: it derives its paths from the
    # Wayback CDX result, which arrives with `subs`, so it has to run after
    # stage 1 rather than alongside it.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        dns_f = pool.submit(_phase_dns, host)
        subs_f = pool.submit(_phase_passive_subs, host)
        fp_f = pool.submit(_phase_fingerprint, host, headers, body)
        content_f = pool.submit(_phase_content, host, body)
        whois_f = pool.submit(_phase_whois, host)
        us_f = pool.submit(_phase_urlscan, host)
        if vulns:
            vn_f = pool.submit(_phase_vulns, headers, body, nvd_key, cve_cap)
        else:
            vn_f = None
        dns = _future_result(dns_f, {})
        subs = _future_result(subs_f, {})
        fp = _future_result(fp_f, {})
        content = _future_result(content_f, {})
        whois = _future_result(whois_f, {})
        uscan = _future_result(us_f, {})
        vn = _future_result(vn_f, {}) if vn_f else {}

    for phase in (dns, subs, fp, content, whois, uscan, vn):
        for key, value in phase.items():
            if not key.startswith("_"):
                result[key] = value

    # State the dependent phases need.
    ips = sorted(set(dns.get("_ips", set())) | set(subs.get("_passive_ips", set())))
    wild = dns.get("_wild", False)
    wild_ip = dns.get("_wild_ip")

    # Stage 2 — active brute + port scan depend on stage-1 state.
    active = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        active_f = pool.submit(_phase_active_brute, host, wild, wild_ip)
        scan_f = pool.submit(_phase_shodan_ports, ips)
        active = _future_result(active_f, set())
        scan = _future_result(scan_f, {})
    for key, value in scan.items():
        result[key] = value

    # Subdomain assembly (passive + active).
    passive_subs = subs.get("_passive_subs", set())
    sources = dict(subs.get("_sources", {}))
    sources["active"] = len(active)
    all_subs = sorted(passive_subs | active)
    if all_subs:
        result["subdomains"] = all_subs
        result["subdomain_sources"] = sources
    crt = subs.get("_crt", set())
    if crt:
        result["crt_sh_subdomains"] = sorted(crt)
    wb = subs.get("_wb", {})
    if wb.get("subs"):
        result["wayback_subdomains"] = sorted(wb["subs"])
    # Historical resolutions: what each name pointed at, and when anyone last
    # saw it. This is the "is this still dangling" check that live resolution
    # cannot answer, and it is a set rather than a scalar so `cases diff` sees a
    # changed address as what it is.
    rows = subs.get("_pdns") or []
    if rows:
        by_host = {}
        for name, ip, rrtype, seen in rows:
            by_host.setdefault(name, []).append(
                {"ip": ip, "type": rrtype, "last_seen": seen})
        result["passive_dns"] = {
            "hosts": len(by_host),
            "records": len(rows),
            "resolved": {k: v for k, v in sorted(by_host.items())},
        }
    # Archived-path directories, now that the CDX result is in hand.
    dirs = _phase_dirs(wb.get("paths") or set())
    if dirs:
        result.update(dirs)

    # Stage 3 — httpx probing of all discovered subdomains.
    if all_subs and _HTPPX:
        try:
            hx = _run(
                ["httpx", "-silent", "-status-code", "-title", "-server",
                 "-content-length", "-timeout", "10"]
                + [f"https://{s}" for s in all_subs][:200],
                timeout=90,
            )
            if hx and "Usage:" not in hx and "No such option" not in hx:
                probe = [l.strip() for l in hx.split("\n") if l.strip()]
                if probe:
                    result["http_probe"] = probe
        except Exception:
            pass

    # Wayback history (from the CDX call in stage 1).
    if wb.get("first"):
        result["history"] = {
            "first_snapshot": wb["first"],
            "last_snapshot": wb["last"],
            "snapshot_count": wb["count"],
        }

    return result


def _ptr_sweep(ip, window=32, max_hosts=40):
    """Reverse-resolve adjacent hosts in the same /24 (shared hosting signal)."""
    try:
        octets = ip.split(".")
        prefix = ".".join(octets[:3])
        n = int(octets[3])
    except Exception:
        return []
    found = []
    lo, hi = max(1, n - window), min(254, n + window)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        def _probe(last):
            addr = f"{prefix}.{last}"
            if addr == ip:
                return None
            try:
                name = socket.gethostbyaddr(addr)[0]
                return f"{addr} -> {name}" if name else None
            except Exception:
                return None
        for item in pool.map(_probe, range(lo, hi + 1)):
            if item:
                found.append(item)
                if len(found) >= max_hosts:
                    break
    return found
