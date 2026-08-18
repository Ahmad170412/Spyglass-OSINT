"""Website reconnaissance for Spyglass.

A deep, defense-in-depth rebuild of the original module. Every probe is
independent and best-effort: a missing tool, an offline API, or a refused
connection degrades gracefully instead of failing the whole run.

Design principles
-----------------
* No paid APIs and no API keys. Passive sources are crt.sh, HackerTarget,
  AlienVault OTX (public endpoint), and the Wayback Machine CDX index.
* OPSEC-aware: HTTP goes through curl (which honors --proxy); DNS through
  ``dig`` is routed via torsocks when a proxy is active; in-process DNS
  resolution is only used when no proxy is set, so the operator's resolver is
  never leaked through Tor.
* macOS/Linux focused: dig, curl, whois, nmap, gobuster, httpx and shodan are
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
from .utils import (
    _check_tool,
    _extract_emails,
    _extract_phones,
    _extract_whois_fields,
    _run,
    _CURL,
    _DIG,
    _GOBUSTER,
    _HTPPX,
    _NMAP,
    _SHODAN,
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

_DIR_LIST = """
admin administrator api app assets backup backups cache cdn cgi-bin cmd config
configuration content css dashboard db demo dev docs download downloads error
examples export favicon.ico files fonts forum graphql help home html images
img include includes index install js json language lib library license login
log logs mail media migrate mobile modules news old package pages panel
phpinfo.php plugins private prod public README readme reports rest robots.txt
rss sass save scripts search secure server-status service services session
setup sitemap.xml sql src ssh stat static stats status storage styles svn
swagger temp template templates test tmp todo tools tmp update upload uploads
user users v2 vendor version video views web webapp webroot wiki wpad.dat www
xml xmlrpc
""".strip().split()

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
    """One CDX query with matchType=domain: subdomains + snapshot history."""
    out = {"subs": set(), "first": "", "last": "", "count": 0}
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
    if stamps:
        out["first"] = min(stamps)
        out["last"] = max(stamps)
        out["count"] = len(stamps)
    return out


def _active_brute(host, wildcard, wildcard_ip):
    """Wordlist brute-force. gobuster preferred; native fallback when no proxy."""
    found = set()
    wordlist = _wordlist()
    if _GOBUSTER:
        out = _run(
            ["gobuster", "dns", "-d", host, "-w", "-", "-q"]
            + (utils._proxy_args() if utils._PROXY else []),
            timeout=90, stdin="\n".join(wordlist),
        )
        found = {s.strip().lower() for s in re.findall(r"Found:\s*(\S+)", out)}
        if wildcard and wildcard_ip:
            found = {s for s in found if _resolve_a(s) != wildcard_ip}
        return found
    if utils._PROXY:
        # In-process resolution would bypass torsocks and leak DNS — skip it.
        return found

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

def website(target, display=None):
    out = _collect(target)
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


def _phase_passive_subs(host):
    """Passive subdomain sources (crt.sh, HackerTarget, CertSpotter, Wayback)."""
    result = {}
    passive_subs, passive_ips = set(), set()
    sources = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        crt_f = pool.submit(_crt_subs, host)
        ht_f = pool.submit(_hackertarget_subs, host)
        cs_f = pool.submit(_certspotter_subs, host)
        wb_f = pool.submit(_wayback_cdx, host)
        crt = _future_result(crt_f, set())
        ht_subs, ht_ips = _future_result(ht_f, (set(), set()))
        cs = _future_result(cs_f, set())
        wb = _future_result(wb_f, {"subs": set(), "first": "", "last": "", "count": 0})
    passive_subs |= crt | ht_subs | cs | wb.get("subs", set())
    passive_ips |= ht_ips
    sources["crt_sh"] = len(crt)
    sources["hackertarget"] = len(ht_subs)
    sources["certspotter"] = len(cs)
    sources["wayback"] = len(wb.get("subs", set()))
    result["_passive_subs"] = passive_subs
    result["_passive_ips"] = passive_ips
    result["_sources"] = sources
    result["_crt"] = crt
    result["_wb"] = wb
    return result


def _phase_fingerprint(host, headers, body):
    """HTTP headers, security headers, cookies, CSP, tech, favicon, TLS."""
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


def _phase_dirs(host):
    """Directory brute-force (gobuster, small bundled list)."""
    result = {}
    if _check_tool("gobuster", _GOBUSTER):
        gb_out = _run(
            ["gobuster", "dir", "-u", f"https://{host}", "-w", "-", "-q", "-t", "20", "-k"]
            + (utils._proxy_args() if utils._PROXY else []),
            timeout=90, stdin="\n".join(_DIR_LIST),
        )
        dirs = sorted(set(re.findall(r"/(\S+)\s+\(Status:\s*\d+\)", gb_out)))
        if dirs:
            result["directories"] = dirs
    return result


def _phase_active_brute(host, wild, wild_ip):
    try:
        return _active_brute(host, wild, wild_ip)
    except Exception:
        return set()


def _phase_shodan_ports(ips):
    """Shodan + nmap port scan + reverse DNS + adjacent-host sweep."""
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

    if ips and _check_tool("nmap", _NMAP):
        ports_data = []
        for ip in ips[:1]:
            nm = _run(["nmap", "--top-ports", "50", "-sV", "-T4", "--open",
                       ip, "-oG", "-"], timeout=90)
            ports = re.findall(r"(\d+)/(open|filtered)/tcp//([^/]*?)//([^/]*?)", nm)
            if ports:
                parts = []
                for p, st, sv, pr in ports:
                    if pr:
                        parts.append(f"{p}/{sv} ({pr})")
                    elif sv:
                        parts.append(f"{p}/{sv}")
                    else:
                        parts.append(p)
                ports_data.append(f"{ip}: {', '.join(parts)}")
            else:
                ports_data.append(f"{ip}: No open ports found")
        if ports_data:
            result["port_scan"] = ports_data

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


def _collect(target):
    host = utils._domain(target)
    _reset_caches()
    result = {}

    # Homepage fetched once and shared by the fingerprint + content phases.
    headers = _http_headers(f"https://{host}")
    body = _http_body(f"https://{host}")

    # Stage 1 — independent phases run concurrently.
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        dns_f = pool.submit(_phase_dns, host)
        subs_f = pool.submit(_phase_passive_subs, host)
        fp_f = pool.submit(_phase_fingerprint, host, headers, body)
        content_f = pool.submit(_phase_content, host, body)
        whois_f = pool.submit(_phase_whois, host)
        dirs_f = pool.submit(_phase_dirs, host)
        dns = _future_result(dns_f, {})
        subs = _future_result(subs_f, {})
        fp = _future_result(fp_f, {})
        content = _future_result(content_f, {})
        whois = _future_result(whois_f, {})
        dirs = _future_result(dirs_f, {})

    for phase in (dns, subs, fp, content, whois, dirs):
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
