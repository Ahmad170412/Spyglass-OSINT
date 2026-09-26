#!/usr/bin/env python3
import os
import re
import json
import time
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

# pip's ``--user`` scheme installs console scripts into a per-version directory
# that is frequently absent from PATH. Sherlock, maigret, holehe and ignorant all
# land in ~/Library/Python/3.13/bin on macOS, and when that directory is not on
# PATH every one of them is silently skipped: the username module reported
# "user-scanner only" because shutil.which returned None for three engines that
# were installed and working. These directories are searched as a fallback so a
# PATH gap degrades coverage instead of silently shrinking it.
def _candidate_bin_dirs():
    """Directories to search when a tool is not on PATH.

    Covers the two schemes that hide console scripts on macOS: pip's
    ``--user`` tree under ~/Library/Python, and the python.org Framework
    installers under /Library/Frameworks. Both are per-version, so they are
    globbed rather than hardcoded to one release.
    """
    import glob as _glob

    dirs = []
    for v in ("3.14", "3.13", "3.12", "3.11", "3.10", "3.9"):
        dirs.append(os.path.expanduser(f"~/Library/Python/{v}/bin"))
        dirs.append(f"/Library/Frameworks/Python.framework/Versions/{v}/bin")
    dirs += [
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.pyenv/shims"),
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/opt/homebrew/opt/python@3.13/libexec/bin",
        "/opt/homebrew/opt/python@3.12/libexec/bin",
    ]
    dirs += sorted(_glob.glob("/opt/homebrew/opt/python@*/libexec/bin"), reverse=True)
    seen, out = set(), []
    for d in dirs:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append(d)
    return tuple(out)


_EXTRA_BIN_DIRS = _candidate_bin_dirs()


def _which(name):
    """shutil.which, extended to the user site-script directories."""
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_BIN_DIRS:
        candidate = os.path.join(d, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


_TORSOCKS = _which("torsocks")
_HOLEHE  = _which("holehe")
_US      = _which("user-scanner")
_SH      = _which("sherlock")
_MG      = _which("maigret")
_BB      = _which("blackbird") or _which("blackbird.py")
_BB_DIR  = os.path.dirname(_BB) if _BB else None
_PHONEINFOGA = _which("phoneinfoga")
_IGNORANT = _which("ignorant")

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

_DIG = _which("dig")
_NMAP = _which("nmap")
_GOBUSTER = _which("gobuster")
_HTPPX = _which("httpx")
_WHOIS = _which("whois")
_CURL = _which("curl")
_SHODAN = _which("shodan")
_EXIFTOOL = _which("exiftool")
_SUBFINDER = _which("subfinder")
_NUCLEI = _which("nuclei")


# ─── network helpers ──────────────────────────────────────

# A current desktop browser UA. Verification fetches real pages, and a default
# curl UA is rejected outright by a number of platforms, which would show up as
# a false negative indistinguishable from a missing profile.
_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


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


def _curl_status(url, timeout=20, headers=None):
    """HTTP status for a URL, following redirects. None on failure.

    Used where the status itself is the answer — Gravatar's ``?d=404`` avatar
    route returns 404 for an address with no avatar, which makes it an existence
    check that needs no body parsing.
    """
    if not _CURL:
        return None
    cmd = [_CURL, "-sS", "-L", "-o", os.devnull, "-w", "%{http_code}",
           "--max-time", str(timeout), "-A", _UA]
    for h in headers or ():
        cmd += ["-H", h]
    cmd = cmd[:1] + _proxy_args() + cmd[1:]
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except Exception:
        return None
    out = (r.stdout or "").strip()
    return int(out) if out.isdigit() else None


def _check_tool(name, path):
    if not path:
        from . import display as _ui
        _ui.err(f"{name} not found. Install it and ensure it's in your PATH.")
        return False
    return True


def _tool_failed(name, proc, stderr_tail=160):
    """Report a tool that exited non-zero.

    Without this a crashed engine is indistinguishable from one that simply found
    nothing. Blackbird was installed without its WhatsMyName dataset, crashed on
    every username search with a FileNotFoundError on stderr, and was reported as
    "0 results" for as long as nobody noticed — which quietly demoted the tool's
    four-way agreement ranking to three-way without any signal that anything was
    wrong.

    Returns True when the failure was reported.
    """
    if proc is None or getattr(proc, "returncode", 0) == 0:
        return False
    tail = ""
    try:
        raw = (proc.stderr or "").strip().splitlines()
        if raw:
            tail = raw[-1].strip()[:stderr_tail]
    except Exception:
        pass
    from . import display as _ui
    _ui.warn(f"{name} exited {proc.returncode} — treating its results as empty."
             + (f" Last line: {tail}" if tail else ""))
    return True


def blackbird_ready():
    """Is blackbird's username dataset present?

    Blackbird resolves its site list from ``os.getcwd()`` and ships without it, so
    a plain clone is installed broken. This checks for the file so the failure can
    be named instead of surfacing as an engine that mysteriously finds nothing.
    """
    if not _BB:
        return False, "blackbird is not installed"
    data = os.path.join(_BB_DIR or "", "data", "wmn-data.json")
    if not os.path.isfile(data):
        return False, ("blackbird's site list is missing "
                       f"({data}). Fetch it with:\\n"
                       "  curl -sL -o ~/.local/bin/blackbird/data/wmn-data.json \\\n"
                       "    https://raw.githubusercontent.com/WebBreacher/"
                       "WhatsMyName/main/wmn-data.json")
    return True, ""


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


# Interstitial and error pages, matched against the <title> only.
#
# This started as a whole-body substring scan and was wrong: a bare "captcha"
# matches GitHub's own feature-flag name "octocaptcha_origin_optimization" in
# the JS payload, so every real GitHub profile was rejected as a bot challenge.
# Titles are the reliable signal — an interstitial names itself — and a profile
# page's title is the one thing it is happy to state.
_CHALLENGE_TITLES = (
    "just a moment", "attention required", "security verification",
    "client challenge", "checking your browser", "one more step",
    "are you a robot", "verify you are human", "access denied",
    "please verify", "ddos protection", "bot verification",
    "403 forbidden", "too many requests", "rate limit",
    "please enable cookies", "checking if the site connection is secure",
)

# A small set of body markers, restricted to phrases long and specific enough
# that a real page will not contain them in a script or stylesheet URL.
_CHALLENGE_BODY = (
    "cf-browser-verification", "cf_chl_opt", "cf-turnstile",
    "checking your browser before accessing", "enable javascript and cookies",
    "ddos protection by", "px-captcha", "please stand by, we are checking",
)

# Not-found markers, likewise title-only. In the body they are far too common —
# forum templates and ad scripts say "not found" in unrelated copy — so a
# body-wide match would throw away genuine profiles.
_NOTFOUND_MARKERS = (
    "page not found", "404", "not found", "doesn't exist", "does not exist",
    "isn't available", "is not available", "no longer available",
    "user not found", "profile not found", "nothing found", "no results",
    "content not found", "not exist",
)

# Registration and marketing interstitials, matched against the <title>. These
# are not profiles: a signup prompt returned for a profile URL is a page about
# creating an account, and it can be large and repeat the requested slug many
# times. Observed: strava.com/athletes/<slug> answers 200 with 610KB, echoes the
# slug 36 times, and is titled "Signup for free to see more about Anthony" —
# a different person entirely.
_INTERSTITIAL_TITLES = (
    "sign up", "signup", "sign-in", "sign in", "create an account",
    "create account", "join now", "join us", "get started", "log in",
    "login", "register", "subscribe", "start your", "unlock the",
)

# A real profile page carries navigation, scripts and copy. The observed shells
# were ~1.4KB (an empty SPA frame) and ~6KB (a JavaScript app bundle with no
# server-rendered profile in it).
_MIN_BODY_BYTES = 1500

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _page_is_real(body, code):
    """Reject 200 responses that are not the page that was requested.

    ``code`` is the HTTP status, ``body`` the response text (may be truncated).
    Returns (ok, reason) so the caller can report *why* a candidate was dropped
    rather than silently shrinking the result set.
    """
    if not (200 <= code < 400):
        return False, f"http {code}"

    low = body.lower()
    for marker in _CHALLENGE_BODY:
        if marker in low:
            return False, "bot challenge"

    title = _TITLE_RE.search(body)
    title_text = title.group(1).strip().lower() if title else ""
    if title_text:
        for marker in _CHALLENGE_TITLES:
            if marker in title_text:
                return False, f"challenge page ({title_text[:36]!r})"
        for marker in _INTERSTITIAL_TITLES:
            if marker in title_text:
                return False, f"registration prompt ({title_text[:36]!r})"
        for marker in _NOTFOUND_MARKERS:
            if marker in title_text:
                return False, "title says not found"

    if len(body) < _MIN_BODY_BYTES:
        return False, f"body too small ({len(body)}B)"

    return True, "ok"


# Statuses that mean "ask again later", not "this page does not exist".
# Verification fans 30 requests out at once across every candidate URL, and
# several of those candidates are usually the same host, which is enough to
# earn a 429 or a dropped connection from a site we just asked. Treating that
# as a verdict turns a real profile into a silent absence.
_TRANSIENT_CODES = {0, 408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 524}
_RETRY_BACKOFF = 1.5


def _verify(urls, max_workers=30, timeout=10, silent=False, fetch_bytes=200_000,
            expect=None, rejections=None, retries=2):
    """Check which URLs actually serve the page they claim to.

    A 2xx is not evidence that a profile exists. Single-page apps return their
    shell, Cloudflare and bot walls return an interstitial, and platforms with a
    catch-all profile route return *someone else's* profile — all with a success
    status. Three checks are applied, in increasing cost:

    1. HTTP status.
    2. Body inspection: reject bot-challenge interstitials anywhere in the body,
       and reject a ``<title>`` that says the page does not exist.
    3. Body size floor, which catches empty SPA frames.

    ``expect`` adds a fourth: the response must actually carry the term. A bare
    echo of the requested URL is not evidence, so the term must appear more than
    once in the body.

    What this deliberately does *not* require is that the page repeat the handle
    in its title or Open Graph tags. That was tried and it was wrong: a real
    YouTube profile titled "Nat - YouTube" belongs to the handle ``qrxznat`` and
    was rejected, because plenty of platforms show a display name that differs
    from the handle. Identity text is a bonus signal, not a gate.

    Measured behaviour of the current rule:

    =============================  ==========================================
    Page                          verdict
    =============================  ==========================================
    github.com/torvalds           keep  (133 mentions, titled with handle)
    linktr.ee/not.jason.abe       keep
    youtube.com/@qrxznat/about    keep  (18 mentions, titled "Nat")
    strava.com/athletes/<slug>    drop  (registration prompt in the title)
    mastodon.social/@<handle>     drop  (single mention — an echo)
    bsky.app/profile/<handle>     drop  (no mention, 6KB shell)
    tiktok.com/@<handle>          drop  (1.4KB, no content)
    =============================  ==========================================

    Not caught: catch-all profile routes that serve a *valid* profile page for a
    different identity, and platforms whose display name is free text (Strava,
    Facebook, LinkedIn). There the response genuinely is a real profile, so no
    generic signal distinguishes it; that needs per-platform knowledge.


    Pass a dict as ``rejections`` to receive a per-reason tally. Without it the
    filtering is invisible, and a search that drops from six results to one looks
    identical to a search that found less — which is exactly the confusion this
    parameter exists to prevent.

    Transient failures (429, 5xx, dropped connections) are retried twice with a
    linear backoff, because the fan-out above reliably provokes them and a
    throttled real profile is otherwise indistinguishable from a missing one.

    Returns the set of URLs that passed.
    """

    urls = set(urls or ())
    if rejections is not None:
        rejections.clear()
    if not urls:
        return set()
    needle = str(expect).lower() if expect else None
    if not silent:
        print(f"  [*] Verifying {len(urls)} URLs with curl...", end=" ", flush=True)

    def _check(u):
        # Follow redirects and keep the body: the interesting failures are all
        # 200-with-wrong-content, which a header-only HEAD cannot see.
        #
        # Retried on transient statuses only. A real verdict — a registration
        # prompt, a not-found title, a body too small — is the same on the
        # second request, so retrying those would just cost time.
        last = (False, "request failed")
        for attempt in range(retries + 1):
            if attempt:
                time.sleep(_RETRY_BACKOFF * attempt)
            cmd = ["curl", "-sS", "-L", "--max-time", str(timeout), "-A", _UA,
                   "-w", "\n%{http_code}", u]
            if _PROXY:
                cmd = cmd[:1] + _proxy_args() + cmd[1:]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   errors="replace", timeout=timeout + 5)
            except Exception:
                last = (False, "request failed")
                continue
            raw = r.stdout or ""
            if "\n" not in raw[-8:]:
                last = (False, "no status returned")
                continue
            body, _, code_s = raw.rpartition("\n")
            code_s = code_s.strip()
            if not code_s.isdigit():
                last = (False, "bad status")
                continue
            code = int(code_s)
            if code in _TRANSIENT_CODES:
                last = (False, f"http {code}")
                continue
            body = body[:fetch_bytes]
            ok, why = _page_is_real(body, code)
            if ok and needle and body.lower().count(needle) < 2:
                ok, why = False, "search term appears only once (echo)"
            return u, (ok, why)
        return u, last

    valid, reasons = set(), {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for u, (ok, why) in pool.map(_check, urls):
            if ok:
                valid.add(u)
            else:
                reasons[why.split("(")[0].strip()] = \
                    reasons.get(why.split("(")[0].strip(), 0) + 1
    if rejections is not None:
        rejections.update(reasons)
    if not silent:
        dropped = len(urls) - len(valid)
        print(f"({len(valid)} alive, {dropped} rejected)")
        for why, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            print(f"        {n:>4}  {why}")
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
