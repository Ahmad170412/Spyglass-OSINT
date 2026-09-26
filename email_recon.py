#!/usr/bin/env python3
import sys
import re
import json
import hashlib
import subprocess
import concurrent.futures

from .utils import _run, _domain, _verify, _pick, _check_tool, _CURL, _proxy_args, \
    _HOLEHE, _US, _BB, _BB_DIR, _proxy_env, _proxy_args
from . import utils
from .breach import check as _breach_check


# ─── tool runners ─────────────────────────────────────────

_GRAVATAR_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


def _gravatar_hash(address):
    """The Gravatar hash for an address.

    Gravatar's spec is md5 of the address lowercased and trimmed, so the case an
    operator types cannot change the result. Leading/trailing whitespace is the
    usual reason a real profile fails to resolve.

    The shape is validated on the *trimmed* value: ``"a@"`` has an ``@`` but no
    domain, and hashing it would report a confident "no Gravatar" for an address
    that was never an address.
    """
    if not address:
        return ""
    addr = str(address).strip().lower()
    if addr.count("@") != 1:
        return ""
    local, _, domain = addr.partition("@")
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return ""
    return hashlib.md5(addr.encode("utf-8")).hexdigest()


def _gravatar_json(url, timeout=20):
    """GET and parse JSON, honouring the module's proxy. None on any failure."""
    if not _CURL:
        return None
    cmd = [_CURL, "-sS", "-L", "-A", _GRAVATAR_UA, "--max-time", str(timeout),
           "-H", "Accept: application/json", url]
    cmd = cmd[:1] + _proxy_args() + cmd[1:]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except Exception:
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def _gravatar(address):
    """Look up the public Gravatar profile for an email address.

    Worth doing because it is the one keyless source that answers "does this
    address have a public identity, and what else is that identity linked to".
    Gravatar profiles carry an ``accounts`` array of other social profiles, which
    turns an opaque address into a set of handles that can be fed back into the
    username module — the join key the registration checkers do not give you.

    Two steps, cheapest first:

    1. ``/avatar/<hash>?d=404`` — Gravatar's documented behaviour for ``d=404`` is
       to answer 404 when the address has no avatar, so this is an existence test
       that needs no parsing. The negative side is verified directly; the positive
       side is that documented contract, so a missing profile is authoritative and
       a present one is still worth confirming against the profile JSON.
    2. The profile JSON, only when step 1 says the avatar exists.
    """
    digest = _gravatar_hash(address)
    if not digest:
        return {"status": "error", "reason": "not a valid email address",
                "found": False}
    if not _CURL:
        return {"status": "unavailable", "reason": "curl not found", "found": False}

    # Step 1 — existence.
    code = utils._curl_status(f"https://gravatar.com/avatar/{digest}?d=404")
    if code is None:
        return {"status": "error", "reason": "gravatar unreachable", "found": False}
    if code == 404:
        return {"status": "ok", "found": False, "hash": digest,
                "profile_url": f"https://gravatar.com/{digest}"}

    # Step 2 — profile detail.
    data = _gravatar_json(f"https://en.gravatar.com/{digest}.json") or {}
    entries = data.get("entry") or []
    if not entries:
        return {"status": "ok", "found": True, "hash": digest,
                "profile_url": f"https://gravatar.com/{digest}",
                "note": "avatar exists but no public profile data is exposed"}

    e = entries[0]
    accounts = []
    for a in e.get("accounts") or []:
        url = a.get("url") or ""
        domain = a.get("domain") or ""
        handle = a.get("username") or a.get("shortname") or ""
        if not handle and not url:
            continue
        # Gravatar gives the service as a full domain, so the name is the leading
        # label: "twitter.com" -> twitter. Taking the *last* label yields "com",
        # which is the same for every service and therefore useless.
        if not domain and url:
            m = re.match(r"https?://([^/:]+)", url, re.I)
            domain = m.group(1) if m else ""
        service = domain.split(".")[0] if domain else (handle or "")
        accounts.append({"service": service, "username": handle, "url": url})

    return {
        "status": "ok",
        "found": True,
        "hash": digest,
        "profile_url": e.get("profileUrl") or f"https://gravatar.com/{digest}",
        "display_name": e.get("displayName") or e.get("preferredUsername") or "",
        "username": e.get("preferredUsername") or "",
        "location": (e.get("currentLocation") or ""),
        "about": (e.get("aboutMe") or "")[:200],
        "accounts": accounts,
        "photos": len(e.get("photos") or []),
    }


def _holehe(email):
    if not _check_tool("holehe", _HOLEHE):
        return set()
    try:
        r = subprocess.run(
            [_HOLEHE, email, "--only-used"],
            capture_output=True, text=True, timeout=120,
            env=_proxy_env(),
        )
    except Exception:
        return set()
    out = set()
    for line in r.stdout.split("\n"):
        line = line.strip()
        if line.startswith("[+] "):
            d = line[4:].strip()
            if d and "." in d and " " not in d:
                out.add(d.lower())
    return out


def _us_email(email):
    if not _check_tool("user-scanner", _US):
        return {}
    try:
        r = subprocess.run(
            [_US, "-e", email, "-v", "--only-found"],
            capture_output=True, text=True, timeout=120, input="n\n",
            env=_proxy_env(),
        )
    except Exception:
        return {}
    out = {}
    for line in r.stdout.split("\n"):
        m = re.search(r"\[(https?://[^\]]+)\]", line)
        if m:
            u = m.group(1)
            out[_domain(u)] = u
    return out


def _blackbird_email(email):
    if not _check_tool("blackbird", _BB):
        return {}
    bb_cmd = [sys.executable, _BB, "-e", email, "--no-update", "--no-nsfw"]
    if utils._PROXY:
        bb_cmd += _proxy_args()
    try:
        r = subprocess.run(
            bb_cmd,
            capture_output=True, text=True, timeout=120, cwd=_BB_DIR,
            env=_proxy_env(),
        )
    except Exception:
        return {}
    out = {}
    for i, line in enumerate(r.stdout.split("\n")):
        m = re.search(r"✔️\s+\[([^\]]+)\]\s*(https?://\S+)?", line)
        if m:
            url = m.group(2)
            if not url and i + 1 < len(r.stdout.split("\n")):
                nxt = re.search(r"(https?://\S+)", r.stdout.split("\n")[i + 1])
                if nxt:
                    url = nxt.group(1)
            if url:
                out[_domain(url)] = url
    return out


# ─── public API ───────────────────────────────────────────

def email(target):
    """Run holehe + user-scanner + blackbird on an email in parallel.

    Returns:
        both           – sites confirmed by ≥2 tools
        holehe_only    – only holehe flagged it
        user_scanner_only
        blackbird_only
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        h_fut  = pool.submit(_holehe, target)
        u_fut  = pool.submit(_us_email, target)
        bb_fut = pool.submit(_blackbird_email, target)
        br_fut = pool.submit(_breach_check, target, "email")
        gv_fut = pool.submit(_gravatar, target)
        h  = h_fut.result()
        u  = u_fut.result()
        bb = bb_fut.result()
        br = br_fut.result()
        gv = gv_fut.result()

    rejected = {}
    if u:
        alive = _verify(set(u.values()), silent=True, rejections=rejected)
        u = {d: url for d, url in u.items() if url in alive}
    if bb:
        alive = _verify(set(bb.values()), silent=True, rejections=rejected)
        bb = {d: url for d, url in bb.items() if url in alive}

    uk  = set(u)
    bsk = set(bb)
    get = _pick(u, bb)

    both = (h & uk) | (h & bsk) | (uk & bsk)
    return {
        "both":             [{"domain": d, "url": get(d)} for d in sorted(both)],
        "holehe_only":      [{"domain": d} for d in sorted(h - uk - bsk)],
        "user_scanner_only":[{"domain": d, "url": u[d]} for d in sorted(uk - h - bsk)],
        "blackbird_only":   [{"domain": d, "url": bb[d]} for d in sorted(bsk - h - uk)],
        "breach":           br,
        "gravatar":         gv,
        # Fetched-and-rejected candidates by reason, so a short result set is
        # auditable rather than looking like a thin search.
        "rejected":         rejected,
    }
