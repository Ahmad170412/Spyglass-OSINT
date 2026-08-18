#!/usr/bin/env python3
import sys
import re
import subprocess
import concurrent.futures

from .utils import _run, _domain, _verify, _pick, _check_tool, _HOLEHE, _US, _BB, _BB_DIR, _proxy_env, _proxy_args
from . import utils
from .breach import check as _breach_check


# ─── tool runners ─────────────────────────────────────────

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
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        h_fut  = pool.submit(_holehe, target)
        u_fut  = pool.submit(_us_email, target)
        bb_fut = pool.submit(_blackbird_email, target)
        br_fut = pool.submit(_breach_check, target, "email")
        h  = h_fut.result()
        u  = u_fut.result()
        bb = bb_fut.result()
        br = br_fut.result()

    if u:
        alive = _verify(set(u.values()), silent=True)
        u = {d: url for d, url in u.items() if url in alive}
    if bb:
        alive = _verify(set(bb.values()), silent=True)
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
    }
