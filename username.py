#!/usr/bin/env python3
import sys
import re
import subprocess
import concurrent.futures

from .utils import _run, _domain, _verify, _pick, _check_tool, _US, _SH, _MG, _BB, _BB_DIR, _proxy_env, _proxy_args
from . import utils
from .breach import check as _breach_check


# ─── tool runners ─────────────────────────────────────────

def _us_username(username):
    if not _check_tool("user-scanner", _US):
        return {}
    r = subprocess.run(
        [_US, "-u", username, "-v", "--only-found"],
        capture_output=True, text=True, timeout=120, input="n\n",
        env=_proxy_env(),
    )
    out = {}
    for line in r.stdout.split("\n"):
        m = re.search(r"\[(https?://[^\]]+)\]", line)
        if m:
            u = m.group(1)
            out[_domain(u)] = u
    return out


def _sherlock(username):
    if not _check_tool("sherlock", _SH):
        return {}
    r = subprocess.run(
        [_SH, username, "--print-found"],
        capture_output=True, text=True, timeout=120,
        env=_proxy_env(),
    )
    out = {}
    for line in r.stdout.split("\n"):
        m = re.search(r"(https?://\S+)", line)
        if m:
            u = m.group(1).rstrip(".,")
            out[_domain(u)] = u
    return out


def _maigret(username):
    if not _check_tool("maigret", _MG):
        return {}
    r = subprocess.run(
        [_MG, username, "--no-progressbar", "-C", "--top-sites", "50"],
        capture_output=True, text=True, timeout=300,
        env=_proxy_env(),
    )
    out = {}
    for line in r.stdout.split("\n"):
        if not line.startswith("[+] "):
            continue
        if line.startswith(("[+] MAIGRET", "[+] Using", "[+] Donate")):
            continue
        m = re.search(r"(https?://\S+)", line)
        if m:
            u = m.group(1).rstrip(".,")
            out[_domain(u)] = u
    return out


def _blackbird_username(username):
    if not _check_tool("blackbird", _BB):
        return {}
    bb_cmd = [sys.executable, _BB, "-u", username, "--no-update", "--no-nsfw"]
    if utils._PROXY:
        bb_cmd += _proxy_args()
    r = subprocess.run(
        bb_cmd,
        capture_output=True, text=True, timeout=300, cwd=_BB_DIR,
        env=_proxy_env(),
    )
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

def username(target):
    """Run user-scanner + sherlock + maigret + blackbird on a username.

    Returns dict of lists of {domain, url} for each overlap category.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        u_fut  = pool.submit(_us_username, target)
        s_fut  = pool.submit(_sherlock, target)
        m_fut  = pool.submit(_maigret, target)
        bb_fut = pool.submit(_blackbird_username, target)
        br_fut = pool.submit(_breach_check, target, "login")
        u  = u_fut.result()
        s  = s_fut.result()
        m  = m_fut.result()
        bb = bb_fut.result()
        br = br_fut.result()

    all_raw = {**u, **s, **m, **bb}
    if all_raw:
        alive = _verify(set(all_raw.values()), silent=True)
        u  = {d: url for d, url in u.items()  if url in alive}
        s  = {d: url for d, url in s.items()  if url in alive}
        m  = {d: url for d, url in m.items()  if url in alive}
        bb = {d: url for d, url in bb.items() if url in alive}

    uk, sk, mk, bk = set(u), set(s), set(m), set(bb)
    get = _pick(u, s, m, bb)

    def _fmt(ds):
        return [{"domain": d, "url": get(d)} for d in sorted(ds)]

    return {
        "all_4":            _fmt(uk & sk & mk & bk),
        "all_3_no_bb":      _fmt((uk & sk & mk) - bk),
        "all_3_no_mg":      _fmt((uk & sk & bk) - mk),
        "all_3_no_sh":      _fmt((uk & mk & bk) - sk),
        "all_3_no_us":      _fmt((sk & mk & bk) - uk),
        "us+sherlock":      _fmt((uk & sk) - mk - bk),
        "us+maigret":       _fmt((uk & mk) - sk - bk),
        "us+blackbird":     _fmt((uk & bk) - sk - mk),
        "sherlock+maigret": _fmt((sk & mk) - uk - bk),
        "sherlock+blackbird":_fmt((sk & bk) - uk - mk),
        "maigret+blackbird": _fmt((mk & bk) - uk - sk),
        "us_only":          _fmt(uk - sk - mk - bk),
        "sherlock_only":    _fmt(sk - uk - mk - bk),
        "maigret_only":     _fmt(mk - uk - sk - bk),
        "blackbird_only":   _fmt(bk - uk - sk - mk),
        "breach":           br,
    }
