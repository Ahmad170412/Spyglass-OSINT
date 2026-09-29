#!/usr/bin/env python3
import os
import shutil
import sys
import tempfile
import re
import json
import subprocess
import concurrent.futures

from .utils import _run, _domain, _verify, _pick, _check_tool, _tool_failed, \
    blackbird_ready, _US, _SH, _MG, _BB, _BB_DIR, _proxy_env, _proxy_args
from . import utils
from .breach import check as _breach_check

# How many of maigret's 6,206 sites to check. Its own database is far larger
# than anything worth waiting for, so this is a time/coverage trade rather
# than a limit of the tool. Measured on a real handle, unique domains found:
#
#   --top-sites   50 ->    4.8s,  6 domains     (previous default)
#   --top-sites  200 ->   12.2s,  7 domains
#   --top-sites  500 ->   15.2s, 12 domains
#   --top-sites 1000 ->   27.0s, 16 domains     (chosen: +22s for +10 domains)
#   --top-sites 3000 ->   58.0s, 24 domains
#
# 1000 costs about 10% of a full four-engine search and roughly triples the
# domains maigret contributes. Past that the returns per second fall away, and
# sherlock's 198s dominates the wall clock regardless.
_MG_SITES = 1000


# ─── tool runners ─────────────────────────────────────────

def _us_username(username):
    if not _check_tool("user-scanner", _US):
        return {}
    try:
        r = subprocess.run(
            [_US, "-u", username, "-v", "--only-found"],
            capture_output=True, text=True, timeout=120, input="n\n",
            env=_proxy_env(),
        )
    except Exception:
        return {}
    _tool_failed("user-scanner", r)
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
    try:
        r = subprocess.run(
            [_SH, username, "--print-found"],
            capture_output=True, text=True, timeout=300,
            env=_proxy_env(),
        )
    except Exception:
        return {}
    _tool_failed("sherlock", r)
    out = {}
    for line in r.stdout.split("\n"):
        m = re.search(r"(https?://\S+)", line)
        if m:
            u = m.group(1).rstrip(".,")
            out[_domain(u)] = u
    return out


def _maigret_stdout_urls(r):
    """Profile URLs scraped from maigret's stdout, used only as a fallback.

    maigret's JSON report is the better source because it carries the
    extracted fields as well as the URL, but it is a report file and a
    report file can be missing. Without this, a maigret build that writes no
    report would look like a handle with no accounts rather than a tool that
    half-worked.
    """
    out = {}
    for line in (r.stdout or "").split("\n"):
        if not line.startswith("[+] "):
            continue
        if line.startswith(("[+] MAIGRET", "[+] Using", "[+] Donate")):
            continue
        m = re.search(r"(https?://\S+)", line)
        if not m:
            continue
        url = m.group(1).rstrip(".,")
        domain = _domain(url)
        if domain and domain not in out:
            out[domain] = url
    return out


def _maigret(username, top_sites=_MG_SITES, timeout=420):
    """maigret's profile URLs and the data it extracted, in one pass.

    Returns ``(hits, details)``. One run, not two: the ndjson report carries
    both the URL and the structured fields behind it, so parsing the report
    yields hits and details that are guaranteed to describe the same search.
    Running maigret once for URLs and again for the report doubled the wall
    clock and risked the two passes disagreeing.

    maigret writes reports into ``./reports`` unless told otherwise, so output
    is directed at a throwaway directory and removed afterwards. Left alone it
    scatters CSV and JSON dossiers of every search into the working directory,
    unencrypted.
    """
    if not _check_tool("maigret", _MG):
        return {}, {}
    tmp = tempfile.mkdtemp(prefix="spyglass-maigret-")
    try:
        try:
            r = subprocess.run(
                [_MG, username, "--no-progressbar", "-C",
                 "--top-sites", str(top_sites), "--folderoutput", tmp,
                 "-J", "ndjson"],
                capture_output=True, text=True, timeout=timeout,
                env=_proxy_env(),
            )
        except Exception:
            return {}, {}
        _tool_failed("maigret", r)

        payload = None
        for name in sorted(os.listdir(tmp)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(tmp, name), encoding="utf-8") as fh:
                    # ndjson: one JSON record per line, one line per hit.
                    payload = [json.loads(l) for l in fh if l.strip()]
                break
            except Exception:
                continue
        if not isinstance(payload, list):
            return _maigret_stdout_urls(r), {}

        hits, details = {}, {}
        for rec in payload:
            if not isinstance(rec, dict):
                continue
            status = rec.get("status") or {}
            if not isinstance(status, dict):
                continue
            # maigret marks unclaimed handles "Unclaimed" and errors separately;
            # only "Claimed" is a real account.
            if str(status.get("status", "")).lower() != "claimed":
                continue
            url = status.get("url") or rec.get("url_user") or ""
            domain = _domain(url) if url else (rec.get("sitename") or "")
            if domain and domain not in hits:
                # A claimed record with a URL is a hit even when it carries no
                # extractable fields, so the two maps are built independently.
                hits[domain] = url.rstrip(".,")
            ids = status.get("ids")
            if not isinstance(ids, dict) or not domain:
                continue
            # The extractor name is an implementation detail, not intelligence.
            entry = {k: v for k, v in ids.items()
                     if not k.startswith("_") and v not in (None, "")}
            if entry:
                details[domain] = entry
        return hits, details
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _blackbird_username(username):
    if not _check_tool("blackbird", _BB):
        return {}
    bb_cmd = [sys.executable, _BB, "-u", username, "--no-update", "--no-nsfw"]
    if utils._PROXY:
        bb_cmd += _proxy_args()
    try:
        r = subprocess.run(
            bb_cmd,
            capture_output=True, text=True, timeout=300, cwd=_BB_DIR,
            env=_proxy_env(),
        )
    except Exception:
        return {}
    _tool_failed("blackbird", r)
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
    if _BB:
        ok, why = blackbird_ready()
        if not ok:
            from . import display as _ui
            _ui.warn(why)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        u_fut  = pool.submit(_us_username, target)
        s_fut  = pool.submit(_sherlock, target)
        m_fut  = pool.submit(_maigret, target)
        bb_fut = pool.submit(_blackbird_username, target)
        br_fut = pool.submit(_breach_check, target, "login")
        u  = u_fut.result()
        s  = s_fut.result()
        m, mgd = m_fut.result()
        bb = bb_fut.result()
        br = br_fut.result()

    all_raw = {**u, **s, **m, **bb}
    rejected = {}
    if all_raw:
        # Verification requires the response to actually mention the handle.
        # Without that, a client-rendered app whose shell carries no profile data
        # is indistinguishable from a real hit, since both answer 200.
        alive = _verify(set(all_raw.values()), silent=True, expect=target,
                        rejections=rejected)
        u  = {d: url for d, url in u.items()  if url in alive}
        s  = {d: url for d, url in s.items()  if url in alive}
        m  = {d: url for d, url in m.items()  if url in alive}
        bb = {d: url for d, url in bb.items() if url in alive}
    else:
        alive = set()

    uk, sk, mk, bk = set(u), set(s), set(m), set(bb)
    get = _pick(u, s, m, bb)

    sh_only = sk - uk - mk - bk
    mg_only = mk - uk - sk - bk
    bb_only = bk - uk - sk - mk
    both_l = sorted((uk & sk) | (uk & mk) | (uk & bk)
                   | (sk & mk) | (sk & bk) | (mk & bk))

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
        # Candidates that were fetched and rejected, by reason. Reported so a
        # short result set is auditable rather than looking like a thin search.
        "rejected":         rejected,
        "candidates":       len(all_raw),
        "verdict":          _verdict(uk, sk, mk, bk),
        "details":          {d: mgd[d] for d in mgd
                             if d in set(both_l) | sh_only | mg_only | bb_only},
    }


def _verdict(uk, sk, mk, bk):
    """State how strong the evidence actually is, in one line.

    A single-tool hit is not a finding — it is a lead. Some platforms treat the
    display name as free text (Strava, Facebook, LinkedIn), so a match there
    proves the name is taken, not that it belongs to the same person. Saying so
    is more useful than printing one confident-looking URL.
    """
    corroborated = ((uk & sk) | (uk & mk) | (uk & bk)
                    | (sk & mk) | (sk & bk) | (mk & bk))
    singles = ((uk - sk - mk - bk) | (sk - uk - mk - bk)
               | (mk - uk - sk - bk) | (bk - uk - sk - mk))
    total = len(corroborated) + len(singles)
    if not total:
        return ("No verified profiles found for this handle. That is a real "
                "result, not an error: the handle may be unused, or every "
                "profile it has may be client-rendered and invisible to an "
                "HTTP fetch.")
    if not corroborated:
        return (f"{total} platform(s), each found by one tool only — "
                "unconfirmed. A single-tool hit is a lead, not a finding: "
                "platforms with free-text display names match on name alone.")
    return (f"{total} platform(s); {len(corroborated)} corroborated by two or "
            f"more tools, {len(singles)} single-tool lead(s).")


# Human-readable names for the buckets above. These keys are the module's
# internal vocabulary and must never reach an operator raw: ``us_only`` reads as
# "United States only" and ``all_3_no_bb`` means nothing to anyone who has not
# memorised the tool list. The agreement tiers are also the point of the module,
# so they should say who agreed rather than how many.
SECTION_LABELS = {
    "all_4":              "All 4 tools agree",
    "all_3_no_bb":        "3 of 4 — no Blackbird",
    "all_3_no_mg":        "3 of 4 — no Maigret",
    "all_3_no_sh":        "3 of 4 — no Sherlock",
    "all_3_no_us":        "3 of 4 — no user-scanner",
    "us+sherlock":        "user-scanner + Sherlock",
    "us+maigret":         "user-scanner + Maigret",
    "us+blackbird":       "user-scanner + Blackbird",
    "sherlock+maigret":   "Sherlock + Maigret",
    "sherlock+blackbird": "Sherlock + Blackbird",
    "maigret+blackbird":  "Maigret + Blackbird",
    "us_only":            "user-scanner only",
    "sherlock_only":      "Sherlock only",
    "maigret_only":       "Maigret only",
    "blackbird_only":     "Blackbird only",
    "breach":             "Breach data",
}
