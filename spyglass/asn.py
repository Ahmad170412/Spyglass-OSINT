#!/usr/bin/env python3
"""BGP / autonomous-system recon, via RIPEStat.

Fills the layer between :mod:`ip` and :mod:`website`. ``ip`` answers "where is
this address", ``website`` answers "what is running there", and neither can say
*who routes it* — which is the question that decides whether an address belongs
to the target, to its host, or to a transit provider three hops away.

Everything here is a keyless GET against RIPEStat (https://stat.ripe.net), so
there is nothing to configure and no rate-limit key to manage. The module takes
either form of input:

* an IP or prefix  -> resolves the covering prefix, its origin AS, the less-
  specific chain above it, and whether that route is RPKI-validated
* an AS number      -> resolves the holder and the size of its announced
  footprint

Why RPKI is the interesting output
----------------------------------
A route whose origin AS has a matching ROA is *protected*: an upstream that
receives a conflicting announcement will reject it. A route with ``status:
invalid`` has a ROA that names a *different* origin, which is what a hijack
looks like, and it is the one finding in this tool that reports a weakness
rather than a fact about the target. ``valid`` and ``invalid`` are both worth
seeing; the absence of RPKI data is not evidence of safety, so an unvalidated
prefix is reported as ``unknown`` rather than folded into either.

Scope limits
------------
* RPKI validation is defined per prefix against an origin AS. An AS-only query
  has no prefix to validate, so the RPKI section is omitted and says why rather
  than reporting a result it cannot compute.
* A prefix can have several origins (anycast, multi-origin AS). Every origin is
  reported, but RPKI is queried for at most ``_RPKI_ORIGIN_CAP`` of them to keep
  the request count bounded.
* ``announced-prefixes`` is a footprint *size*, not a list to read. Large
  operators announce thousands of prefixes (AS15169 returns 1415), so the sample
  is capped and biased towards the address family of the input, with the true
  total always reported.
"""

import concurrent.futures
import ipaddress
import re

from .utils import _curl_json

_RIPE = "https://stat.ripe.net/data"

# Origin ASNs are usually one. Anycast and multi-origin deployments exist, so the
# list is never assumed to have length 1, but each extra origin is another
# round trip.
_RPKI_ORIGIN_CAP = 3

# Prefix lists run to thousands of entries for large operators. The cap keeps
# the result readable; the full count is reported either way. A sample is biased
# towards the address family of the input, with a few of the other family kept so
# a dual-stack operator is visibly dual-stack.
_PREFIX_SAMPLE = 24
_PREFIX_SAMPLE_OTHER_FAMILY = 6

_ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.I)


# ─── target parsing ───────────────────────────────────────

def _parse_target(target):
    """Classify the input as an IP, a prefix, or an AS number.

    Returns ``(kind, value)`` where kind is "ip", "prefix" or "asn", or
    ``(None, None)`` when the input is neither. The two are kept apart because
    ``ipaddress.ip_network`` happily accepts a bare address as a /32, so testing
    the network form first would report every IP as a prefix and the ``ip``
    branch would be unreachable.
    """
    raw = (target or "").strip()
    if not raw:
        return None, None

    asn = _ASN_RE.match(raw)
    if asn:
        return "asn", int(asn.group(1))

    if "/" in raw:
        try:
            return "prefix", ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return None, None
    try:
        return "ip", ipaddress.ip_address(raw)
    except ValueError:
        return None, None


# ─── RIPEStat calls ───────────────────────────────────────
#
# Each call is best-effort and returns a (payload, error) pair rather than
# raising, because one missing data call must not cost the caller the rest of
# the answer. ``_curl_json`` already returns None on any curl failure, so the
# distinction the callers care about is "RIPE said no" versus "RIPE was
# unreachable", and only the second is worth reporting as an error.

def _ripe_data(call, **params):
    """Fetch one RIPEStat data call. Returns (data_dict, error_or_None).

    RIPEStat reports an explanatory reason in a top-level ``messages`` list
    rather than in ``data``, and it does so for the case that matters most here
    — an address with no visible route still returns ``status: ok``. The first
    message is copied onto the returned dict as ``_note`` so the caller can
    report *why* something was empty; without it that answer is unrecoverable.
    """
    query = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{_RIPE}/{call}/data.json" + (f"?{query}" if query else "")
    payload = _curl_json(url, timeout=20)
    if payload is None:
        return None, f"could not reach RIPEStat ({call})"
    note = _ripe_message(payload)
    if payload.get("status") == "error":
        return None, note or f"RIPEStat rejected the query ({call})"
    data = payload.get("data")
    data = dict(data) if isinstance(data, dict) else {}
    if note:
        data["_note"] = note
    return data, None


def _ripe_message(payload):
    """First human-readable message RIPEStat attached to a response.

    RIPE reports a non-announced address by returning ``status: ok`` with an
    explanatory message rather than an error, so the message is the only place
    the reason appears.
    """
    for messages in (payload.get("messages") or []):
        if isinstance(messages, (list, tuple)) and len(messages) >= 2:
            return str(messages[1])
        if isinstance(messages, str):
            return messages
    return ""


def _prefix_overview(resource):
    data, err = _ripe_data("prefix-overview", resource=resource)
    if err:
        return None, err
    asns = [{"asn": a.get("asn"), "holder": a.get("holder") or ""}
            for a in (data.get("asns") or []) if isinstance(a, dict) and a.get("asn")]
    return {
        "prefix": data.get("resource") or "",
        "announced": bool(data.get("announced")),
        "origin_asns": asns,
        "covering_prefixes": [p for p in (data.get("related_prefixes") or []) if p],
        "registry": _registry(data.get("block")),
        "note": data.get("_note") or "",
    }, None


def _as_overview(number):
    data, err = _ripe_data("as-overview", resource=f"AS{number}")
    if err:
        return None, err
    holder = (data.get("holder") or "").strip()
    if not holder:
        return None, f"AS{number} has no holder on record"
    return {
        "asn": number,
        "holder": holder,
        "announced": bool(data.get("announced")),
        "registry": _registry(data.get("block")),
        "note": data.get("_note") or "",
    }, None


def _announced_prefixes(number, family=4):
    """Footprint size plus a readable sample, biased to the input's family.

    A large operator announces thousands of prefixes (AS15169 returns 1415), so
    the list is sampled rather than returned whole. IPv4 leads because that is
    what a target address is nearly always given as; a few of the other family
    are kept so a dual-stack operator is visibly dual-stack rather than looking
    v4-only.
    """
    data, err = _ripe_data("announced-prefixes", resource=f"AS{number}")
    if err:
        return None, err

    # A prefix that does not parse is dropped from the count rather than kept in
    # the total, so that ``total`` always equals ipv4_total + ipv6_total and the
    # "showing N of M" note adds up.
    preferred, other = [], []
    for entry in data.get("prefixes") or []:
        if not isinstance(entry, dict) or not entry.get("prefix"):
            continue
        try:
            is_v4 = ipaddress.ip_network(entry["prefix"], strict=False).version == 4
        except ValueError:
            continue
        (preferred if (is_v4 == (family == 4)) else other).append(entry["prefix"])

    sample = (preferred[:_PREFIX_SAMPLE]
              + other[:_PREFIX_SAMPLE_OTHER_FAMILY])
    note = None
    if len(preferred) + len(other) > len(sample):
        note = (f"showing {len(sample)} of {len(preferred) + len(other)} announced "
                f"prefixes ({len(preferred)} IPv4, {len(other)} IPv6)")
    return {
        "total": len(preferred) + len(other),
        "ipv4_total": len(preferred),
        "ipv6_total": len(other),
        "sample": sample,
        "note": note,
    }, None


def _rpki(prefix, asn):
    """RPKI validity of one (prefix, origin AS) pair.

    A prefix can be validated against exactly one origin at a time, so this is
    called per origin by the caller.
    """
    data, err = _ripe_data("rpki-validation", resource=f"AS{asn}", prefix=prefix)
    if err:
        return None, err
    status = (data.get("status") or "unknown").lower()
    return {
        "prefix": prefix,
        "origin_asn": asn,
        "status": status,
        "validator": data.get("validator") or "",
        "roas": [
            {"origin": r.get("origin"), "prefix": r.get("prefix"),
             "max_length": r.get("max_length"), "validity": r.get("validity")}
            for r in (data.get("validating_roas") or []) if isinstance(r, dict)
        ],
    }, None


def _registry(block):
    if not isinstance(block, dict):
        return None
    out = {k: block[k] for k in ("resource", "desc", "name") if block.get(k)}
    return out or None


# ─── public API ──────────────────────────────────────────

def asn(target):
    """Look up BGP routing data for an IP, prefix, or AS number.

    ``target`` may be ``8.8.8.8``, ``8.8.8.0/24``, ``AS15169`` or ``15169``.
    Returns a result dict, or one carrying a top-level ``error``.
    """
    kind, value = _parse_target(target)
    if kind is None:
        return {"error": f"Not an IP, prefix, or AS number: {target or '(empty)'}",
                "hint": "try 8.8.8.8, 8.8.8.0/24, or AS15169"}

    result = {"query": str(target).strip(),
              "query_type": "ip" if kind == "ip" else kind}

    if kind == "asn":
        return _collect_asn(value, result)
    return _collect_prefix(kind, value, result)


def _collect_prefix(kind, addr, result):
    """IP or prefix input: resolve the covering prefix, then validate it."""
    resource = str(addr)
    family = addr.version
    overview, err = _prefix_overview(resource)
    if err:
        result["error"] = err
        return result

    result["prefix"] = overview["prefix"]
    result["announced"] = overview["announced"]
    if overview["covering_prefixes"]:
        result["covering_prefixes"] = overview["covering_prefixes"]
    if overview["registry"]:
        result["registry"] = overview["registry"]
    if not overview["announced"]:
        result["unannounced_reason"] = (
            overview["note"]
            or "no route visible for this address (private, reserved, or unannounced)"
        )

    origins = overview["origin_asns"]
    if origins:
        result["origin_asns"] = origins

    # Stage two needs the prefix and origin, so it cannot run alongside stage
    # one. RPKI per origin and the footprint of the primary origin are
    # independent of each other, so they go in parallel.
    primary = origins[0]["asn"] if origins else None
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs = {}
        if overview["prefix"] and primary:
            for origin in origins[:_RPKI_ORIGIN_CAP]:
                jobs[pool.submit(_rpki, overview["prefix"], origin["asn"])] = "rpki"
        if primary:
            jobs[pool.submit(_announced_prefixes, primary, family)] = "prefixes"
        for fut in concurrent.futures.as_completed(jobs):
            kind_out = jobs[fut]
            data, err = fut.result()
            if kind_out == "rpki":
                if data:
                    result.setdefault("rpki", []).append(data)
                else:
                    result.setdefault("rpki_errors", []).append(err)
            elif data:
                result["announced_prefixes"] = data

    if not result.get("rpki") and not result.get("rpki_errors"):
        result["rpki"] = []
    if result.get("rpki"):
        # as_completed order is not stable across runs, and a result that
        # reorders itself between two invocations of the same target reads as a
        # change that never happened.
        result["rpki"].sort(key=lambda r: r.get("origin_asn") or 0)
        result["rpki_summary"] = _rpki_summary(result["rpki"])
    return result


def _collect_asn(number, result):
    """AS input: holder and footprint, in parallel, since neither needs the other.

    RPKI is omitted with a stated reason. Validation is defined per prefix
    against an origin, so an AS on its own has nothing to validate, and
    reporting a reassuring "valid" from an AS-level lookup would be the one
    answer in this tool that looks like a safety result and is not one.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        as_fut = pool.submit(_as_overview, number)
        pref_fut = pool.submit(_announced_prefixes, number)
        overview, err = as_fut.result()
        footprint, pref_err = pref_fut.result()

    if err:
        result["error"] = err
        return result

    result["asn"] = overview["asn"]
    result["holder"] = overview["holder"]
    result["announced"] = overview["announced"]
    if overview["registry"]:
        result["registry"] = overview["registry"]
    if footprint:
        result["announced_prefixes"] = footprint
    elif pref_err:
        result["announced_prefixes"] = {"total": 0, "sample": [],
                                        "error": pref_err}
    result["rpki"] = []
    result["rpki_note"] = (
        "RPKI validates a prefix against an origin AS, not an AS alone — "
        "pass a prefix or an IP to get a validation result"
    )
    return result


def _rpki_summary(entries):
    """One line per distinct verdict, worst first.

    Ordering matters: a route with a conflicting ROA is the finding, and it
    should not be buried under a list of prefixes that are fine.
    """
    rank = {"invalid": 0, "unknown": 1, "valid": 2}
    seen = {}
    for entry in entries:
        status = entry.get("status", "unknown")
        seen.setdefault(status, []).append(f"AS{entry.get('origin_asn')}")
    parts = []
    for status in sorted(seen, key=lambda s: rank.get(s, 3)):
        origins = ", ".join(sorted(seen[status]))
        parts.append(f"{status} (origin {origins})")
    return "; ".join(parts)
