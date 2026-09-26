"""Known-vulnerability matching for Spyglass.

Closes the gap between "this is WordPress 6.0 with a weak TLS config" and "that
is CVE-2022-43497". The website module already fingerprints roughly forty
products but only records that they exist; this module records their *versions*
and asks the NVD which published CVEs actually cover that version.

Design principles
-----------------
* Queries go through the ``virtualMatchString`` parameter rather than ``cpeName``:
  the plain CPE lookup requires a fully specified CPE and cannot express a version
  *range*, which is how most nginx and OpenSSL advisories are written.
* NVD's matching is then verified rather than trusted. ``virtualMatchString`` does
  not always apply a recorded versionStart/versionEnd — a query for nginx 1.31.3 came
  back with CVE-2009-3555, whose range stops at 0.8.22 — so every hit is re-checked
  against the bounds NVD itself recorded and dropped if it does not apply. There is
  deliberately no wildcard-version fallback: matching every advisory ever published
  for a product is the precise failure this avoids. A false CVE claim is far more
  damaging than a missed one, because nothing in the output distinguishes them.
* Vendor names are versioned facts, not guesses. NVD re-homed nginx from
  ``igor_sysoev`` to ``f5`` and OpenSSL to ``openssl``, and a CPE with the wrong
  vendor silently returns nothing. Each product therefore carries every vendor
  spelling that has been observed, and the first one that returns a result wins.
* A wrong vendor produces a false *negative*, never a false positive — NVD
  returns an empty set rather than an unrelated advisory — so an unverified
  entry in the table costs recall, not accuracy. That asymmetry is why the
  table can be extended without re-testing every row.
* Rate limits are the real constraint, not bandwidth. Unauthenticated NVD
  allows 5 requests per rolling 30 seconds, so requests are spaced rather than
  fired in parallel; supplying ``NVD_API_KEY`` raises that to 50 and the
  spacing drops accordingly. The component count is capped for the same reason.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone

from . import utils
from .utils import _CURL, _proxy_args


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Unauthenticated NVD allows 5 requests per 30s; the documented ceiling with a
# key is 50. Spacing requests out is the whole rate-limiting strategy, so the
# interval is derived from the key rather than tuned per call site.
_MIN_INTERVAL_NO_KEY = 6.5
_MIN_INTERVAL_KEY = 0.7

# Product -> CPE vendor spellings, newest first. A CPE is
# ``cpe:2.3:a:<vendor>:<product>:<version>:...``; the version is filled in at
# query time. Products with no entry here are detected and reported but never
# queried, because guessing a vendor would only ever return nothing.
_CPE_VENDORS = {
    "nginx":        ("f5", "igor_sysoev"),
    "apache":       ("apache",),
    "php":          ("php",),
    "openssh":      ("openbsd",),
    "tomcat":       ("apache",),
    "jenkins":      ("cloudbees",),
    "wordpress":    ("wordpress",),
    "drupal":       ("drupal",),
    "joomla":       ("joomla",),
    "vbulletin":    ("vbulletin",),
    "phpmyadmin":   ("phpmyadmin",),
    "iis":          ("microsoft",),
    "django":       ("djangoproject",),
    "jquery":       ("jquery",),
    "bootstrap":    ("getbootstrap",),
    "openssl":      ("openssl",),
    "mysql":        ("oracle",),
    "maria":        ("mariadb",),
}

# CPE product name, which is not always the marketing name.
_CPE_PRODUCT = {
    "apache": "http_server",
    "tomcat": "tomcat",
    "iis": "iis",
    "openssl": "openssl",
    "mysql": "mysql",
    "maria": "mariadb",
}

# (product, kind, pattern). Detection is deliberately narrow: a version is
# claimed only when the marker is unambiguous, because a wrong version produces
# a CVE claim that looks authoritative and is not.
#
# ``kind`` is "header" (matched against the header value) or "body" (matched
# against the page source).
_RULES = (
    # Server banners carry the product and version together more often than
    # anything else, so they are matched first.
    ("nginx",      "header", r"\bnginx[/ ](\d[\d.]*\d)"),
    ("apache",     "header", r"\bapache[/ ](\d[\d.]*\d)"),
    ("tomcat",     "header", r"\b(?:tomcat|apache-coyote)[/ ](\d[\d.]*\d)"),
    ("iis",        "header", r"\bmicrosoft-iis[/ ](\d[\d.]*\d)"),
    ("openssh",    "header", r"\bopenssh[/ ](\d[\d.]*\d)"),
    ("php",        "header", r"\bphp[/ ](\d[\d.]*\d)"),
    # Jenkins and Drupal announce their version in dedicated headers.
    ("jenkins",    "header", r"^([\d.]+)$"),
    ("drupal",     "header", r"^([\d.]+)$"),
    # Generators are the most reliable version source for CMS platforms.
    ("wordpress",  "body", r"generator\"[^>]*content=[\"'][^\"']*wordpress\s*([\d.]+\d)"),
    ("joomla",     "body", r"generator\"[^>]*content=[\"'][^\"']*joomla!?\s*([\d.]+\d)"),
    ("drupal",     "body", r"generator\"[^>]*content=[\"'][^\"']*drupal\s*([\d.]+\d)"),
    ("php",        "body", r"\"generator\"[^>]*content=[\"']?php\s*([\d.]+\d)"),
    # Front-end libraries version themselves in the asset filename. These are
    # usually CDN-served and patched without a site change, so they rank below
    # the server-side components.
    ("jquery",     "body", r"jquery[-.]?(\d+\.\d+(?:\.\d+)?)"),
    ("bootstrap",  "body", r"bootstrap[-.](\d+\.\d+(?:\.\d+)?)"),
    # phpMyAdmin and vBulletin leak their version in asset paths.
    ("phpmyadmin", "body", r"phpmyadmin[/ ]?v?(\d+\.\d+(?:\.\d+)?)"),
    ("vbulletin",  "body", r"vbulletin[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)"),
)

# Which headers each versioned product is read from.
_HEADER_FOR = {
    "nginx":    ("server",),
    "apache":   ("server",),
    "tomcat":   ("server", "x-powered-by"),
    "iis":      ("server",),
    "openssh":  ("server",),
    "php":      ("x-powered-by",),
    "jenkins":  ("x-jenkins",),
    "drupal":   ("x-drupal-cache", "x-generator"),
}


# ─── detection ───────────────────────────────────────────

def _clean_version(raw):
    """Reduce a captured version to something comparable.

    Distribution suffixes are dropped: ``1.18.0-0ubuntu1`` is 1.18.0 as far as an
    advisory is concerned, and keeping the suffix would compare as a lower
    release than it is and over-report.
    """
    if not raw:
        return ""
    v = str(raw).strip().strip("v")
    v = re.split(r"[-+~ ]", v, 1)[0]
    m = re.match(r"^\d+(?:\.\d+)*", v)
    return m.group(0) if m else ""


def detect_components(headers, body=""):
    """Find products *and their versions* from a header dict and page body.

    Returns a list of ``{product, version, source, evidence}``. Entries with no
    version are dropped: a product without one cannot be turned into a CPE, and
    reporting "nginx present, version unknown" is already the website module's
    job.
    """
    headers = {str(k).lower(): (v or "") for k, v in (headers or {}).items()}
    found = {}

    for product, kind, pattern in _RULES:
        rx = re.compile(pattern, re.I)
        haystacks = []
        if kind == "header":
            for hdr in _HEADER_FOR.get(product, ()):
                if headers.get(hdr):
                    haystacks.append((hdr, headers[hdr]))
        else:
            haystacks.append(("body", body or ""))

        for source, text in haystacks:
            if not text:
                continue
            m = rx.search(text)
            if not m:
                continue
            version = _clean_version(m.group(1) if m.groups() else m.group(0))
            if not version:
                continue
            # First rule to match wins, so a specific header beats a body guess.
            if product not in found:
                found[product] = {
                    "product": product,
                    "version": version,
                    "source": f"{kind}:{source}",
                    "evidence": m.group(0)[:80],
                }
            break

    return sorted(found.values(), key=lambda c: c["product"])


def _cpes_for(product, version):
    """Every plausible CPE for this product/version, best guess first."""
    out = []
    for vendor in _CPE_VENDORS.get(product, ()):
        prod = _CPE_PRODUCT.get(product, product)
        out.append(f"cpe:2.3:a:{vendor}:{prod}:{version}")
    return out


def _cpe_wildcards(product):
    """Wildcard-version CPEs.

    Deliberately unused for querying. A wildcard version matches every advisory
    ever published for the product regardless of the detected version, so it was
    producing results like "nginx 1.31.3 is affected by CVE-2009-3555" whose
    range ends at 0.8.22. Kept only so the failure mode stays documented and
    testable rather than being rediscovered.
    """
    out = []
    for vendor in _CPE_VENDORS.get(product, ()):
        prod = _CPE_PRODUCT.get(product, product)
        out.append(f"cpe:2.3:a:{vendor}:{prod}")
    return out


# ─── version sanity ──────────────────────────────────────

def _version_key(version):
    """Sortable tuple for a dotted version.

    Missing components are padded so ``1.2`` and ``1.2.0`` compare equal, and
    non-numeric parts are dropped rather than raising.
    """
    parts = []
    for chunk in str(version or "").split("."):
        m = re.match(r"^(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def version_in_range(version, start, start_inc, end, end_inc):
    """Evaluate one NVD version bound set against a detected version.

    NVD expresses a bound with exactly one of four fields per edge. Getting this
    wrong in the permissive direction is how a tool ends up claiming a patched
    server is vulnerable, so anything unrecognised is treated as "not affected"
    and the caller reports the advisory as unverified rather than confirmed.
    """
    if not version:
        return False
    vk = _version_key(version)

    if start:
        sk = _version_key(start)
        if vk < sk or (vk == sk and not start_inc):
            return False
    if end:
        ek = _version_key(end)
        if vk > ek or (vk == ek and not end_inc):
            return False
    # A range with no bounds at all means every version of the product, which is
    # how NVD records a product-wide advisory.
    return True


# ─── NVD ─────────────────────────────────────────────────

_last_request = [0.0]


def _throttle(key):
    """Space NVD calls out to stay inside the rate limit."""
    interval = _MIN_INTERVAL_KEY if key else _MIN_INTERVAL_NO_KEY
    wait = interval - (time.monotonic() - _last_request[0])
    if wait > 0:
        time.sleep(wait)
    _last_request[0] = time.monotonic()


def _nvd_get(params, key=None, timeout=45, retries=2):
    """One NVD request. Returns parsed JSON, or None on failure.

    A 403 here is almost always the rate limit rather than a permissions
    problem, so it is retried with backoff before giving up.
    """
    if not _CURL:
        return None
    # _run() executes argv[0], so the binary has to lead; the proxy flags are
    # inserted here rather than left to _run so that --max-time stays adjacent
    # to the transfer it governs.
    args = [_CURL, "-sS", "--compressed", "--max-time", str(timeout)]
    args = args[:1] + _proxy_args() + args[1:]
    for key_name, value in params.items():
        args += ["-G", "--data-urlencode", f"{key_name}={value}"]
    args.append(NVD_API)
    if key:
        args += ["-G", "--data-urlencode", f"apiKey={key}"]

    for attempt in range(retries + 1):
        _throttle(key)
        try:
            r = utils._run(args, timeout=timeout + 10, proxy=False)
        except Exception:
            return None
        if not r:
            return None
        if isinstance(r, str) and r.lstrip().startswith("{"):
            try:
                import json
                return json.loads(r)
            except ValueError:
                return None
        if attempt < retries:
            time.sleep(3 * (attempt + 1))
    return None


def _severity(cve):
    """Best available CVSS base score and label across metric versions."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        data = (entries[0] or {}).get("cvssData") or {}
        score = data.get("baseScore")
        label = (data.get("baseSeverity") or "").upper()
        if not label:
            # CVSS v2 has no baseSeverity field; derive one from the score.
            if isinstance(score, (int, float)):
                label = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                         else "MEDIUM" if score >= 4 else "LOW")
        return score, label
    return None, ""


def _cve_affects(cve, vendor, product, version):
    """Does this advisory's own recorded range actually cover the version?

    NVD's ``virtualMatchString`` is not fully trustworthy on its own. Where a
    product's CPEs carry a wildcard version plus explicit versionStart/versionEnd
    bounds, a match can come back without the range being applied — a query for
    nginx 1.31.3 returned CVE-2009-3555, whose range stops at 0.8.22. So every hit
    is re-checked here against the bounds NVD itself recorded, and anything that
    does not demonstrably cover the detected version is dropped.

    A missing or unparseable range is treated as "not applicable". That is
    deliberately strict: a false CVE claim is far more damaging than a missed
    one, because an operator has no way to tell the difference without reading
    the advisory by hand.
    """
    if not version:
        return False
    needle = f":{vendor}:{product}:"
    seen = False
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                crit = m.get("criteria") or ""
                if needle not in crit:
                    continue
                seen = True
                crit_version = crit.split(":")[5] if crit.count(":") > 5 else "*"
                if crit_version not in ("*", "-"):
                    if crit_version == version:
                        return True
                    continue
                start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                end = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                if not start and not end:
                    # A wildcard version with no bounds is a product-wide
                    # advisory, which does apply.
                    return True
                if version_in_range(version, start, bool(m.get("versionStartIncluding")),
                                    end, bool(m.get("versionEndIncluding"))):
                    return True
    return False if seen else False


def _affected_ranges(cve, vendor, product):
    """The version bounds NVD records for this product, as readable strings.

    This is not cosmetic. NVD frequently revises a version range upward after
    publication while the advisory prose keeps its original wording, so a PHP
    7.4.3 install can be legitimately flagged for an advisory whose description
    still reads "through 7.1.5". Showing the structured range next to the
    description is what stops that looking like a false positive, and the
    structured range is the authoritative one.
    """
    ranges = []
    needle = f":{vendor}:{product}:"
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                crit = m.get("criteria") or ""
                if needle not in crit:
                    continue
                # ``cpe:2.3:a:vendor:product:version:...`` — index 5 is the
                # version. A concrete one is an exact-version advisory, which is
                # a different claim from "every version is affected".
                crit_version = crit.split(":")[5] if crit.count(":") > 5 else "*"
                if crit_version not in ("*", "-"):
                    ranges.append(crit_version)
                    continue
                if m.get("versionStartIncluding") or m.get("versionStartExcluding"):
                    lo = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                    op_lo = ">=" if m.get("versionStartIncluding") else ">"
                else:
                    lo, op_lo = None, ""
                if m.get("versionEndIncluding") or m.get("versionEndExcluding"):
                    hi = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                    op_hi = "<=" if m.get("versionEndIncluding") else "<"
                else:
                    hi, op_hi = None, ""
                if lo and hi:
                    ranges.append(f"{op_lo} {lo}, {op_hi} {hi}")
                elif hi:
                    ranges.append(f"< {hi}")
                elif lo:
                    ranges.append(f">= {lo}")
                else:
                    ranges.append("all versions")
    seen, out = set(), []
    for r in ranges:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out[:4]


def _parse_nvd(payload, product, version, source, cap=10, vendor=""):
    """Normalize one NVD response into the module's result shape.

    ``cap`` is applied *after* the version check, so a response full of
    out-of-range advisories does not starve the result of the ones that apply.
    """
    out = []
    for entry in (payload.get("vulnerabilities") or []):
        cve = entry.get("cve") or {}
        cid = cve.get("id") or ""
        if not cid:
            continue
        if not _cve_affects(cve, vendor, _CPE_PRODUCT.get(product, product), version):
            continue
        score, label = _severity(cve)
        refs = [r.get("url") for r in (cve.get("references") or [])
                if r.get("url")][:3]
        desc = ""
        for d in cve.get("descriptions") or []:
            if d.get("lang") == "en":
                desc = re.sub(r"\s+", " ", d.get("value") or "").strip()
                break
        out.append({
            "id": cid,
            "product": product,
            "version": version,
            "source": source,
            "severity": label,
            "score": score,
            "published": (cve.get("published") or "")[:10],
            "affected": _affected_ranges(cve, vendor, _CPE_PRODUCT.get(product, product)),
            "description": desc[:220],
            "references": refs,
        })
        if len(out) >= cap:
            break
    return out



# ─── public API ──────────────────────────────────────────

def check(components, key=None, cap=4, per_product=10):
    """Look up known CVEs for detected ``{product, version}`` components.

    ``components`` comes from :func:`detect_components`. ``cap`` bounds how many
    products are queried — each one is a rate-limited round trip, and server-side
    components are ordered ahead of front-end libraries because they are the ones
    an attacker can actually reach first. Returns a result dict with a
    ``status`` of ok, unavailable or error.
    """
    queryable = [c for c in components if c.get("product") in _CPE_VENDORS
                 and c.get("version")]
    if not queryable:
        return {
            "status": "ok",
            "checked": 0,
            "skipped": [c.get("product") for c in components if c not in queryable],
            "cve_count": 0,
            "cves": [],
            "components": [],
            "errors": [],
            "note": "no versioned components with a known CPE were detected",
        }
    if not _CURL:
        return {"status": "unavailable", "reason": "curl not found",
                "checked": 0, "cve_count": 0, "cves": [], "components": [],
                "skipped": [], "errors": []}

    # Server-side first: these are reachable and worth the round trip.
    order = {"nginx": 0, "apache": 1, "php": 2, "tomcat": 3, "iis": 4,
             "jenkins": 5, "openssh": 6, "wordpress": 7, "drupal": 8,
             "joomla": 9, "phpmyadmin": 10, "vbulletin": 11, "django": 12,
             "openssl": 13, "mysql": 14, "maria": 15, "jquery": 16, "bootstrap": 17}
    ranked = sorted(queryable, key=lambda c: order.get(c["product"], 50))
    limited = ranked[:cap] if cap else ranked
    skipped = [c["product"] for c in ranked[len(limited):]]

    all_cves, errors, checked = [], [], []
    for comp in limited:
        product, version = comp["product"], comp["version"]
        cpes = _cpes_for(product, version)
        found_for = []
        for cpe in cpes:
            payload = _nvd_get({"virtualMatchString": cpe, "resultsPerPage": 200}, key)
            if payload is None:
                errors.append(f"{product}: NVD request failed")
                break
            vendor = cpe.split(":")[3] if cpe.count(":") > 3 else ""
            hits = _parse_nvd(payload, product, version,
                              comp.get("source", ""), per_product, vendor)
            if hits:
                found_for = hits
                break
        if found_for:
            all_cves.extend(found_for)
            checked.append({"product": product, "version": version,
                            "cve_count": len(found_for),
                            "source": comp.get("source", "")})
        else:
            checked.append({"product": product, "version": version,
                            "cve_count": 0, "source": comp.get("source", "")})

    # Worst first so a report leads with what matters.
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4}
    all_cves.sort(key=lambda c: (sev_rank.get(c["severity"], 5),
                                 -(c["score"] or 0)))

    return {
        "status": "ok",
        "checked": len(limited),
        "components": checked,
        "skipped": skipped,
        "cve_count": len(all_cves),
        "cves": all_cves,
        "errors": errors,
        "keyed": bool(key),
        "queried_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
    }


def scan(headers, body="", key=None, cap=4, per_product=10):
    """Detect components from a response then look up their CVEs."""
    components = detect_components(headers, body)
    result = check(components, key=key, cap=cap, per_product=per_product)
    result["detected"] = components
    return result
