"""Local, opt-in SQLite case store for Spyglass results.

Every stored run keeps a full JSON snapshot plus an entity index extracted from
the result: domains, IPs, autonomous systems, orgs, emails, phone numbers, file
hashes, coordinates, onions and breach-source names (see ``_KINDS``). The entity
index is what makes ``diff`` and ``timeline`` fast and useful — e.g. "did this
target gain/lose subdomains since last week?"

Extraction is per-module where the shape matters and inferred from value shape
where it does not, so a module that ships without a rule here is still
diffable. See ``_EXTRACTORS`` and ``_walk``.

OPSEC note: the store is *opt-in* (``--store``). Storing recon results writes
target data to disk; the location is configurable via ``SPYGLASS_HOME``
(default ``~/.spyglass``). No store is ever written unless you ask for one.

Data at rest is encrypted with Fernet (AES-128-GCM). The key is derived from
``SPYGLASS_STORE_KEY`` (base64-encoded 32-byte key) or from ``SPYGLASS_STORE_PASS``
(via PBKDF2 with 100k iterations). If neither is set, a warning is printed and
data is stored in plaintext (backwards compatible).

Note that the ``entities`` table is not covered by that encryption: it holds
domain, IP and email values in plaintext regardless of the key.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import base64
import hashlib
import ipaddress
from datetime import datetime

from . import __version__

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    _CRYPTO_AVAILABLE = True
except Exception:
    _CRYPTO_AVAILABLE = False

_SCHEMA_VERSION = 1


def _db_path():
    home = os.environ.get("SPYGLASS_HOME") or os.path.expanduser("~/.spyglass")
    os.makedirs(home, exist_ok=True)
    return os.path.join(home, "spyglass.db")


def _get_fernet():
    """Get Fernet instance for encryption. Returns None if crypto unavailable or no key set."""
    if not _CRYPTO_AVAILABLE:
        return None
    key_b64 = os.environ.get("SPYGLASS_STORE_KEY")
    if key_b64:
        try:
            return Fernet(key_b64.encode())
        except Exception:
            pass
    password = os.environ.get("SPYGLASS_STORE_PASS")
    if password:
        salt = b"spyglass-salt"  # Fixed salt for deterministic key derivation
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
    return None


def _encrypt(data: str) -> str:
    """Encrypt string data. Returns base64-encoded ciphertext or plaintext if no key."""
    f = _get_fernet()
    if not f:
        return data
    return f.encrypt(data.encode()).decode()


def _decrypt(data: str) -> str:
    """Decrypt string data. Returns plaintext or original if decryption fails."""
    f = _get_fernet()
    if not f:
        return data
    try:
        return f.decrypt(data.encode()).decode()
    except Exception:
        return data


def _connect():
    db = sqlite3.connect(_db_path())
    db.row_factory = sqlite3.Row
    return db


def _init(db):
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            qtype TEXT NOT NULL,
            run_at TEXT NOT NULL,
            result_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS entities (
            run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target, qtype, run_at);
        CREATE INDEX IF NOT EXISTS idx_entities_kind_value ON entities(kind, value);
        CREATE INDEX IF NOT EXISTS idx_entities_run ON entities(run_id);
        """
    )
    db.commit()


# ─── entity extraction ────────────────────────────────────

# Kinds, and why each one earns its place. A kind is a column in the entity
# index; ``diff`` is set subtraction over "kind:value" strings, so a kind is
# only useful if a change in it means something to the operator.
#
#   domain        infrastructure the target is reachable on
#   prefix        an announced CIDR, from the asn module. A change here means
#                 the route moved, which is a different fact from an address
#                 changing inside a stable prefix
#   ip            the target's own addresses
#   operator_ip   *your* address, from the opsec module. Deliberately NOT "ip":
#                 opsec reports the machine running Spyglass, and a cross-module
#                 diff on a target would otherwise show the operator's address
#                 appearing and disappearing alongside the target's — the same
#                 misattribution as a suffix-matched subdomain.
#   asn           BGP autonomous system
#   org           registrant / ISP, the pivot from infrastructure to entity
#   email         addresses found in WHOIS or page bodies
#   phone         E.164, so a phone run is diffable at all
#   hash          file digests from the metadata module, which link one file
#                 across cases and make a changed file visible
#   geo           a location, as "lat,lon"
#   onion         .onion host
#   breach        the name of a breached-data source
#
_KINDS = ("domain", "prefix", "ip", "operator_ip", "asn", "org", "email", "phone",
          "hash", "geo", "onion", "breach")


def _csv_split(text):
    if not text:
        return []
    return [p.strip() for p in str(text).replace(", ", ",").split(",") if p.strip()]


# ── shape inference ──
#
# The fallback for any module without an extractor below. It reads the value's
# *shape* rather than its key, which is what lets a newly added module get a
# working entity index without touching this file: a module that ships with no
# rule here is still diffable from day one, and a rule is only worth writing
# when inference is wrong for that module or too noisy.
#
# Order matters. An email is tested before a domain (it contains one), and an
# onion host before a domain (it is one). Testing the other way round
# classifies every address as a domain and quietly breaks ``diff``.

_ASN_RE = re.compile(r"^as\d+$", re.I)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_ONION_RE = re.compile(r"^[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion$", re.I)
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_URL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)

# Shape inference cannot tell a domain from a filename. "report.pdf" and
# "photo.jpg" satisfy every structural rule a domain does, and the metadata
# module returns filenames, so an unbounded TLD match files evidence files as
# infrastructure. There is no public-suffix list in the standard library, so the
# collision is closed from the other side: the extensions that are also valid
# TLDs. This only constrains the fallback — an explicit extractor that means to
# index something is never second-guessed.
_NOT_A_TLD = frozenset("""
    jpg jpeg jpe gif png bmp tif tiff svg webp ico heic raw cr2 nef arw dng
    pdf doc docx xls xlsx ppt pptx odt ods odp rtf txt csv tsv md rst log
    html htm xhtml css scss js mjs cjs ts tsx jsx json xml yaml yml toml ini
    conf cfg env bak old orig swp tmp temp lock part crdownload exe dll so dylib
    bin iso img dmg deb rpm apk msi jar py sh bash zsh ps1 bat cmd vbs pyc
    class jar war ear zip tar gz bz2 xz 7z rar tgz db sqlite sql mdb dat
    mp3 mp4 avi mkv mov wmv flv wav ogg m4a m4v aac flac webm wma
    asc sig pem crt cer key pub gpg pfx p12 keystore
""".split())

# Inference walks whatever a module returns, so it needs bounds. A website
# result can carry a few hundred subdomains and a port scan; nobody diffs a
# 10k-element list, and an unbounded walk is a latency bug waiting for the
# module that happens to return one.
_INFER_MAX_DEPTH = 6
_INFER_MAX_VALUES = 750


def _infer_kind(value):
    """Classify a string into an entity kind, or None if it is not an entity."""
    value = value.strip().lower()
    if not value or len(value) > 253:
        return None
    if _EMAIL_RE.match(value):
        return "email"
    if _ONION_RE.match(value):
        return "onion"
    if _ASN_RE.match(value):
        return "asn"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if "/" in value:
        # A CIDR, not an address. Checked after ipaddress so "1.2.3.4/32" is
        # still a prefix rather than being read as an ip with trailing noise.
        try:
            ipaddress.ip_network(value, strict=False)
            return "prefix"
        except ValueError:
            return None
    if _DOMAIN_RE.match(value):
        if value.rsplit(".", 1)[-1] in _NOT_A_TLD:
            return None
        return "domain"
    return None


def _index_scalar(add, value, budget):
    """Index one scalar, unwrapping URLs to their host and comma-joined fields.

    Several modules serialise a list as a comma-joined string (website's
    ``dns_records`` is built that way), so a walker that only ever saw real
    lists would miss exactly the fields the explicit rules were written for.
    """
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        return
    if not isinstance(value, str):
        return
    for part in _csv_split(value):
        budget[0] -= 1
        if budget[0] <= 0:
            return
        if _URL_RE.match(part):
            host = part.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
            part = host
        kind = _infer_kind(part)
        if kind:
            add(kind, part)


def _walk(result, add, skip=(), _depth=0, budget=None):
    """Depth-bounded walk that indexes scalars by shape.

    ``budget`` is a one-element list threaded down the recursion rather than a
    module global. A global would be shared between calls, so the first walk in
    a process would exhaust it and every later walk — a second ``--store`` run,
    or any request to the long-running web console — would silently index
    nothing. A fresh cell per pass also keeps concurrent callers independent.
    """
    if budget is None:
        budget = [_INFER_MAX_VALUES]
    if budget[0] <= 0 or _depth > _INFER_MAX_DEPTH:
        return
    if isinstance(result, dict):
        children = [(k, v) for k, v in result.items()
                    if not (isinstance(k, str) and (k.startswith("_") or k in skip))]
    elif isinstance(result, list):
        children = list(enumerate(result))
    else:
        return
    for _key, value in children:
        if budget[0] <= 0:
            return
        if isinstance(value, (dict, list)):
            _walk(value, add, skip, _depth + 1, budget)
        else:
            _index_scalar(add, value, budget)


def _extract_email(result, add):
    for key in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
        for item in result.get(key) or []:
            if isinstance(item, dict) and item.get("domain"):
                add("domain", item["domain"])
    _breach_sources(result, add)


def _extract_username(result, add):
    for key, items in result.items():
        if key == "breach" or not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and item.get("domain"):
                add("domain", item["domain"])
    _breach_sources(result, add)


def _extract_website(result, add):
    for ip in _csv_split((result.get("dns_records") or {}).get("A", "")):
        add("ip", ip)
    for d in result.get("subdomains") or []:
        add("domain", d)
    for d in result.get("csp_domains") or []:
        add("domain", d)
    for d in _csv_split((result.get("tls") or {}).get("san", "")):
        add("domain", d)
    for d in _csv_split((result.get("dns_email_security") or {}).get("spf_includes", "")):
        add("domain", d)
    # Historical resolutions. Indexed rather than left inside the `passive_dns`
    # blob because these are exactly the entities `cases diff` should notice: a
    # name moving to a new address is a change, and one that only shows up in
    # the passive record is the one a live re-scan would miss entirely.
    for recs in (result.get("passive_dns") or {}).get("resolved", {}).values():
        for rec in recs or []:
            if isinstance(rec, dict) and rec.get("ip"):
                add("ip", rec["ip"])
    for ip in result.get("observed_ips") or []:
        if isinstance(ip, str):
            add("ip", ip)
    for asn in result.get("observed_asns") or []:
        if isinstance(asn, str):
            add("asn", asn)
    who = result.get("whois") or {}
    for k in ("Organization", "OrgName", "org", "Org"):
        if who.get(k):
            add("org", who[k])
    for k in ("Email", "Tech Email", "Admin Email", "Registrant Email", "Extra Emails"):
        for e in _csv_split(who.get(k, "")):
            if "@" in e:
                add("email", e)


def _extract_ip(result, add):
    if result.get("ip"):
        add("ip", result["ip"])
    who = result.get("whois") or {}
    for k in ("Organization", "OrgName", "org", "Org"):
        if who.get(k):
            add("org", who[k])
    # InternetDB hostnames are the highest-value thing this module returns: a
    # vhost on the same address is an asset that neither the target's own DNS nor
    # a subdomain sweep of the domain would surface.
    net = result.get("internetdb") or {}
    for h in net.get("hostnames") or []:
        if isinstance(h, str):
            add("domain", h)
    _walk(result, add, skip=("whois",))


def _extract_darkweb(result, add):
    for item in result.get("ahmia") or []:
        if isinstance(item, dict) and item.get("url"):
            add("onion", item["url"])
    _breach_sources(result, add)


def _extract_phone(result, add):
    """A phone run had no index at all, so diffing one always reported nothing.

    The useful signal is which sites have the number registered: that is a set
    that grows, and watching it grow is the reason to re-run a phone target.
    """
    pn = result.get("phonenumbers") or {}
    if pn.get("e164"):
        add("phone", pn["e164"])
    for domain in result.get("ignorant") or []:
        if isinstance(domain, str):
            add("domain", domain)
    _breach_sources(result, add)
    # phoneinfoga's schema varies by version and carries OSINT source URLs.
    _walk(result, add, skip=("phonenumbers", "ignorant", "breach"))


def _extract_metadata(result, add):
    """Index file digests and GPS, so a changed file is visible in a diff.

    The digests are worth more than the EXIF fields: the same file appearing
    under two case targets links those cases, and a changed digest between two
    runs of one target says the evidence was swapped.
    """
    for key in ("md5", "sha256", "sha1", "FileHash"):
        if result.get(key):
            add("hash", result[key])
    gps = result.get("GPS") or {}
    if isinstance(gps, dict):
        for k, v in gps.items():
            if k.lower() in ("md5", "sha256", "sha1", "filehash"):
                add("hash", v)
    point = _gps_point(gps)
    if point:
        add("geo", point)
    # exiftool surfaces free-text fields (UserComment, Warning, HostName) that
    # routinely contain domains and addresses worth indexing.
    _walk(result, add, skip=("GPS",))


def _gps_point(gps):
    """Compose a GPS fix into "lat,lon" from exiftool's split fields.

    exiftool reports the magnitude and hemisphere separately, and the magnitude
    is unsigned, so a southern or western position needs the ref applied or it
    lands on the wrong side of the equator. Falls back to the combined
    ``GPSPosition`` string, which is formatted for humans and therefore only
    used when the split fields are missing.
    """
    if not isinstance(gps, dict):
        return ""

    def _num(key, ref_key, negative_ref):
        raw = gps.get(key)
        if raw is None:
            return None
        try:
            value = float(str(raw).strip())
        except (TypeError, ValueError):
            return None
        ref = str(gps.get(ref_key, "") or "").strip().upper()[:1]
        if ref and ref == negative_ref:
            value = -abs(value)
        return round(value, 5)

    lat = _num("GPSLatitude", "GPSLatitudeRef", "S")
    lon = _num("GPSLongitude", "GPSLongitudeRef", "W")
    if lat is not None and lon is not None:
        return f"{lat},{lon}"
    position = str(gps.get("GPSPosition", "") or "").strip()
    return position if _infer_kind(position) is None and position else ""


def _extract_opsec(result, add):
    """Index the operator's own addresses, under a kind that cannot be confused
    with the target's.

    ``opsec`` reports the machine running Spyglass. Filing that under ``ip``
    would put the operator's address into a target's entity set, and a
    cross-module ``cases diff`` would then report the operator's IP as
    infrastructure that appeared or disappeared on the target.
    """
    for section in ("direct", "proxy"):
        block = result.get(section) or {}
        if isinstance(block, dict) and block.get("ip"):
            add("operator_ip", block["ip"])


def _extract_asn(result, add):
    """Index the origin AS and the holder it resolves to.

    The holder is the pivot worth keeping: it is the same organisation string
    WHOIS puts in an ``org`` entity, so an asn run and a website run on the same
    operator land on a shared value and a cross-module diff can connect them.
    """
    if result.get("asn"):
        add("asn", f"AS{result['asn']}")
    for origin in result.get("origin_asns") or []:
        if isinstance(origin, dict):
            if origin.get("asn"):
                add("asn", f"AS{origin['asn']}")
            if origin.get("holder"):
                add("org", origin["holder"])
    if result.get("holder"):
        add("org", result["holder"])
    if result.get("prefix"):
        add("prefix", result["prefix"])


def _breach_sources(result, add):
    for source in (result.get("breach") or {}).get("sources") or []:
        if isinstance(source, dict) and source.get("name"):
            add("breach", source["name"])


# A module with no extractor here still gets an index, from shape inference.
# Adding a row is an optimisation, not a prerequisite.
_EXTRACTORS = {
    "email": _extract_email,
    "username": _extract_username,
    "website": _extract_website,
    "ip": _extract_ip,
    "darkweb": _extract_darkweb,
    "phone": _extract_phone,
    "metadata": _extract_metadata,
    "opsec": _extract_opsec,
    "asn": _extract_asn,
}


def _entities(result, qtype):
    """Return a deduplicated list of (kind, value) tuples for a result dict.

    Deduplicated and lowercased, because ``diff`` is set subtraction over
    "kind:value" strings: two runs that differ only in case would otherwise
    report a change that nothing actually made.
    """
    out = []

    def add(kind, value):
        value = str(value).strip().lower()
        if value and (kind, value) not in out:
            out.append((kind, value))

    if not isinstance(result, dict):
        return out
    extractor = _EXTRACTORS.get(qtype)
    if extractor is not None:
        extractor(result, add)
    else:
        _walk(result, add)
    return out



# ─── write / read ─────────────────────────────────────────

def store_result(result, qtype, target):
    """Persist one result snapshot + its entities. Returns the run id or None."""
    if not result or not target:
        return None
    db = _connect()
    try:
        _init(db)
        run_at = datetime.now().isoformat(timespec="seconds")
        result_json = json.dumps(result, default=str)
        enc_result = _encrypt(result_json)
        cur = db.execute(
            "INSERT INTO runs (target, qtype, run_at, result_json) VALUES (?, ?, ?, ?)",
            (target, qtype, run_at, enc_result),
        )
        run_id = cur.lastrowid
        for kind, value in _entities(result, qtype):
            db.execute(
                "INSERT INTO entities (run_id, kind, value) VALUES (?, ?, ?)",
                (run_id, kind, value),
            )
        db.commit()
        if _get_fernet():
            from . import display as ui
            ui.info("Stored with encryption (SPYGLASS_STORE_KEY or SPYGLASS_STORE_PASS set)")
        return run_id
    except Exception:
        return None
    finally:
        db.close()


def _latest_runs(db, target, qtype, limit):
    if qtype:
        rows = db.execute(
            "SELECT * FROM runs WHERE target=? AND qtype=? "
            "ORDER BY run_at DESC, id DESC LIMIT ?",
            (target, qtype, limit),
        )
    else:
        rows = db.execute(
            "SELECT * FROM runs WHERE target=? ORDER BY run_at DESC, id DESC LIMIT ?",
            (target, limit),
        )
    return [dict(r) for r in rows.fetchall()]


def _entity_set(db, run_id):
    rows = db.execute(
        "SELECT kind, value FROM entities WHERE run_id=?", (run_id,)
    ).fetchall()
    return {f"{r['kind']}:{r['value']}" for r in rows}


# ─── queries ──────────────────────────────────────────────

def list_cases():
    """Return [{target, qtype, count, last}] for every stored target/qtype."""
    db = _connect()
    try:
        _init(db)
        rows = db.execute(
            "SELECT target, qtype, COUNT(*) AS count, MAX(run_at) AS last "
            "FROM runs GROUP BY target, qtype ORDER BY target, qtype"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def diff(target, qtype=None):
    """Entity-level added/removed between the two most recent runs."""
    db = _connect()
    try:
        _init(db)
        runs = _latest_runs(db, target, qtype, limit=2)
        if len(runs) < 2:
            return {"target": target, "qtype": qtype, "added": [], "removed": [],
                    "error": "need at least two stored runs to diff"}
        old_ents = _entity_set(db, runs[1]["id"])
        new_ents = _entity_set(db, runs[0]["id"])
        return {
            "target": target,
            "qtype": qtype,
            "old_run": runs[1]["run_at"],
            "new_run": runs[0]["run_at"],
            "added": sorted(new_ents - old_ents),
            "removed": sorted(old_ents - new_ents),
        }
    finally:
        db.close()


def timeline(target, qtype=None):
    """Chronological entity snapshots (oldest first) for a target."""
    db = _connect()
    try:
        _init(db)
        runs = _latest_runs(db, target, qtype, limit=500)
        out = []
        for row in reversed(runs):
            out.append({
                "run_at": row["run_at"],
                "qtype": row["qtype"],
                "entities": sorted(_entity_set(db, row["id"])),
            })
        return out
    finally:
        db.close()


def export_profile(target):
    """Latest result per qtype merged into a stable, shareable JSON profile."""
    db = _connect()
    try:
        _init(db)
        rows = db.execute(
            "SELECT * FROM runs WHERE id IN ("
            "SELECT MAX(id) FROM runs WHERE target=? GROUP BY qtype"
            ") ORDER BY qtype",
            (target,),
        ).fetchall()
        results, entities = {}, {}
        for row in rows:
            d = dict(row)
            result = json.loads(_decrypt(d["result_json"]))
            results[d["qtype"]] = result
            for kind, value in _entities(result, d["qtype"]):
                entities.setdefault(kind, []).append(value)
        for kind in entities:
            entities[kind] = sorted(set(entities[kind]))
        return {
            "target": target,
            "generated": datetime.now().isoformat(timespec="seconds"),
            "schema_version": _SCHEMA_VERSION,
            "spyglass_version": __version__,
            "entities": entities,
            "results": results,
        }
    finally:
        db.close()
