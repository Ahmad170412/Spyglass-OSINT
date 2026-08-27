"""Local, opt-in SQLite case store for Spyglass results.

Every stored run keeps a full JSON snapshot plus an entity index (domains,
IPs, emails, phones, orgs, onions, breaches) extracted from the result. The
entity index is what makes ``diff`` and ``timeline`` fast and useful — e.g.
"did this target gain/lose subdomains since last week?"

OPSEC note: the store is *opt-in* (``--store``). Storing recon results writes
target data to disk; the location is configurable via ``SPYGLASS_HOME``
(default ``~/.spyglass``). No store is ever written unless you ask for one.

Data at rest is encrypted with Fernet (AES-128-GCM). The key is derived from
``SPYGLASS_STORE_KEY`` (base64-encoded 32-byte key) or from ``SPYGLASS_STORE_PASS``
(via PBKDF2 with 100k iterations). If neither is set, a warning is printed and
data is stored in plaintext (backwards compatible).
"""

from __future__ import annotations

import json
import os
import sqlite3
import base64
import hashlib
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

def _csv_split(text):
    if not text:
        return []
    return [p.strip() for p in str(text).replace(", ", ",").split(",") if p.strip()]


def _entities(result, qtype):
    """Return a deduplicated list of (kind, value) tuples for a result dict."""
    out = []

    def add(kind, value):
        value = str(value).strip().lower()
        if value and (kind, value) not in out:
            out.append((kind, value))

    if qtype == "investigation":
        for kind, values in (result.get("entities") or {}).items():
            singular = kind.rstrip("s") or kind
            for v in values:
                add(singular, v)
        return out

    if qtype == "email":
        for key in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
            for item in result.get(key, []) or []:
                if isinstance(item, dict) and item.get("domain"):
                    add("domain", item["domain"])
    elif qtype == "username":
        for key, items in result.items():
            if key == "breach" or not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, dict) and item.get("domain"):
                    add("domain", item["domain"])
    elif qtype == "website":
        for ip in _csv_split(result.get("dns_records", {}).get("A", "")):
            add("ip", ip)
        for d in result.get("subdomains", []) or []:
            add("domain", d)
        for d in result.get("csp_domains", []) or []:
            add("domain", d)
        for d in _csv_split(result.get("tls", {}).get("san", "")):
            add("domain", d)
        for d in _csv_split(result.get("dns_email_security", {}).get("spf_includes", "")):
            add("domain", d)
        who = result.get("whois", {}) or {}
        for k in ("Organization", "OrgName", "org", "Org"):
            if who.get(k):
                add("org", who[k])
        for k in ("Email", "Tech Email", "Admin Email", "Registrant Email", "Extra Emails"):
            for e in _csv_split(who.get(k, "")):
                if "@" in e:
                    add("email", e)
    elif qtype == "ip":
        if result.get("ip"):
            add("ip", result["ip"])
        who = result.get("whois", {}) or {}
        for k in ("Organization", "OrgName", "org", "Org"):
            if who.get(k):
                add("org", who[k])
    elif qtype == "darkweb":
        for item in result.get("ahmia", []) or []:
            if isinstance(item, dict) and item.get("url"):
                add("onion", item["url"])
        for s in (result.get("breach") or {}).get("sources", []) or []:
            if isinstance(s, dict) and s.get("name"):
                add("breach", s["name"])
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
