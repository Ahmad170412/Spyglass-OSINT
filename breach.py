import json
import subprocess
import concurrent.futures
from urllib.parse import quote

from . import utils


def check(query, qtype="email"):
    """Run leakcheck + scylla in parallel and merge results."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        lk = pool.submit(_leakcheck, query)
        sc = pool.submit(_scylla, query)
        lk_result = lk.result()
        sc_result = sc.result()

    total = lk_result["found"] + sc_result["found"]
    sources = lk_result["sources"] + sc_result["sources"]
    fields = list(set(lk_result["fields"] + sc_result["fields"]))
    return {"found": total, "sources": sources, "fields": fields}


def _leakcheck(query):
    if not utils._CURL:
        return {"found": 0, "sources": [], "fields": []}
    try:
        url = f"https://leakcheck.io/api/public?check={quote(query)}"
        cmd = [utils._CURL, "-s", url]
        if utils._PROXY:
            cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout.strip())
        if data.get("success"):
            return {
                "found": data.get("found", 0),
                "sources": data.get("sources", []),
                "fields": data.get("fields", []),
            }
    except Exception:
        pass
    return {"found": 0, "sources": [], "fields": []}


def _scylla(query):
    if not utils._CURL:
        return {"found": 0, "sources": [], "fields": []}
    try:
        url = f"https://scylla.so/api/search/email/{quote(query)}"
        cmd = [utils._CURL, "-s", url]
        if utils._PROXY:
            cmd = cmd[:1] + utils._proxy_args() + cmd[1:]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        data = json.loads(r.stdout.strip())
        if isinstance(data, list) and data:
            names = set()
            fields = set()
            for entry in data:
                for key in ("database", "source", "breach"):
                    if entry.get(key):
                        names.add(str(entry[key]))
                for key, val in entry.items():
                    if val and key not in ("database", "source", "breach", "_id"):
                        fields.add(key.replace("_", " ").title())
            return {
                "found": len(data),
                "sources": [{"name": n, "date": "N/A"} for n in sorted(names)[:10]],
                "fields": sorted(fields),
            }
    except Exception:
        pass
    return {"found": 0, "sources": [], "fields": []}
