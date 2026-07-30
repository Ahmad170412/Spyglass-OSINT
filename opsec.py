import json
import subprocess
import time

from . import utils


def health_check():
    r = {}
    recs = []

    direct = _direct_ip()
    if direct:
        r["direct"] = direct

    proxy_succeeded = False
    if utils._PROXY:
        proxy = _proxy_ip()
        if proxy:
            r["proxy"] = proxy
            anon = direct.get("ip") != proxy.get("ip") if direct else None
            r["anonymized"] = anon
            proxy_succeeded = True
            if anon is False:
                recs.append("Proxy does not hide your IP — check config or try a different proxy")
            else:
                recs.append("Proxy is active and IP is masked")
        else:
            recs.append("Proxy configured but unreachable — is Tor running?")

    r["tor_available"] = bool(utils._TORSOCKS)
    r["dns_leak"] = _dns_leak_status()
    r["timezone"] = _get_timezone()
    r["proxy_configured"] = bool(utils._PROXY)

    if not utils._PROXY:
        recs.append("No proxy configured — your real IP is exposed to every target")

    dl = r.get("dns_leak")
    if dl == "unverified":
        recs.append("DNS may leak — install torsocks to route DNS through Tor")
    elif dl == "protected":
        recs.append("DNS is routed through Tor — no leak")

    tor_note = _check_tor_tools()
    if tor_note:
        recs.extend(tor_note)

    if r.get("timezone") and direct and direct.get("country"):
        recs.append(f"Timezone ({r['timezone']}) matches {direct['country']} — potential geo-fingerprint")

    if recs:
        r["recommendations"] = recs

    return r


def _direct_ip():
    if not utils._CURL:
        return None
    cmd = [utils._CURL, "-s", "--noproxy", "*",
           "http://ip-api.com/json/?fields=query,country,isp,org"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        data = json.loads(r.stdout.strip())
        if data.get("query"):
            return {
                "ip": data["query"],
                "country": data.get("country"),
                "isp": data.get("isp"),
            }
    except Exception:
        pass
    return None


def _proxy_ip():
    url = "http://ip-api.com/json/?fields=query,country,isp,org"
    data = utils._curl_json(url)
    if data and data.get("query"):
        return {
            "ip": data["query"],
            "country": data.get("country"),
            "isp": data.get("isp"),
        }
    return None


def _dns_leak_status():
    if not utils._PROXY:
        return "not_applicable"
    if not utils._TORSOCKS:
        return "unverified"
    try:
        r = subprocess.run(
            [utils._TORSOCKS, "dig", "+short", "check.torproject.org"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            return "protected"
    except Exception:
        pass
    return "unverified"


def _get_timezone():
    try:
        return time.tzname[0] if time.tzname else "UTC"
    except Exception:
        return "unknown"


def _check_tor_tools():
    recs = []
    if not utils._PROXY:
        return None
    for name, path in [("nmap", utils._NMAP), ("dig", utils._DIG), ("whois", utils._WHOIS)]:
        if path and not utils._TORSOCKS:
            recs.append(f"{name} found but not Tor-safe — install torsocks to route it")
    return recs if recs else None
