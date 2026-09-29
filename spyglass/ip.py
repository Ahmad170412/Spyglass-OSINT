import re
import socket

from .utils import _run, _check_tool, _WHOIS, _curl_json

# Shodan's InternetDB: open ports and hostnames for an address, with no API key
# and no rate limit. This is what replaced the nmap port scan.
#
# The distinction that matters: InternetDB reports what *Shodan's own scan* saw,
# which is passive and keyless but only as fresh as that scan. nmap asked the
# host itself, so it was current and keyless but actively probed the target.
# Going passive means accepting stale data in exchange for never touching the
# target — the right trade for a tool that is run against third parties.
_INTERNETDB = "https://internetdb.shodan.io"


def address(target, top_ports=None):
    """Geolocate, reverse-resolve, WHOIS and passive port data for an address.

    ``top_ports`` is accepted and ignored. It tuned the nmap scan, and a flag
    that silently does nothing is worse than no flag, so it is being removed
    from the CLI rather than left behind as a no-op.
    """
    target = target.strip()
    ip = _resolve(target)
    if not ip:
        return {"error": f"Could not resolve: {target}"}

    r = {"ip": ip}

    geo = _geolocate(ip)
    if geo:
        r["geo"] = geo

    rdns = _reverse_dns(ip)
    if rdns:
        r["hostname"] = rdns

    hostname = target if _is_domain(target) else rdns
    if hostname:
        a_recs = _dns_a(hostname)
        if a_recs:
            r["a_records"] = a_recs

    who = _whois_lookup(ip)
    if who:
        r["whois"] = who

    net = _internetdb(ip)
    if net:
        r["internetdb"] = net
        if net.get("ports"):
            r["open_ports"] = net["ports"]

    return r


def _is_domain(s):
    return not s.replace(".", "").isdigit() and ":" not in s


def _resolve(target):
    if _is_domain(target):
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        return None


def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def _dns_a(hostname):
    if not hostname:
        return None
    addrs = []
    try:
        for res in socket.getaddrinfo(hostname, 0, socket.AF_INET):
            addr = res[4][0]
            if addr not in addrs:
                addrs.append(addr)
    except socket.gaierror:
        pass
    return addrs if addrs else None


def _ip_api(ip):
    url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone,query"
    data = _curl_json(url)
    if data and data.get("status") == "success":
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "as": data.get("as"),
            "location": f"{data['lat']},{data['lon']}",
            "timezone": data.get("timezone"),
        }
    return None


def _ipwhois(ip):
    """Second geolocation opinion, keyless.

    ip-api.com was the *only* place this module got a location from, so when it
    rate-limited, was blocked, or was simply down, the whole geo block vanished
    with no signal that anything had failed. Two independent sources for a fact
    this cheap is the cheapest redundancy in the tool.

    Also carries ``connection.asn`` and ``connection.org``, which is a free
    cross-check on the ``asn`` module: if RIPEStat and ipwho.is disagree about
    who routes an address, that disagreement is worth seeing rather than
    resolving silently in favour of whichever answered first.
    """
    data = _curl_json(f"https://ipwho.is/{ip}")
    if not isinstance(data, dict) or not data.get("success"):
        return None
    conn = data.get("connection") or {}
    out = {
        "country": data.get("country"),
        "region": data.get("region"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": conn.get("org") or data.get("isp"),
        "as": f"AS{conn['asn']}" if conn.get("asn") else None,
        "location": (f"{data['latitude']},{data['longitude']}"
                     if data.get("latitude") is not None
                     and data.get("longitude") is not None else None),
        "timezone": (data.get("timezone") or {}).get("id")
        if isinstance(data.get("timezone"), dict) else data.get("timezone"),
    }
    return {k: v for k, v in out.items() if v} or None


def _geolocate(ip):
    """Primary source first, fallback second, and say which one answered.

    The provenance is kept rather than discarded because a location that came
    from the fallback is worth half a location that came from the primary, and
    a reader cannot tell them apart if both render as "Brisbane".
    """
    primary = _ip_api(ip)
    if primary:
        primary["_source"] = "ip-api.com"
        return primary
    fallback = _ipwhois(ip)
    if fallback:
        fallback["_source"] = "ipwho.is (fallback)"
    return fallback


def _whois_lookup(ip):
    if not _check_tool("whois", _WHOIS):
        return None
    out = _run(["whois", "-h", "whois.arin.net", ip], timeout=15)
    if not out or "error" in out.lower()[:50]:
        return None
    result = {}
    for field in ("NetName", "Organization", "Country", "CIDR", "NetRange"):
        m = re.search(rf"^{field}:\s*(.+)$", out, re.MULTILINE)
        if m:
            result[field.lower()] = m.group(1).strip()
    return result if result else None


def _internetdb(ip):
    """Shodan InternetDB: open ports, hostnames, CPEs and tags for an address.

    Keyless and unmetered, which is the whole reason it is used. The Shodan
    *CLI* that this replaced needs an API key, so on a machine where nobody ran
    ``shodan init`` the old path returned nothing at all and the ip module
    reported no ports while looking like it had.

    Returns None when the address is unknown to Shodan. That is a different
    answer from "no open ports", so the two are kept apart: this returns None
    (and no ``open_ports`` key) rather than an empty port list, because an
    absent scan and a scan that found nothing must not read the same way in a
    dossier.
    """
    data = _curl_json(f"{_INTERNETDB}/{ip}")
    if not isinstance(data, dict):
        return None
    # A miss comes back as {"detail": "No information available..."}.
    if "detail" in data and "ip" not in data:
        return None

    out = {}
    ports = [p for p in (data.get("ports") or []) if isinstance(p, int)]
    if ports:
        out["ports"] = sorted(ports)
    names = [h for h in (data.get("hostnames") or []) if isinstance(h, str) and h]
    if names:
        out["hostnames"] = sorted(set(names))[:10]
    cpes = [c for c in (data.get("cpes") or []) if isinstance(c, str) and c]
    if cpes:
        # Product identification with no version. Not fed to cve.py on purpose —
        # its matching is built on detected *versions* re-checked against NVD's
        # recorded bounds, and a bare CPE has no version to bound.
        out["cpes"] = sorted(set(cpes))[:10]
    tags = [t for t in (data.get("tags") or []) if isinstance(t, str) and t]
    if tags:
        out["tags"] = sorted(set(tags))
    # ``vulns`` is deliberately not read. Shodan's list is unverified against
    # any range, and this project's rule is that a CVE claim must be
    # demonstrably covered by the affected range NVD recorded. Importing a
    # third-party list would reintroduce exactly the false positive the cve
    # module was written to avoid.
    return out or None
