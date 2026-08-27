import re
import socket

from .utils import _run, _check_tool, _SHODAN, _NMAP, _WHOIS, _curl_json

_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
                 5986, 6379, 8080, 8443, 9090, 27017]


def address(target, top_ports=None):
    target = target.strip()
    ip = _resolve(target)
    if not ip:
        return {"error": f"Could not resolve: {target}"}

    r = {"ip": ip}

    geo = _ip_api(ip)
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

    if _SHODAN:
        sd = _shodan_lookup(ip)
        if sd:
            r["shodan"] = sd

    ports = _port_scan(ip, top_ports)
    if ports:
        r["open_ports"] = ports

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


def _shodan_lookup(ip):
    out = _run(["shodan", "host", ip], timeout=30)
    if not out or "error" in out.lower()[:50]:
        return None
    lines = out.splitlines()
    ports = []
    hostnames = set()
    for line in lines:
        m = re.match(r"^(\d+)/", line)
        if m:
            ports.append(int(m.group(1)))
        if "hostnames:" in line.lower():
            parts = line.split(":", 1)[1].strip().strip("[]")
            if parts:
                for h in parts.replace(";", ",").split(","):
                    h = h.strip().strip("'\"")
                    if h:
                        hostnames.add(h)
    sd = {}
    if ports:
        sd["ports"] = sorted(ports)[:50]
    if hostnames:
        sd["hostnames"] = sorted(hostnames)[:10]
    return sd if sd else None


def _port_scan(ip, top_ports=None):
    if not _check_tool("nmap", _NMAP):
        return None
    if top_ports:
        port_args = ["--top-ports", str(top_ports)]
    else:
        ports_str = ",".join(str(p) for p in _COMMON_PORTS)
        port_args = ["-p", ports_str]
    out = _run(["nmap", "-Pn", "-n", "--open", "-T4"] + port_args + ["--min-rate", "1000", ip], timeout=120)
    if not out:
        return None
    found = []
    for line in out.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open", line)
        if m:
            found.append(int(m.group(1)))
    return found if found else None
