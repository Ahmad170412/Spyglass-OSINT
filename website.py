import re
import subprocess

from .utils import (_run, _extract_emails, _extract_phones,
                    _extract_whois_fields, _check_tool, _DIG, _NMAP, _GOBUSTER,
                    _HTPPX, _WHOIS, _CURL, _SHODAN, _proxy_env, _proxy_args,
                    _curl_json)
from . import utils

_SUB_LIST = """
www mail admin api blog dev test staging app beta cdn docs shop store support
help portal status web m mobile news forum wiki demo vpn secure signup login
register assets img css js static download files media video chat community
boards calendar events maps api2 api3 backup db dns email ftp git graphql hr
iam jenkins jobs kibana ldap localhost logs mail2 metrics monitor mx mx1 mx2
ns1 ns2 pay payment phpmyadmin pop prod proxy radius redirect redis remote
rest sandbox smtp sql ssh ssl stats status2 svn sync syslog test2 tunnel
upload uploads vhost vm vpn2 webmail websocket ws www2 www3 xmlrpc
""".strip().split()

_DIR_LIST = """
admin administrator api app assets backup backups cache cdn cgi-bin cmd config
configuration content css dashboard db demo dev docs download downloads error
examples export favicon.ico files fonts forum graphql help home html images
img include includes index install js json language lib library license login
log logs mail media migrate mobile modules news old package pages panel
phpinfo.php plugins private prod public README readme reports rest robots.txt
rss sass save scripts search secure server-status service services session
setup sitemap.xml sql src ssh stat static stats status storage styles svn
swagger temp template templates test tmp todo tools tmp update upload uploads
user users v2 vendor version video views web webapp webroot wiki wpad.dat www
xml xmlrpc
""".strip().split()


def website(target, display=None):
    out = _collect(target)
    if display:
        display(out)
    return out


def _collect(target):
    result = {}

    ips = []
    for rtype in ["A", "AAAA"]:
        raw = _run(["dig", target, rtype, "+short"])
        if raw:
            ips.extend(l.strip() for l in raw.split("\n") if l.strip() and "." in l)
    ips = list(set(ips))

    # 1. DNS records
    dns = {}
    if _check_tool("dig", _DIG):
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            raw = _run(["dig", target, rtype, "+short"])
            if raw:
                vals = [l.strip() for l in raw.split("\n") if l.strip()]
                if vals:
                    dns[rtype] = ", ".join(vals)
    if dns:
        result["dns_records"] = dns

    # 2. Shodan
    shodan_data = []
    if ips and _check_tool("shodan", _SHODAN):
        for ip in ips:
            try:
                r = subprocess.run(
                    ["shodan", "host", ip],
                    capture_output=True, text=True, timeout=20,
                    env=_proxy_env(),
                )
                data = r.stdout.strip()
                err = r.stderr.strip()
            except Exception as e:
                data, err = "", str(e)

            if data:
                org = ports = isp = country = ""
                for line in data.split("\n"):
                    low = line.lower()
                    if "organization" in low or low.startswith("org:"):
                        org = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "isp" in low:
                        isp = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "country" in low:
                        country = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "ports" in low:
                        ports = line.split(":", 1)[1].strip() if ":" in line else ""
                parts = [p for p in [f"Org: {org}" if org else "",
                                     f"ISP: {isp}" if isp else "",
                                     f"Country: {country}" if country else "",
                                     f"Ports: {ports}" if ports else ""] if p]
                shodan_data.append(f"{ip}: {' | '.join(parts)}" if parts else f"{ip}: No Shodan data")
            elif "403" in err:
                shodan_data.append(f"{ip}: Free tier limit")
            elif "init" in err.lower():
                shodan_data.append(f"{ip}: Shodan not configured")
            elif err:
                shodan_data.append(f"{ip}: {err.split(chr(10))[-1].strip()}")
            else:
                shodan_data.append(f"{ip}: No Shodan data")
    elif ips:
        shodan_data.append("Skipping (shodan not found)")
    if shodan_data:
        result["shodan"] = shodan_data

    # 3. Port scan
    ports_data = []
    if ips and _check_tool("nmap", _NMAP):
        for ip in ips:
            nm = _run(
                ["nmap", "--top-ports", "100", "-sV", "-T4", "--open", ip, "-oG", "-"],
                timeout=120,
            )
            ports = re.findall(r"(\d+)/(open|filtered)/tcp//([^/]*?)//([^/]*?)", nm)
            if ports:
                parts = []
                for p, st, sv, pr in ports:
                    if pr:
                        parts.append(f"{p}/{sv} ({pr})")
                    elif sv:
                        parts.append(f"{p}/{sv}")
                    else:
                        parts.append(p)
                ports_data.append(f"{ip}: {', '.join(parts)}")
            else:
                ports_data.append(f"{ip}: No open ports found")
    if ports_data:
        result["port_scan"] = ports_data

    # 4. HTTP headers
    if _check_tool("curl", _CURL):
        hd = _run(["curl", "-sI", "-L", f"https://{target}"])
        server = ""
        for line in hd.split("\n"):
            low = line.lower()
            if low.startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif low.startswith("x-powered-by:"):
                server += (" | " + line.split(":", 1)[1].strip()) if server else line.split(":", 1)[1].strip()
        if server:
            result["http_headers"] = {"Server": server}

    # 5. WHOIS
    whois_data = {}
    if _check_tool("whois", _WHOIS):
        wh = _run(["whois", target], timeout=30)
        fields = _extract_whois_fields(wh)
        whois_emails = _extract_emails(wh)
        whois_phones = _extract_phones(wh)
        for k, v in fields.items():
            whois_data[k] = v
        extra_emails = [e for e in whois_emails if e not in whois_data.values()]
        if extra_emails:
            whois_data["Extra Emails"] = ", ".join(extra_emails)
        extra_phones = [p for p in whois_phones if p not in whois_data.values()]
        if extra_phones:
            whois_data["Extra Phones"] = ", ".join(extra_phones)
    if whois_data:
        result["whois"] = whois_data

    # 6. Certificate Transparency (crt.sh) — passive subdomain enumeration
    crt_subs = set()
    raw = _curl_json(f"https://crt.sh/?q=%25.{target}&output=json&limit=100")
    if raw and isinstance(raw, list):
        for entry in raw:
            vals = entry.get("name_value", "")
            for name in vals.split("\n"):
                name = name.strip().lower()
                if name.endswith(f".{target.lower()}") or name == target.lower():
                    crt_subs.add(name)
    if crt_subs:
        result["crt_sh_subdomains"] = sorted(crt_subs)

    # 7. Subdomain enumeration (gobuster)
    gb_subs = []
    if _check_tool("gobuster", _GOBUSTER):
        sd_out = _run(
            ["gobuster", "dns", "-d", target, "-w", "-", "-q"] + (_proxy_args() if utils._PROXY else []),
            timeout=60, stdin="\n".join(_SUB_LIST),
        )
        gb_subs = sorted(set(re.findall(r"Found:\s*(\S+)", sd_out)))
    if gb_subs:
        result["subdomains"] = gb_subs

    # 8. HTTP probing — probe all discovered subdomains
    all_subs = sorted(set(gb_subs) | crt_subs)
    if all_subs:
        probe = []
        if _check_tool("httpx", _HTPPX):
            hx = _run(
                ["httpx", "-silent", "-status-code", "-title",
                 "-server", "-content-length", "-timeout", "10"]
                + [f"https://{s}" for s in all_subs],
                timeout=60,
            )
            probe = [l.strip() for l in hx.split("\n") if l.strip()]
        if probe:
            result["http_probe"] = probe

    # 9. Directory enumeration
    dirs = []
    if _check_tool("gobuster", _GOBUSTER):
        gb_out = _run(
            ["gobuster", "dir", "-u", f"https://{target}",
             "-w", "-", "-q", "-t", "20", "-k"] + (_proxy_args() if utils._PROXY else []),
            timeout=90, stdin="\n".join(_DIR_LIST),
        )
        found_dirs = re.findall(r"/(\S+)\s+\(Status:\s*\d+\)", gb_out)
        if found_dirs:
            dirs = sorted(set(found_dirs))
        else:
            hint = re.findall(r"/(\S+)", gb_out)
            if hint:
                dirs = sorted(set(hint))[:10]
    if dirs:
        result["directories"] = dirs

    return result
