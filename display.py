import sys
import os
import re
import socket

try:
    from rich.console import Console as _Console
    from rich.style import Style

    _con = _Console(highlight=False)
    _con_stderr = _Console(highlight=False, file=sys.stderr)
    _RICH = True

    def _style(*, fg=None, bold=False, dim=False):
        return Style(color=fg, bold=bold, dim=dim)

except ImportError:
    _RICH = False
    _con = None
    _con_stderr = None

    def _style(*, fg=None, bold=False, dim=False):
        class _Null:
            def __call__(self, s):
                return s
        return _Null()


# ─── banner ──────────────────────────────────────────────

_BANNER = r"""
 ███████╗██████╗ ██╗   ██╗ ██████╗ ██╗      █████╗ ███████╗███████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝ ██║     ██╔══██╗██╔════╝██╔════╝
 ███████╗██████╔╝ ╚████╔╝ ██║  ███╗██║     ███████║███████╗███████╗
 ╚════██║██╔═══╝   ╚██╔╝  ██║   ██║██║     ██╔══██║╚════██║╚════██║
 ███████║██║        ██║   ╚██████╔╝███████╗██║  ██║███████║███████║
 ╚══════╝╚═╝        ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝
"""


def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def banner():
    if _RICH:
        _con.clear()
        _con.print(_BANNER, style="bold #00ff00")
        _con.print(f"    Your Local IP: {_local_ip()}\n", style="#00ff00")
    else:
        os.system("clear")
        print(_BANNER)
        print(f"    Your Local IP: {_local_ip()}\n")


# ─── public helpers ──────────────────────────────────────

_GREEN = "#00ff00"

_MAIN_ITEMS = [
    "[1]  Identity              (email, username, phone, dark web)",
    "[2]  Infrastructure        (website, IP)",
    "[3]  Full investigation    (correlate everything)",
    "[4]  Utilities             (OPSEC, metadata, help, clear)",
    "[5]  Exit",
]

_SUB_MENUS = {
    "identity": [
        "[1]  Email investigation",
        "[2]  Username search",
        "[3]  Phone investigation",
        "[4]  Dark web search",
        "[5]  Back",
    ],
    "infra": [
        "[1]  Website recon",
        "[2]  IP address recon",
        "[3]  Back",
    ],
    "utils": [
        "[1]  OPSEC health check",
        "[2]  Metadata extraction",
        "[3]  Help",
        "[4]  Clear screen",
        "[5]  Back",
    ],
}

_SUB_LABELS = {
    "main":     "Select [1-5]",
    "identity": "Select [1-5]",
    "infra":    "Select [1-3]",
    "utils":    "Select [1-5]",
}


def _show_lines(lines):
    if _RICH:
        _con.print("", style=_GREEN)
        for line in lines:
            _con.print(f"  {line}", style=_GREEN)
        _con.print("", style=_GREEN)
    else:
        print()
        for line in lines:
            print(f"  {line}")
        print()


def menu_prompt(category="main"):
    """Show a category menu and return the user's choice."""
    if category == "main":
        _show_lines(_MAIN_ITEMS)
    else:
        items = _SUB_MENUS.get(category, _MAIN_ITEMS)
        _show_lines(items)
    label = _SUB_LABELS.get(category, "Select:")
    if _RICH:
        _con_stderr.print(f"[bold {_GREEN}]{label}:[/] ", end="")
    else:
        sys.stderr.write(f"{label}: ")
    sys.stderr.flush()
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        raise


def target_prompt(qtype):
    """Ask for the target value for a given query type."""
    labels = {
        "email":    "Enter email address",
        "username": "Enter username",
        "phone":    "Enter phone number",
        "website":  "Enter domain or URL",
        "metadata": "Enter file path",
        "ip":       "Enter IP address or domain",
        "darkweb":  "Enter email, username, phone, domain, or IP",
    }
    label = labels.get(qtype, "Enter target")
    if _RICH:
        _con_stderr.print(f"[bold {_GREEN}]{label}:[/] ", end="")
    else:
        sys.stderr.write(f"{label}: ")
    sys.stderr.flush()
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        raise


def investigation_prompt():
    if _RICH:
        _con_stderr.print(f"[bold {_GREEN}]Enter what you know about the target:[/]")
        _con_stderr.print(f"  email, username, phone, website (comma-sep)", style="dim")
        _con_stderr.print(f"[bold {_GREEN}]>[/] ", end="")
    else:
        sys.stderr.write("Enter what you know (email, username, phone, website):\n> ")
    sys.stderr.flush()
    try:
        return input().strip()
    except (EOFError, KeyboardInterrupt):
        raise


def info(msg):
    _print(f"[*] {msg}", _GREEN)


def good(msg):
    _print(msg, _GREEN)


def warn(msg):
    _print(msg, "yellow")


def err(msg):
    _print(msg, "red")


def header(label, target):
    _print(f"\n[*] {label}: {target}", _GREEN, bold=True)


def section(label):
    _print(f"\n  {label}", _GREEN)


def item(text):
    _print(f"    {text}", "green")


def item_dim(text):
    _print(f"    {text}", None, dim=True)


def kv(key, value):
    _print(f"    {key}: {value}", None)


def found(label, items, extract=None):
    if not items:
        return
    _print(f"\n  {label}", _GREEN)
    for it in items:
        val = extract(it) if extract else it.get("url", it.get("domain", str(it)))
        _print(f"    {val}", _GREEN)


def only(label, items, extract=None):
    if not items:
        return
    _print(f"\n  {label}", "yellow")
    for it in items:
        val = extract(it) if extract else it.get("url", it.get("domain", str(it)))
        _print(f"    {val}", "yellow")


def empty(label):
    _print(f"\n  {label}", None, dim=True)


def breach(br):
    if br.get("found"):
        top = [f"{s['name']} ({s['date']})" for s in br["sources"][:5]]
        _print(f"\n  Breach data: {br['found']} databases ({', '.join(top)})", None, dim=True)
        if br.get("fields"):
            _print(f"  Exposed fields: {', '.join(br['fields'][:8])}", None, dim=True)


def blank():
    _print("", None)


# ─── composite display functions ─────────────────────────

def show_email(r):
    found("Registered on (multi-tool agreement):", r["both"])
    only(f"Only holehe found ({len(r['holehe_only'])}):", r["holehe_only"],
         extract=lambda x: x["domain"])
    only(f"Only user-scanner found ({len(r['user_scanner_only'])}):", r["user_scanner_only"])
    only(f"Only blackbird found ({len(r['blackbird_only'])}):", r["blackbird_only"])
    breach(r.get("breach", {}))
    if not any(v for k, v in r.items() if k != "breach"):
        empty("No results found.")


def show_username(r):
    labels = {
        "all_4":             "Username found on (all 4 tools agree):",
        "all_3_no_bb":       "user-scanner + sherlock + maigret (blackbird missed):",
        "all_3_no_mg":       "user-scanner + sherlock + blackbird (maigret missed):",
        "all_3_no_sh":       "user-scanner + maigret + blackbird (sherlock missed):",
        "all_3_no_us":       "sherlock + maigret + blackbird (user-scanner missed):",
        "us+sherlock":       "user-scanner + sherlock agree (others missed):",
        "us+maigret":        "user-scanner + maigret agree (others missed):",
        "us+blackbird":      "user-scanner + blackbird agree (others missed):",
        "sherlock+maigret":  "sherlock + maigret agree (others missed):",
        "sherlock+blackbird":"sherlock + blackbird agree (others missed):",
        "maigret+blackbird": "maigret + blackbird agree (others missed):",
        "us_only":           "Only user-scanner found:",
        "sherlock_only":     "Only sherlock found:",
        "maigret_only":      "Only maigret found:",
        "blackbird_only":    "Only blackbird found:",
    }
    for key, label in labels.items():
        only(label, r[key])
    breach(r.get("breach", {}))
    if not any(v for k, v in r.items() if k != "breach"):
        empty("No results found.")


def show_phone(r):
    pi = r["phonenumbers"]
    if "error" in pi:
        err(pi["error"])
        return

    section("Number info")
    item(f"{pi['e164']} -- {pi['type']} -- {pi['region']} ({pi['location']})")
    item_dim(f"Carrier: {pi['carrier']}  |  Timezone: {pi['timezone']}")

    pf = r["phoneinfoga"]
    sections = pf.get("sections", {})
    if sections:
        section("Web search (PhoneInfoga)")
        for name, urls in sections.items():
            domains = []
            for u in urls[:5]:
                m = re.search(r"site%3A([^+&]+)", u)
                if m:
                    domains.append(m.group(1))
            if domains:
                item(f"{name.replace('_', ' ').title()}: {', '.join(domains)}")

    ig = r["ignorant"]
    section("Platform check (Ignorant)")
    if ig:
        for site in ig:
            item(f"{site}: registered")
    else:
        item_dim("No known registrations found")
    breach(r.get("breach", {}))


def show_website(r):
    if not r:
        return
    for section_title, items in r.items():
        label = section_title.replace("_", " ").title()
        if isinstance(items, list):
            if items:
                section(label)
                for line in items:
                    item(str(line))
        elif isinstance(items, dict):
            if items:
                section(label)
                for k, v in items.items():
                    kv(k, v)


def show_metadata(r):
    if "error" in r:
        err(r["error"])
        return

    section("File")
    for k in ("file_name", "file_size", "file_type", "created", "modified"):
        if k in r:
            kv(k.replace("_", " ").title(), r[k])

    groups = {
        "Camera":     {"Make", "Model", "Software"},
        "Image":      {"ImageWidth", "ImageHeight", "Megapixels", "ISO", "FNumber",
                       "ExposureTime", "FocalLength", "Flash", "WhiteBalance", "ColorSpace"},
        "Timestamps": {"DateTimeOriginal", "CreateDate", "ModifyDate", "DateCreated"},
        "Document":   {"Author", "Creator", "Producer", "Title", "Subject", "Description",
                       "Keywords", "LastModifiedBy", "RevisionNumber", "Company", "Manager",
                       "Language", "Pages"},
        "Audio":      {"Artist", "Album", "Track", "Genre", "Duration", "SampleRate",
                       "Channels", "AudioBitrate"},
    }
    shown = {"file_name", "file_size", "file_type", "created", "modified"}
    for group_name, fields in groups.items():
        items = {k: r[k] for k in fields if k in r}
        if not items:
            continue
        section(group_name)
        for k, v in items.items():
            kv(k, v)
            shown.add(k)

    if "GPS" in r and isinstance(r["GPS"], dict):
        section("GPS Coordinates")
        for k, v in r["GPS"].items():
            kv(k, v)
            shown.add("GPS")

    leftover = {k: v for k, v in r.items()
                if k not in shown and not k.startswith("_") and k != "GPS"}
    if leftover:
        section("Extra")
        for k, v in sorted(leftover.items()):
            kv(k, v)


def show_ip(r):
    if "error" in r:
        err(r["error"])
        return

    geo = r.get("geo")
    if geo:
        section("Geolocation")
        kv("Country", geo.get("country"))
        kv("Region", geo.get("region"))
        kv("City", geo.get("city"))
        kv("ISP", geo.get("isp"))
        kv("Organization", geo.get("org"))
        kv("AS", geo.get("as"))
        kv("Location", geo.get("location"))
        kv("Timezone", geo.get("timezone"))

    section("DNS")
    kv("IP", r.get("ip"))
    if r.get("hostname"):
        kv("Hostname", r["hostname"])
    if r.get("a_records"):
        kv("A Records", ", ".join(r["a_records"]))

    who = r.get("whois")
    if who:
        section("WHOIS")
        for k, v in who.items():
            kv(k.replace("_", " ").title(), v)

    sd = r.get("shodan")
    if sd:
        section("Shodan")
        if sd.get("ports"):
            kv("Open ports", ", ".join(str(p) for p in sd["ports"]))
        if sd.get("hostnames"):
            kv("Hostnames", ", ".join(sd["hostnames"]))

    ports = r.get("open_ports")
    if ports:
        section("Open ports (nmap)")
        for p in ports:
            item(str(p))


def show_darkweb(r):
    if r.get("error"):
        err(r["error"])
        return

    ahmia = r.get("ahmia", [])
    section(f"Ahmia .onion index ({len(ahmia)} results)")
    if ahmia:
        for res in ahmia:
            title = res.get("title") or res.get("domain") or res.get("url", "")
            item(title)
            if res.get("url"):
                item_dim(f"    {res['url']}")
            if res.get("description"):
                item_dim(f"    {res['description'][:160]}")
            meta = res.get("domain", "")
            if res.get("last_seen"):
                meta = f"{meta}  |  last seen {res['last_seen']}".strip(" |")
            if meta:
                item_dim(f"    {meta}")
    else:
        item_dim("No .onion index results")

    if r.get("breach") is not None:
        breach(r["breach"])

    intelx = r.get("intelx")
    if intelx:
        total = intelx.get("total", len(intelx.get("results", [])))
        section(f"IntelX ({total} total)")
        for v in intelx.get("results", []):
            item(str(v))

    hibp = r.get("hibp")
    if hibp:
        found = hibp.get("breaches", [])
        section(f"HaveIBeenPwned ({len(found)} breaches)")
        if found:
            for x in found:
                item(f"{x.get('name', 'unknown')} ({x.get('date', 'n/a')})")
        else:
            item_dim("No known breaches")


def show_pwned(r):
    if r.get("error"):
        warn(f"    Could not check: {r['error']}")
        return
    if r.get("pwned"):
        warn(f"    This password has appeared in {r.get('count', '?')} known breaches.")
    else:
        good("    This password was not found in known breach collections.")


def show_opsec(r):
    _print("\n  OPSEC Health Check", _GREEN, bold=True)
    section("Connection")

    d = r.get("direct", {})
    if d:
        kv("Direct IP", f"{d['ip']} ({d.get('country', '?')} — {d.get('isp', '?')})")

    p = r.get("proxy")
    if p:
        kv("Proxy IP", f"{p['ip']} ({p.get('country', '?')} — {p.get('isp', '?')})")
    elif r.get("proxy_configured"):
        warn("    Proxy IP: Failed to reach API through proxy")

    anon = r.get("anonymized")
    if anon is True:
        good("    Anonymized: yes")
    elif anon is False:
        warn("    Anonymized: no — proxy may not be routing correctly")
    elif r.get("proxy_configured"):
        item_dim("Anonymized: unknown")

    section("DNS")
    dl = r.get("dns_leak")
    if dl == "protected":
        good("    Status: protected (routed through Tor)")
    elif dl == "unverified":
        warn("    Status: unverified — install torsocks for DNS protection")
    else:
        item_dim("Status: not applicable (no proxy configured)")

    section("System")
    if r.get("tor_available"):
        good("    Tor: available")
    else:
        item_dim("Tor: not installed")
    kv("Timezone", r.get("timezone", "unknown"))

    recs = r.get("recommendations")
    if recs:
        section("Recommendations")
        for rec in recs:
            if any(w in rec for w in ("exposed", "leak", "unreachable", "not hide", "DNS may")):
                warn(f"    {rec}")
            elif any(w in rec for w in ("active", "masked", "routed", "no leak")):
                good(f"    {rec}")
            else:
                item(rec)


def _section_hdr(text):
    _print(f"\n  {text}", _GREEN)


def show_investigation(r):
    inputs = r.get("inputs", {})
    results = r.get("results", {})
    correlations = r.get("correlations", [])

    _print("\n  ── Full Investigation Report ──", _GREEN, bold=True)

    _section_hdr("Known")
    for k in ("email", "username", "phone", "website"):
        if inputs.get(k) and k in results:
            kv(f"{k.capitalize():10}", inputs[k])

    # ── Email ──
    er = results.get("email", {})
    if "error" not in er and er:
        _section_hdr("Email")
        sites = []
        for key in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
            for item in er.get(key, []):
                if "domain" in item:
                    sites.append(item["domain"])
        if sites:
            _print(f"    Registered on {len(sites)} sites", _GREEN)
            _print(f"    {', '.join(sites[:12])}", _GREEN)
        br = er.get("breach", {})
        if br.get("found"):
            _print(f"    Breach: {br['found']} databases", "yellow")
        domain = inputs.get("email", "").split("@")[-1] if "@" in inputs.get("email", "") else None
        if domain:
            ips = r.get("entities", {}).get("ips", [])
            _print(f"    Domain: {domain}", None)
            if ips:
                _print(f"    IP: {ips[0]}", None, dim=True)

    # ── Username ──
    ur = results.get("username", {})
    if "error" not in ur and ur:
        _section_hdr("Username")
        all_sites = []
        us_keys = ["all_4", "all_3_no_bb", "all_3_no_mg", "all_3_no_sh", "all_3_no_us",
                   "us+sherlock", "us+maigret", "us+blackbird",
                   "sherlock+maigret", "sherlock+blackbird", "maigret+blackbird",
                   "us_only", "sherlock_only", "maigret_only", "blackbird_only"]
        for key in us_keys:
            for item in ur.get(key, []):
                if "domain" in item:
                    all_sites.append(item["domain"])
        if all_sites:
            _print(f"    Found on {len(all_sites)} platforms", _GREEN)
            for i in range(0, len(all_sites), 6):
                chunk = all_sites[i:i+6]
                _print(f"    {', '.join(chunk)}", _GREEN)
        br = ur.get("breach", {})
        if br.get("found"):
            _print(f"    Breach: {br['found']} databases", "yellow")

    # ── Phone ──
    pr = results.get("phone", {})
    if "error" not in pr and pr:
        _section_hdr("Phone")
        pi = pr.get("phonenumbers", {})
        if "error" not in pi:
            carrier = pi.get("carrier", "")
            region = pi.get("region", "")
            location = pi.get("location", "")
            parts = [p for p in [carrier, region, location] if p]
            _print(f"    {' · '.join(parts)}", None) if parts else None
        br = pr.get("breach", {})
        if br.get("found"):
            _print(f"    Breach: {br['found']} databases", "yellow")

    # ── Website ──
    wr = results.get("website", {})
    if "error" not in wr and wr:
        _section_hdr("Website")
        dns = wr.get("dns_records", {})
        a_recs = dns.get("A", "")
        if a_recs:
            _print(f"    IP: {a_recs}", None)
        ports = wr.get("port_scan", [])
        if ports:
            parts = ports[0].split(":", 1)[1].strip() if ":" in ports[0] else ports[0]
            _print(f"    Ports: {parts}", None)
        who = wr.get("whois", {})
        org = who.get("Organization", who.get("OrgName", ""))
        country = who.get("Country", "")
        if org:
            loc = f" ({country})" if country else ""
            _print(f"    WHOIS: {org}{loc}", None)
        who_emails = []
        for email_key in ("Extra Emails", "Email", "Tech Email", "Admin Email"):
            val = who.get(email_key, "")
            for e in val.split(","):
                e = e.strip()
                if e and "@" in e:
                    who_emails.append(e)
        if who_emails:
            _print(f"    WHOIS emails: {', '.join(who_emails[:4])}", "yellow")
        subs = wr.get("subdomains", [])
        crt = wr.get("crt_sh_subdomains", [])
        all_subs = sorted(set(subs) | set(crt))
        if all_subs:
            _print(f"    Subdomains: {', '.join(all_subs[:8])}", None)

    # ── Connections ──
    if correlations:
        _section_hdr("Connections")
        for c in correlations:
            icon = "✓" if c["type"] == "match" else "·"
            color = _GREEN if c["type"] == "match" else None
            _print(f"    {icon} {c['desc']}", color)
            if c.get("detail"):
                _print(f"      — {c['detail']}", None, dim=True)


# ─── internals ───────────────────────────────────────────

def _print(text, color=None, bold=False, dim=False):
    if _RICH:
        # markup=False: Spyglass output is plain text, so "[word]" must not be
        # interpreted as a Rich style tag (e.g. cases output, --usage text).
        # Colors still come through the style= argument.
        _con.print(text, style=_style(fg=color, bold=bold, dim=dim), markup=False)
    else:
        print(text)



