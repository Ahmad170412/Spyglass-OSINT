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
    "[2]  Infrastructure        (website, IP, ASN)",
    "[3]  Utilities             (OPSEC, metadata, help, clear)",
    "[4]  Exit",
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
        "[3]  ASN / routing",
        "[4]  Back",
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
    "main":     "Select [1-4]",
    "identity": "Select [1-5]",
    "infra":    "Select [1-4]",
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
        "asn":      "Enter IP, prefix, or AS number",
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

def _trunc(value, limit=54):
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _rejection_note(result, noun="candidates"):
    """Explain a short result set instead of leaving the drop unexplained.

    Verification discards bot walls, app shells, catch-all routes and pages that
    never mention the search term. Showing only what survived makes a search that
    found six and kept one indistinguishable from one that found one.
    """
    rejected = result.get("rejected") or {}
    if not rejected:
        return
    total = sum(rejected.values())
    seen = result.get("candidates")
    prefix = f"{total} of {seen} {noun}" if seen else f"{total} {noun}"
    _print(f"\n  Filtered: {prefix} fetched but not real profiles", None, dim=True)
    for why, n in sorted(rejected.items(), key=lambda kv: -kv[1]):
        _print(f"      {n:>4}  {why}", None, dim=True)


def show_email(r):
    found("Registered on (multi-tool agreement):", r["both"])
    only(f"Only holehe found ({len(r['holehe_only'])}):", r["holehe_only"],
         extract=lambda x: x["domain"])
    only(f"Only user-scanner found ({len(r['user_scanner_only'])}):", r["user_scanner_only"])
    only(f"Only blackbird found ({len(r['blackbird_only'])}):", r["blackbird_only"])
    _show_gravatar(r.get("gravatar"))
    _rejection_note(r)
    breach(r.get("breach", {}))
    if not any(v for k, v in r.items()
               if k not in ("breach", "gravatar", "rejected", "candidates")):
        empty("No results found.")


def _show_gravatar(gv):
    """Render the Gravatar block.

    The linked accounts are the point: they are handles on other services that
    the registration checkers do not return, so they feed straight back into the
    username module.
    """
    if not gv:
        return
    if gv.get("status") == "error":
        section("Gravatar")
        item_dim(f"  {gv.get('reason', 'lookup failed')}")
        return
    if gv.get("status") == "unavailable":
        section("Gravatar")
        item_dim(f"  unavailable: {gv.get('reason', 'unknown')}")
        return
    if not gv.get("found"):
        section("Gravatar")
        item_dim("  No public Gravatar profile for this address")
        return

    section("Gravatar — public profile")
    kv("Name", gv.get("display_name") or gv.get("username") or "-")
    if gv.get("username") and gv["username"] != gv.get("display_name"):
        kv("Username", gv["username"])
    if gv.get("location"):
        kv("Location", gv["location"])
    if gv.get("about"):
        item_dim(f"  {gv['about'][:150]}")
    kv("Profile", gv.get("profile_url", ""))
    if gv.get("note"):
        item_dim(f"  {gv['note']}")

    accounts = gv.get("accounts") or []
    if accounts:
        found("Linked accounts (feed these to the username module):", accounts,
              extract=lambda a: f"{a['service']}: {a['username']}  {a['url']}")


def show_username(r):
    from .username import SECTION_LABELS
    verdict = r.get("verdict")
    if verdict:
        if verdict.startswith("No verified"):
            empty(verdict)
        else:
            _print(f"\n  {verdict}", "yellow" if "unconfirmed" in verdict else None)
    for key, label in SECTION_LABELS.items():
        if key == "breach":
            breach(r.get("breach", {}))
            continue
        only(label + ":", r.get(key))
    _show_details(r.get("details"))
    _rejection_note(r)
    if not any(v for k, v in r.items()
               if k not in ("breach", "rejected", "candidates", "verdict",
                            "details")):
        empty("No results found.")


def _show_details(details):
    """Per-platform data extracted by maigret.

    maigret resolves considerably more than a profile URL — a YouTube hit
    yields the channel id, real name, bio and avatar — and reducing that to a
    bare link throws away the most actionable part of the result.
    """
    if not details:
        return
    section("Extracted account data")
    for domain, fields in details.items():
        item(domain)
        for key, value in fields.items():
            # Truncate to keep the value inside the column; a long avatar URL
            # otherwise wraps to column zero and breaks the alignment below it.
            label = key[:22].ljust(22)
            _print(f"      {label} {_trunc(value, 54)}", None, dim=True)


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
        if section_title == "vulns":
            _show_vulns(items)
            continue
        if section_title == "passive_dns":
            _show_passive_dns(items)
            continue
        if section_title == "observed":
            _show_observed(items)
            continue
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


def _show_passive_dns(pdns):
    """Historical resolutions, as a table.

    Rendered explicitly because the generic walker would print the whole
    ``resolved`` map as one value, which is unreadable and hides the one thing
    worth seeing: a name whose address has not moved in a long time.
    """
    if not isinstance(pdns, dict):
        return
    hosts = pdns.get("hosts") or 0
    records = pdns.get("records") or 0
    section(f"Passive DNS — {hosts} name(s), {records} record(s)")
    for name, recs in (pdns.get("resolved") or {}).items():
        for rec in recs[:6]:
            seen = rec.get("last_seen") or "?"
            rtype = (rec.get("type") or "").lower()
            item_dim(f"  {name} -> {rec.get('ip')}"
                     + (f" ({rtype})" if rtype else "")
                     + f"  last seen {seen}")
        if len(recs) > 6:
            item_dim(f"    …and {len(recs) - 6} more for {name}")


def _show_observed(items):
    """urlscan.io page observations, as a table."""
    section("Observed pages (urlscan.io)")
    for o in items:
        when = o.get("scanned") or "?"
        bits = [b for b in (o.get("ip"), o.get("asn"), o.get("server")) if b]
        item(f"{o.get('url') or '?'}")
        item_dim(f"  {when}  {' | '.join(bits)}")
        if o.get("title"):
            item_dim(f"  {o['title']}")


def _show_vulns(vn):
    """Render the CVE block, which is structured rather than flat."""
    count = vn.get("cve_count", 0)
    section(f"Known Vulnerabilities — {count} CVE{'s' if count != 1 else ''}")
    if vn.get("status") == "error":
        item_dim(f"  lookup failed: {vn.get('reason', 'unknown')}")
        return
    if not count:
        item_dim("  No known CVEs for the versions detected")
        return
    for c in vn.get("cves", []):
        sev = (c.get("severity") or "").upper()
        colour = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow"}.get(sev)
        score = f" {c['score']}" if c.get("score") is not None else ""
        _print(f"\n    {c['id']}  {sev}{score}  —  "
               f"{c.get('product')} {c.get('version')}", colour, bold=True)
        if c.get("affected"):
            item_dim(f"      affected: {'; '.join(c['affected'])}")
        if c.get("description"):
            item_dim(f"      {c['description'][:150]}")
        for ref in (c.get("references") or [])[:2]:
            item_dim(f"      {ref}")
    if vn.get("skipped"):
        item_dim(f"\n  Not queried (cap reached): {', '.join(vn['skipped'])}")
    item_dim("\n  Affected ranges are NVD's structured data. Advisory prose keeps")
    item_dim("  its original wording after NVD widens a range, so trust the range.")


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
        if geo.get("_source"):
            kv("Source", geo["_source"].split(" (")[0])
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

    sd = r.get("internetdb")
    if sd:
        section("InternetDB (Shodan)")
        if sd.get("ports"):
            kv("Open ports", ", ".join(str(p) for p in sd["ports"]))
        if sd.get("hostnames"):
            kv("Hostnames", ", ".join(sd["hostnames"]))
        if sd.get("cpes"):
            kv("Products", ", ".join(sd["cpes"]))
        if sd.get("tags"):
            kv("Tags", ", ".join(sd["tags"]))


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


def show_asn(r):
    if "error" in r:
        err(r["error"])
        if r.get("hint"):
            item_dim(f"    {r['hint']}")
        return

    section("Routing")
    if r.get("prefix"):
        kv("Prefix", r["prefix"])
    kv("Query", f"{r.get('query', '?')} ({r.get('query_type', '?')})")
    if "announced" in r:
        if r["announced"]:
            kv("Announced", "yes")
        else:
            warn("    Announced: no")
            if r.get("unannounced_reason"):
                item_dim(f"      {r['unannounced_reason']}")

    origins = r.get("origin_asns") or []
    if origins:
        section("Origin AS")
        for o in origins:
            holder = o.get("holder") or "unknown holder"
            item(f"AS{o['asn']}  {holder}")

    if r.get("asn") and r.get("holder"):
        section("Autonomous System")
        kv("AS", f"AS{r['asn']}")
        kv("Holder", r["holder"])

    reg = r.get("registry")
    if reg:
        section("Registry")
        kv("Range", reg.get("resource"))
        kv("Allocation", reg.get("desc"))
        kv("Registry", reg.get("name"))

    if r.get("covering_prefixes"):
        section("Covering Prefixes")
        item_dim("less-specific prefixes above the matched one")
        for p in r["covering_prefixes"]:
            item(p)

    rpki = r.get("rpki")
    if rpki:
        section("RPKI")
        for entry in rpki:
            status = str(entry.get("status", "unknown")).lower()
            line = f"AS{entry.get('origin_asn')}  {status}"
            if status == "valid":
                good(f"    {line}")
            elif status == "invalid":
                # A conflicting ROA is the one finding in this tool that reports
                # a weakness rather than a fact, so it is called out in colour.
                warn(f"    {line}  — a ROA names a different origin")
            else:
                item(f"{line}  — no covering ROA")
    elif r.get("rpki_note"):
        section("RPKI")
        item_dim(r["rpki_note"])
    for err_msg in r.get("rpki_errors") or []:
        item_dim(f"RPKI unavailable: {err_msg}")

    fp = r.get("announced_prefixes")
    if fp:
        section("Announced Footprint")
        kv("Total prefixes", fp.get("total"))
        if fp.get("ipv4_total") is not None:
            kv("IPv4 / IPv6", f"{fp['ipv4_total']} / {fp['ipv6_total']}")
        for e in fp.get("rpki_errors") or []:
            item_dim(e)
        if fp.get("error"):
            item_dim(fp["error"])
        if fp.get("note"):
            item_dim(fp["note"])
        for p in fp.get("sample") or []:
            item_dim(p)


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


# ─── internals ───────────────────────────────────────────

def _print(text, color=None, bold=False, dim=False):
    if _RICH:
        # markup=False: Spyglass output is plain text, so "[word]" must not be
        # interpreted as a Rich style tag (e.g. cases output, --usage text).
        # Colors still come through the style= argument.
        _con.print(text, style=_style(fg=color, bold=bold, dim=dim), markup=False)
    else:
        print(text)



