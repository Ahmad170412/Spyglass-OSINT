"""Markdown dossier generation for Spyglass results.

Renders any module's result dict into a clean, shareable Markdown report and
writes it to disk as ``spyglass_report_<qtype>_<target>_<ts>.md``.

This is the "reporting" layer: one flat, human-readable dossier per query so
recon findings can be saved, compared, and handed off between engagements.
"""

from __future__ import annotations

import os
import re
from datetime import datetime

from . import __version__
from . import display as _ui
from .utils import safe_name as _slug


def _breach_lines(br) -> list[str]:
    """Render a breach dict (from breach.check) as Markdown list items."""
    if not br or not br.get("found"):
        return ["- No known breach records found."]
    lines = [f"- **Breach found:** {br['found']} database(s)"]
    for src in br.get("sources", [])[:10]:
        name = src.get("name", "unknown") if isinstance(src, dict) else src
        date = src.get("date", "") if isinstance(src, dict) else ""
        lines.append(f"  - {name} ({date})" if date else f"  - {name}")
    fields = br.get("fields")
    if fields:
        lines.append(f"- **Exposed fields:** {', '.join(fields)}")
    return lines


def _section(title: str, items) -> list[str]:
    """Render a titled section from a list of strings or {domain,url} dicts."""
    lines = [f"### {title}", ""]
    if not items:
        lines += ["_None._", ""]
        return lines
    for it in items:
        if isinstance(it, dict):
            url = it.get("url")
            domain = it.get("domain", "")
            lines.append(f"- {domain}" + (f" — {url}" if url else ""))
        else:
            lines.append(f"- {it}")
    lines.append("")
    return lines


_ACRONYMS = {
    "ip": "IP", "isp": "ISP", "as": "AS", "asn": "ASN", "url": "URL",
    "e164": "E164", "gps": "GPS", "dns": "DNS", "spf": "SPF",
    "dmarc": "DMARC", "dnssec": "DNSSEC", "dkim": "DKIM", "san": "SAN",
    "tls": "TLS", "csp": "CSP", "mmh3": "MMH3", "sha256": "SHA256",
    "caa": "CAA", "whois": "WHOIS", "axfr": "AXFR", "ptr": "PTR",
    "api": "API", "cdn": "CDN", "crt": "CRT", "js": "JS", "css": "CSS",
    "html": "HTML", "ssl": "SSL", "id": "ID", "os": "OS",
}


def _key_label(key) -> str:
    """Human-readable label for a result key.

    Keys that already carry their own casing (GPSLatitude, IP, E164) are kept
    as-is; snake_case keys are title-cased per word (country_code -> Country
    Code) with known acronyms uppercased (spf_all -> SPF All).
    """
    s = str(key)
    if s.isupper() or any(c.isupper() for c in s[1:]):
        return s
    parts = [p for p in s.split("_") if p]
    labels = [_ACRONYMS.get(p.lower(), p.title()) for p in parts]
    return " ".join(labels) if labels else s


def _kv_section(title: str, data: dict) -> list[str]:
    """Render a titled section from a flat dict (None values omitted)."""
    lines = [f"### {title}", ""]
    for key, value in data.items():
        if value is None or value == "":
            continue
        lines.append(f"- **{_key_label(key)}:** {value}")
    lines.append("")
    return lines


# ─── per-module renderers ─────────────────────────────────

def _render_email(r: dict) -> list[str]:
    lines = []
    lines += _section("Registered on (multi-tool agreement)", r.get("both", []))
    for key, label in (
        ("holehe_only", "Only holehe found"),
        ("user_scanner_only", "Only user-scanner found"),
        ("blackbird_only", "Only blackbird found"),
    ):
        items = r.get(key, [])
        if items:
            lines += _section(label, items)
    lines.append("### Breach data")
    lines.append("")
    lines += _breach_lines(r.get("breach", {}))
    lines.append("")
    return lines


def _render_username(r: dict) -> list[str]:
    labels = {
        "all_4": "Username found on (all 4 tools agree)",
        "all_3_no_bb": "user-scanner + sherlock + maigret (blackbird missed)",
        "all_3_no_mg": "user-scanner + sherlock + blackbird (maigret missed)",
        "all_3_no_sh": "user-scanner + maigret + blackbird (sherlock missed)",
        "all_3_no_us": "sherlock + maigret + blackbird (user-scanner missed)",
        "us+sherlock": "user-scanner + sherlock agree (others missed)",
        "us+maigret": "user-scanner + maigret agree (others missed)",
        "us+blackbird": "user-scanner + blackbird agree (others missed)",
        "sherlock+maigret": "sherlock + maigret agree (others missed)",
        "sherlock+blackbird": "sherlock + blackbird agree (others missed)",
        "maigret+blackbird": "maigret + blackbird agree (others missed)",
        "us_only": "Only user-scanner found",
        "sherlock_only": "Only sherlock found",
        "maigret_only": "Only maigret found",
        "blackbird_only": "Only blackbird found",
    }
    lines = []
    for key, label in labels.items():
        items = r.get(key, [])
        if items:
            lines += _section(label, items)
    lines.append("### Breach data")
    lines.append("")
    lines += _breach_lines(r.get("breach", {}))
    lines.append("")
    return lines


def _render_phone(r: dict) -> list[str]:
    pi = r.get("phonenumbers", {})
    if not isinstance(pi, dict):
        pi = {}
    if pi.get("error"):
        return [f"> {pi['error']}", ""]
    lines = []
    lines += _kv_section("Number info", {
        "E164": pi.get("e164"),
        "International": pi.get("international"),
        "National": pi.get("national"),
        "Type": pi.get("type"),
        "Region": pi.get("region"),
        "Location": pi.get("location"),
        "Carrier": pi.get("carrier"),
        "Timezone": pi.get("timezone"),
        "Country code": pi.get("country_code"),
        "Valid": pi.get("valid"),
    })
    pf = r.get("phoneinfoga", {})
    sections = pf.get("sections", {}) if isinstance(pf, dict) else {}
    if sections:
        lines.append("### Web search (PhoneInfoga)")
        lines.append("")
        for name, urls in sections.items():
            lines.append(f"- **{name.replace('_', ' ').title()}:**")
            for u in urls[:5]:
                lines.append(f"  - {u}")
        lines.append("")
    ig = r.get("ignorant", [])
    lines.append("### Platform check (Ignorant)")
    lines.append("")
    if ig:
        for site in ig:
            lines.append(f"- {site}: registered")
    else:
        lines.append("_No known registrations found._")
    lines.append("")
    lines.append("### Breach data")
    lines.append("")
    lines += _breach_lines(r.get("breach", {}))
    lines.append("")
    return lines


def _render_website(r: dict) -> list[str]:
    lines = []
    if "error" in r:
        return [f"> {r['error']}", ""]
    dns = r.get("dns_records", {})
    if dns:
        lines += _kv_section("DNS records", dns)
    es = r.get("dns_email_security", {})
    if es:
        lines += _kv_section("DNS email security", es)
    wc = r.get("wildcard_dns", {})
    if wc:
        lines += _kv_section("Wildcard DNS", wc)
    if r.get("zone_transfer"):
        lines += _section("Zone transfer (AXFR)", r["zone_transfer"])
    subs = r.get("subdomains")
    if subs:
        lines += _section("Subdomains (unified)", subs)
    srcs = r.get("subdomain_sources", {})
    if srcs:
        lines += _kv_section("Subdomain sources", srcs)
    for key, label in (
        ("wayback_subdomains", "Subdomains (Wayback Machine)"),
        ("crt_sh_subdomains", "Subdomains (certificate transparency)"),
        ("http_probe", "HTTP probe (httpx)"),
        ("port_scan", "Port scan (nmap)"),
        ("shodan", "Shodan"),
        ("directories", "Directories (gobuster)"),
        ("interesting_files", "Interesting / exposed files"),
        ("robots", "robots.txt"),
        ("sitemap", "Sitemap"),
        ("js_endpoints", "JavaScript endpoints"),
        ("js_interesting", "JavaScript interesting strings"),
        ("reverse_dns", "Reverse DNS"),
        ("ptr_sweep", "Reverse DNS sweep (/24)"),
    ):
        items = r.get(key)
        if items:
            lines += _section(label, items)
    headers = r.get("http_headers", {})
    if headers:
        lines += _kv_section("HTTP headers", headers)
    sec = r.get("security_headers", {})
    if sec:
        lines += _kv_section("Security headers", sec)
    if r.get("cookies"):
        lines += _section("Cookies", r["cookies"])
    if r.get("csp_domains"):
        lines += _section("CSP domains", r["csp_domains"])
    if r.get("technologies"):
        lines += _section("Technologies", r["technologies"])
    fav = r.get("favicon", {})
    if fav:
        lines += _kv_section("Favicon", fav)
    tls = r.get("tls", {})
    if tls:
        lines += _kv_section("TLS", tls)
    whois = r.get("whois", {})
    if whois:
        lines += _kv_section("WHOIS", whois)
    hist = r.get("history", {})
    if hist:
        lines += _kv_section("Wayback history", hist)
    covered = {
        "dns_records", "dns_email_security", "wildcard_dns", "zone_transfer",
        "subdomains", "subdomain_sources", "wayback_subdomains",
        "crt_sh_subdomains", "http_probe", "port_scan", "shodan",
        "directories", "interesting_files", "robots", "sitemap",
        "js_endpoints", "js_interesting", "reverse_dns", "ptr_sweep",
        "http_headers", "security_headers", "cookies", "csp_domains",
        "technologies", "favicon", "tls", "whois", "history",
    }
    leftover = {k: v for k, v in r.items() if k not in covered and k != "error"}
    if leftover:
        lines += _render_generic(leftover)
    return lines


def _render_ip(r: dict) -> list[str]:
    lines = []
    if "error" in r:
        return [f"> {r['error']}", ""]
    geo = r.get("geo", {})
    if geo:
        lines += _kv_section("Geolocation", geo)
    dns = {}
    if r.get("ip"):
        dns["IP"] = r["ip"]
    if r.get("hostname"):
        dns["Hostname"] = r["hostname"]
    if r.get("a_records"):
        dns["A records"] = ", ".join(r["a_records"])
    if dns:
        lines += _kv_section("DNS", dns)
    whois = r.get("whois", {})
    if whois:
        lines += _kv_section("WHOIS", whois)
    shodan = r.get("shodan", {})
    if shodan:
        lines += _kv_section("Shodan", shodan)
    ports = r.get("open_ports")
    if ports:
        lines += _section("Open ports (nmap)", [str(p) for p in ports])
    return lines


def _render_metadata(r: dict) -> list[str]:
    lines = []
    if "error" in r:
        return [f"> {r['error']}", ""]
    file_info = {k: v for k, v in r.items()
                 if k in ("file_name", "file_size", "file_type", "created",
                          "modified", "accessed") and v}
    if file_info:
        lines += _kv_section("File", file_info)
    groups = {
        "Camera": ("Make", "Model", "Software"),
        "Image": ("ImageWidth", "ImageHeight", "Megapixels", "ISO", "FNumber",
                  "ExposureTime", "FocalLength", "Flash", "WhiteBalance", "ColorSpace"),
        "Timestamps": ("DateTimeOriginal", "CreateDate", "ModifyDate", "DateCreated"),
        "Document": ("Author", "Creator", "Producer", "Title", "Subject", "Description",
                     "Keywords", "LastModifiedBy", "RevisionNumber", "Company",
                     "Manager", "Language", "Pages"),
        "Audio": ("Artist", "Album", "Track", "Genre", "Duration", "SampleRate",
                  "Channels", "AudioBitrate"),
    }
    shown = set(file_info)
    for group_name, fields in groups.items():
        data = {k: r[k] for k in fields if k in r}
        if data:
            lines += _kv_section(group_name, data)
            shown.update(data)
    gps = r.get("GPS")
    if isinstance(gps, dict):
        lines += _kv_section("GPS coordinates", gps)
        shown.add("GPS")
    leftover = {k: v for k, v in r.items()
                if k not in shown and not k.startswith("_") and k != "GPS"}
    if leftover:
        lines += _kv_section("Extra", leftover)
    return lines


def _render_darkweb(r: dict) -> list[str]:
    lines = []
    if r.get("error"):
        return [f"> {r['error']}", ""]

    ahmia = r.get("ahmia", [])
    lines.append(f"### Ahmia .onion index ({len(ahmia)} results)")
    lines.append("")
    if ahmia:
        for res in ahmia:
            title = res.get("title") or res.get("domain") or res.get("url", "")
            url = res.get("url", "")
            lines.append(f"- **{title}**" + (f" — `{url}`" if url else ""))
            if res.get("description"):
                lines.append(f"  - {res['description'][:200]}")
            meta = res.get("domain", "")
            if res.get("last_seen"):
                meta = f"{meta} — last seen {res['last_seen']}".strip(" -")
            if meta:
                lines.append(f"  - {meta}")
    else:
        lines.append("_No .onion index results._")
    lines.append("")

    if r.get("breach") is not None:
        lines.append("### Breach data")
        lines.append("")
        lines += _breach_lines(r["breach"])
        lines.append("")

    intelx = r.get("intelx")
    if intelx:
        total = intelx.get("total", len(intelx.get("results", [])))
        lines.append(f"### IntelX ({total} total)")
        lines.append("")
        results = intelx.get("results", [])
        if results:
            for v in results:
                lines.append(f"- {v}")
        else:
            lines.append("_No selectors returned._")
        lines.append("")

    hibp = r.get("hibp")
    if hibp:
        found = hibp.get("breaches", [])
        lines.append(f"### HaveIBeenPwned ({len(found)} breaches)")
        lines.append("")
        if found:
            for x in found:
                name = x.get("name", "unknown")
                date = x.get("date", "")
                lines.append(f"- {name} ({date})" if date else f"- {name}")
        else:
            lines.append("_No known breaches._")
        lines.append("")
    return lines


def _render_opsec(r: dict) -> list[str]:
    lines = []
    direct = r.get("direct", {})
    if direct:
        lines += _kv_section("Direct connection", {
            "IP": direct.get("ip"),
            "Country": direct.get("country"),
            "ISP": direct.get("isp"),
        })
    proxy = r.get("proxy")
    if proxy:
        lines += _kv_section("Proxy", {
            "IP": proxy.get("ip"),
            "Country": proxy.get("country"),
            "ISP": proxy.get("isp"),
            "Anonymized": r.get("anonymized"),
        })
    elif r.get("proxy_configured"):
        lines += ["### Proxy", "", "- Configured but unreachable", ""]
    lines += _kv_section("Status", {
        "DNS leak": r.get("dns_leak"),
        "Tor available": r.get("tor_available"),
        "Timezone": r.get("timezone"),
    })
    recs = r.get("recommendations")
    if recs:
        lines += _section("Recommendations", recs)
    return lines


def _render_investigation(r: dict) -> list[str]:
    lines = []
    inputs = r.get("inputs", {})
    if inputs:
        lines += _kv_section("Known inputs", inputs)
    entities = r.get("entities", {})
    if entities:
        lines.append("### Entities found")
        lines.append("")
        for kind, vals in entities.items():
            lines.append(f"- **{kind.capitalize()}:** {', '.join(vals)}")
        lines.append("")
    corr = r.get("correlations", [])
    lines.append("### Correlations")
    lines.append("")
    if corr:
        for c in corr:
            desc = c.get("desc", "")
            detail = c.get("detail")
            lines.append(f"- **{c.get('type', 'info').upper()}:** {desc}"
                         + (f" — `{detail}`" if detail else ""))
    else:
        lines.append("_No cross-module correlations found._")
    lines.append("")
    results = r.get("results", {})
    for qtype, res in results.items():
        if isinstance(res, dict) and res.get("error"):
            lines.append(f"### {qtype.capitalize()}")
            lines.append("")
            lines.append(f"> {res['error']}")
            lines.append("")
            continue
        lines.append(f"## {qtype.capitalize()}")
        lines.append("")
        if qtype == "email" and isinstance(res, dict):
            lines += _render_email(res)
        elif qtype == "username" and isinstance(res, dict):
            lines += _render_username(res)
        elif qtype == "phone" and isinstance(res, dict):
            lines += _render_phone(res)
        elif qtype == "website" and isinstance(res, dict):
            lines += _render_website(res)
        elif isinstance(res, dict):
            lines += _render_generic(res)
    return lines


def _render_generic(data: dict, depth: int = 0) -> list[str]:
    """Fallback renderer for unknown dict-shaped results."""
    lines = []
    for key, value in data.items():
        if key == "error":
            lines.append(f"> {value}")
            continue
        if isinstance(value, dict):
            lines.append(f"### {str(key).replace('_', ' ').title()}")
            lines.append("")
            lines += _render_generic(value, depth + 1)
        elif isinstance(value, list):
            lines += _section(str(key).replace("_", " ").title(), value)
        elif value is not None and value != "":
            lines.append(f"- **{key}:** {value}")
    if not lines:
        lines = ["_No data._", ""]
    return lines


# ─── public API ───────────────────────────────────────────

def render(result, qtype: str, target: str) -> str:
    """Render a Spyglass result dict as a Markdown dossier string."""
    renderers = {
        "email": _render_email,
        "username": _render_username,
        "phone": _render_phone,
        "website": _render_website,
        "ip": _render_ip,
        "metadata": _render_metadata,
        "opsec": _render_opsec,
        "darkweb": _render_darkweb,
        "investigation": _render_investigation,
    }
    body = renderers.get(qtype, _render_generic)(result if isinstance(result, dict) else {})
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# Spyglass Report — {qtype}",
        "",
        f"- **Target:** `{target}`",
        f"- **Generated:** {now}",
        f"- **Spyglass version:** {__version__}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines + body)


def write_report(result, qtype: str, target: str, output_dir: str = ".") -> str:
    """Write the Markdown dossier to disk and return its path.

    The file is named ``spyglass_report_<qtype>_<target>_<timestamp>.md`` in
    ``output_dir`` (created if missing).
    """
    path = os.path.join(
        output_dir,
        f"spyglass_report_{_slug(qtype)}_{_slug(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
    )
    os.makedirs(output_dir, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(render(result, qtype, target))
        f.write("\n")
    _ui.info(f"Saved {path}")
    return path
