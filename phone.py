#!/usr/bin/env python3
import re
import concurrent.futures

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_tz
from .utils import _run, _breach_check, show_breach, _check_tool, _PHONEINFOGA, _IGNORANT


_PHONE_TYPE = {
    0: "fixed-line",
    1: "mobile",
    2: "fixed-line-or-mobile",
    3: "toll-free",
    4: "premium-rate",
    5: "shared-cost",
    6: "VoIP",
    7: "personal-number",
    8: "pager",
    9: "voicemail",
}


# ─── tool runners ─────────────────────────────────────────

def _phonenumbers_info(number):
    try:
        x = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException:
        return {"error": "Unable to parse number"}
    if not phonenumbers.is_possible_number(x):
        return {"error": "Impossible phone number"}
    region = phonenumbers.region_code_for_number(x)
    return {
        "valid":         phonenumbers.is_valid_number(x),
        "country_code":  x.country_code,
        "region":        region,
        "location":      geocoder.description_for_number(x, "en"),
        "carrier":       carrier.name_for_number(x, "en") or "N/A",
        "timezone":      ", ".join(pn_tz.time_zones_for_number(x)),
        "type":          _PHONE_TYPE.get(phonenumbers.number_type(x), "unknown"),
        "e164":          phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national":      phonenumbers.format_number(x, phonenumbers.PhoneNumberFormat.NATIONAL),
    }


def _phoneinfoga(number):
    if not _check_tool("phoneinfoga", _PHONEINFOGA):
        return {}
    out = _run(["phoneinfoga", "scan", "-n", number], timeout=30)
    info = {}
    m = re.search(r"Raw local: (\S+)", out)
    if m: info["raw"] = m.group(1)
    m = re.search(r"Local: (.+)", out)
    if m: info["local"] = m.group(1).strip()
    m = re.search(r"E164: (\S+)", out)
    if m: info["e164"] = m.group(1)
    m = re.search(r"International: (\S+)", out)
    if m: info["international"] = m.group(1)
    m = re.search(r"Country: (\S+)", out)
    if m: info["country"] = m.group(1)

    sections = {}
    current = None
    for line in out.split("\n"):
        s = re.match(r"^([A-Za-z /]+):$", line.strip())
        if s:
            current = s.group(1).strip().lower().replace(" ", "_")
            sections[current] = []
        elif current and line.strip().startswith("URL:"):
            url = line.strip()[4:].strip()
            sections[current].append(url)

    info["sections"] = sections
    return info


def _ignorant(number):
    if not _check_tool("ignorant", _IGNORANT):
        return []
    cc = ""
    digits = re.sub(r"\D", "", number)
    if number.startswith("+"):
        for i in range(1, 4):
            part = digits[:i]
            if part:
                cc = part
    if not cc:
        cc = digits[0] if digits else ""
    nums = digits[1:] if number.startswith("+") else digits
    if not nums:
        return []
    out = _run(["ignorant", "--only-used", f"+{cc}", nums], timeout=30)
    return re.findall(r"^\[\+\]\s+([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", out, re.MULTILINE)


# ─── public API ───────────────────────────────────────────

def phone(target):
    """Run phonenumbers + PhoneInfoga + ignorant + breach check on a phone
    number in parallel.

    Returns dict with validation info, carrier data, web search URLs,
    platform list, and breach data.
    """
    digits = re.sub(r"\D", "", target)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pi_fut  = pool.submit(_phonenumbers_info, target)
        pf_fut  = pool.submit(_phoneinfoga, target)
        ig_fut  = pool.submit(_ignorant, target)
        br_fut  = pool.submit(_breach_check, target, "phone")
        pi_info = pi_fut.result()
        pf_info = pf_fut.result()
        ig_found = ig_fut.result()
        br       = br_fut.result()

    return {
        "phonenumbers": pi_info,
        "phoneinfoga":  pf_info,
        "ignorant":     ig_found,
        "breach":       br,
    }


# ─── CLI display ──────────────────────────────────────────

def show_phone(r):
    pi = r["phonenumbers"]
    pf = r["phoneinfoga"]
    ig = r["ignorant"]

    if "error" in pi:
        print(f"    {pi['error']}")
        return

    print("  [1/3] Number info...")
    print(f"    {pi['e164']} — {pi['type']} — {pi['region']} ({pi['location']})")
    print(f"    Carrier: {pi['carrier']}  |  Timezone: {pi['timezone']}")

    sections = pf.get("sections", {})
    if sections:
        print("\n  [2/3] Web search (PhoneInfoga)...")
        for section, urls in sections.items():
            label = section.replace("_", " ").title()
            domains = []
            for u in urls[:5]:
                m = re.search(r"site%3A([^+&]+)", u)
                if m:
                    domains.append(m.group(1))
            if domains:
                print(f"    {label}: {', '.join(domains)}")

    if ig:
        print("\n  [3/3] Platform check (Ignorant)...")
        for site in ig:
            print(f"    {site}: registered ✓")
    else:
        print("\n  [3/3] Platform check (Ignorant)...")
        print("    No known registrations found")
    show_breach(r.get("breach", {}))
