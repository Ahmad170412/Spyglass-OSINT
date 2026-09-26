#!/usr/bin/env python3
import re
import concurrent.futures

import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_tz
from .utils import _run, _check_tool, _PHONEINFOGA, _IGNORANT
from .breach import check as _breach_check


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
    out = _run(["phoneinfoga", "scan", "-n", number, "-o", "json"], timeout=30)
    if not out:
        return {}
    try:
        data = json.loads(out)
        return _parse_phoneinfoga_json(data)
    except Exception:
        return {}


def _parse_phoneinfoga_json(data):
    """Parse PhoneInfoga JSON output into the expected dict structure."""
    info = {}
    # PhoneInfoga JSON structure varies by version; handle common patterns
    if isinstance(data, dict):
        # Single result object
        for key in ("raw", "local", "e164", "international", "country"):
            if key in data:
                info[key] = data[key]
        # Sections with URLs
        sections = {}
        for key in ("osint", "social", "cnam", "other"):
            if key in data and isinstance(data[key], list):
                urls = []
                for item in data[key]:
                    if isinstance(item, dict) and item.get("url"):
                        urls.append(item["url"])
                    elif isinstance(item, str):
                        urls.append(item)
                if urls:
                    sections[key] = urls
        if sections:
            info["sections"] = sections
    elif isinstance(data, list):
        # Array of results - merge them
        for item in data:
            parsed = _parse_phoneinfoga_json(item)
            for k, v in parsed.items():
                if k == "sections":
                    info.setdefault("sections", {}).update(v)
                elif k not in info:
                    info[k] = v
    return info


def _ignorant(number):
    """Ask ignorant which sites have registered this number.

    Derives the country code and local number from phonenumbers instead of
    guessing from the leading digits: the old loop kept overwriting ``cc``, so
    +65 8526 0980 became country code "658" with local "585260980".
    """
    if not _check_tool("ignorant", _IGNORANT):
        return []
    cc = ""
    local = ""
    try:
        parsed = phonenumbers.parse(number, None)
        if phonenumbers.is_possible_number(parsed):
            cc = str(parsed.country_code)
            local = str(parsed.national_number)
    except phonenumbers.NumberParseException:
        digits = re.sub(r"\D", "", number)
        if digits:
            cc = digits[0]
            local = digits[1:]
    if not local:
        return []
    out = _run(["ignorant", "--only-used", f"+{cc}", local], timeout=30)
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



