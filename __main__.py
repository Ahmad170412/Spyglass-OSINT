#!/usr/bin/env python3
import sys
import re
import time

from .email import email
from .username import username
from .website import website
from .phone import phone, show_phone
from .utils import show_breach


# ─── CLI display ─────────────────────────────────────────

def _print_group(header, items, delay=1):
    if not items:
        return
    print(f"\n  {header}")
    for it in items:
        print(f"    {it.get('url', it['domain'])}")
        time.sleep(delay)


def _show_email(r):
    _print_group("Sites where email is registered (multi-tool agreement):", r["both"])
    _print_group(f"Only holehe found ({len(r['holehe_only'])}):", r["holehe_only"])
    _print_group(f"Only user-scanner found ({len(r['user_scanner_only'])}):", r["user_scanner_only"])
    _print_group(f"Only blackbird found ({len(r['blackbird_only'])}):", r["blackbird_only"])
    show_breach(r.get("breach", {}))
    if not any(v for k, v in r.items() if k != "breach"):
        print("\n  No results found.")


def _show_username(r):
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
        _print_group(label, r[key])
    show_breach(r.get("breach", {}))
    if not any(v for k, v in r.items() if k != "breach"):
        print("\n  No results found.")


def _cli():
    try:
        inp = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not inp:
        return

    em = re.match(r"^email\s+(\S+)", inp, re.IGNORECASE)
    um = re.match(r"^username\s+(\S+)", inp, re.IGNORECASE)
    wm = re.match(r"^website\s+(\S+)", inp, re.IGNORECASE)
    pm = re.match(r"^phone\s+(\S+)", inp, re.IGNORECASE)

    if em:
        print(f"\n[*] Checking email: {em.group(1)} (4 tools in parallel)")
        _show_email(email(em.group(1)))

    elif um:
        print(f"\n[*] Checking username: {um.group(1)} (5 tools in parallel)")
        _show_username(username(um.group(1)))

    elif wm:
        website(wm.group(1))

    elif pm:
        print(f"\n[*] Checking phone: {pm.group(1)} (4 tools in parallel)")
        show_phone(phone(pm.group(1)))

    else:
        print("Usage: email <target> OR username <target> OR phone <target> OR website <target>")


if __name__ == "__main__":
    _cli()
