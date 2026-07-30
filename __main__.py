#!/usr/bin/env python3
import sys
import re

from .email import email
from .username import username
from .website import website
from .phone import phone
from .metadata import extract as metadata
from .ip import address as ip_address
from .opsec import health_check as opsec_check
from .investigation import investigate
from .utils import set_proxy
from .export import json_output as export_json, csv_output as export_csv
from . import display as ui


def _run_query(qtype, target, do_json=False, do_csv=False):
    """Run a single query, display results, export if requested."""
    qtype = qtype.lower()
    result = None

    if qtype == "email":
        ui.header("Checking email", target)
        result = email(target)
        ui.show_email(result)
    elif qtype == "username":
        ui.header("Checking username", target)
        result = username(target)
        ui.show_username(result)
    elif qtype == "phone":
        ui.header("Checking phone", target)
        result = phone(target)
        ui.show_phone(result)
    elif qtype == "website":
        ui.header("Website recon", target)
        result = website(target)
        ui.show_website(result)
    elif qtype == "metadata":
        ui.header("Metadata extraction", target)
        result = metadata(target)
        ui.show_metadata(result)
    elif qtype == "ip":
        ui.header("IP recon", target)
        result = ip_address(target)
        ui.show_ip(result)
    elif qtype == "opsec":
        result = opsec_check()
        ui.show_opsec(result)
    elif qtype == "investigation":
        ui.header("Full Investigation", "")
        raw_inputs = _parse_investigation_input(target)
        result = investigate(raw_inputs)
        ui.show_investigation(result)

    if result is not None:
        if do_json:
            export_json(result, target, qtype)
        if do_csv:
            export_csv(result, target, qtype)


def _parse_investigation_input(raw):
    """Parse input into a dict. Supports both formats:
      'email: x, username: y' (explicit keys)
      'x, y, z, w'           (positional: email, username, phone, website)
    """
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    inputs = {}

    # Check if any part has a colon — use key:value parsing
    if any(":" in p for p in parts):
        for part in parts:
            if ":" in part:
                key, val = part.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                if key in ("email", "username", "phone", "website") and val:
                    inputs[key] = val
        return inputs

    # Positional: email, username, phone, website
    keys = ["email", "username", "phone", "website"]
    for i, val in enumerate(parts):
        if i < len(keys) and val:
            inputs[keys[i]] = val
    return inputs


def _parse_args(argv):
    """Parse CLI flags and return (proxy, json, csv, positional_args)."""
    proxy = None
    do_json = False
    do_csv = False
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--proxy" and i + 1 < len(argv):
            proxy = argv[i + 1]
            i += 2
            continue
        if a.startswith("--proxy="):
            proxy = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--json":
            do_json = True
            i += 1
            continue
        if a == "--csv":
            do_csv = True
            i += 1
            continue
        positional.append(a)
        i += 1
    return proxy, do_json, do_csv, positional


def _run_investigation(do_json, do_csv):
    raw = ui.investigation_prompt()
    if raw:
        _run_query("investigation", raw, do_json, do_csv)


def _show_help():
    ui.section("Modules")
    ui.kv("1  Email",       "Check email against holehe + user-scanner + blackbird")
    ui.kv("2  Username",    "Search username across 400+ platforms (4 tools)")
    ui.kv("3  Phone",       "Validate & footprint a phone number")
    ui.kv("4  Website",     "Full recon: DNS, ports, headers, WHOIS, subdomains, dirs")
    ui.kv("5  Metadata",    "Extract metadata from a file (EXIF, GPS, docs, etc.)")
    ui.kv("6  IP recon",    "Geolocate, DNS, WHOIS, open ports, Shodan")
    ui.blank()
    ui.item_dim("Flags: --proxy URL  --json  --csv")
    ui.item_dim("Non-interactive: spyglass email user@example.com --json")


def _run_query_or_prompt(qtype, do_json, do_csv):
    if qtype == "opsec":
        _run_query("opsec", "", do_json, do_csv)
    else:
        target = ui.target_prompt(qtype)
        if target:
            _run_query(qtype, target, do_json, do_csv)


def _cli():
    proxy, do_json, do_csv, positional = _parse_args(sys.argv[1:])

    if proxy:
        set_proxy(proxy)

    # Non-interactive mode: command from args
    if len(positional) >= 2:
        if positional[0].lower() in ("email", "username", "phone", "website", "metadata", "ip"):
            _run_query(positional[0], positional[1], do_json, do_csv)
        else:
            ui.warn("Usage: spyglass email|username|phone|ip|website <target> [--json] [--csv] [--proxy URL]")
        return

    try:
        import readline
    except ImportError:
        pass

    ui.banner()
    if proxy:
        ui.info(f"Using proxy: {proxy}")

    state = "main"
    while True:
        try:
            inp = ui.menu_prompt(state)
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not inp:
            continue

        if state == "main":
            if inp == "1":     state = "identity"
            elif inp == "2":   state = "infra"
            elif inp == "3":   _run_investigation(do_json, do_csv)
            elif inp == "4":   state = "utils"
            elif inp == "5":   break
            else:              ui.warn("Invalid. Enter 1-5.")

        elif state == "identity":
            if inp == "1":     _run_query_or_prompt("email", do_json, do_csv)
            elif inp == "2":   _run_query_or_prompt("username", do_json, do_csv)
            elif inp == "3":   _run_query_or_prompt("phone", do_json, do_csv)
            elif inp == "4":   state = "main"
            else:              ui.warn("Invalid. Enter 1-4.")

        elif state == "infra":
            if inp == "1":     _run_query_or_prompt("website", do_json, do_csv)
            elif inp == "2":   _run_query_or_prompt("ip", do_json, do_csv)
            elif inp == "3":   state = "main"
            else:              ui.warn("Invalid. Enter 1-3.")

        elif state == "utils":
            if inp == "1":     _run_query("opsec", "", do_json, do_csv)
            elif inp == "2":   _run_query_or_prompt("metadata", do_json, do_csv)
            elif inp == "3":   _show_help()
            elif inp == "4":   ui.banner()
            elif inp == "5":   state = "main"
            else:              ui.warn("Invalid. Enter 1-5.")


if __name__ == "__main__":
    _cli()
