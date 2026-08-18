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
from .darkweb import darkweb, pwned_password
from .utils import set_proxy
from .export import json_output as export_json, csv_output as export_csv
from . import store
from . import display as ui
from . import __version__


_USAGE = ("Usage: spyglass email|username|phone|ip|website|metadata|darkweb|investigation <target> "
          "[--type TYPE] [--json] [--csv] [--report] [--store] [--proxy URL]\n"
          "       spyglass darkweb --password   (check a password against Pwned Passwords)\n"
          "       spyglass cases [list|diff|timeline|export] [<target>] [--type TYPE]")


def _run_query(qtype, target, do_json=False, do_csv=False, do_report=False, sub_type=None, do_store=False):
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
    elif qtype == "darkweb":
        ui.header("Dark web search", target)
        result = darkweb(target, sub_type)
        ui.show_darkweb(result)
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
        if do_report:
            from . import report
            report.write_report(result, qtype, target)
        if do_store:
            run_id = store.store_result(result, qtype, target)
            if run_id:
                ui.info(f"Stored run #{run_id} ({qtype} / {target})")
            else:
                ui.warn("Could not store result.")


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
    """Parse CLI flags and return (proxy, json, csv, report, type, password, store, positional)."""
    proxy = None
    do_json = False
    do_csv = False
    do_report = False
    type_hint = None
    do_password = False
    do_store = False
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--version":
            print(f"Spyglass {__version__}")
            raise SystemExit(0)
        if a == "--password":
            do_password = True
            i += 1
            continue
        if a == "--store":
            do_store = True
            i += 1
            continue
        if a == "--type" and i + 1 < len(argv):
            type_hint = argv[i + 1]
            i += 2
            continue
        if a.startswith("--type="):
            type_hint = a.split("=", 1)[1]
            i += 1
            continue
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
        if a == "--report":
            do_report = True
            i += 1
            continue
        positional.append(a)
        i += 1
    return proxy, do_json, do_csv, do_report, type_hint, do_password, do_store, positional


def _run_investigation(do_json, do_csv, do_report=False, do_store=False):
    raw = ui.investigation_prompt()
    if raw:
        _run_query("investigation", raw, do_json, do_csv, do_report, do_store=do_store)


def _run_password_check():
    import getpass
    pw = getpass.getpass("Password to check (hidden, never stored): ")
    if not pw:
        ui.warn("No password entered.")
        return
    ui.header("Pwned Passwords check", "")
    res = pwned_password(pw)
    ui.show_pwned(res)
    # The password and hash are deliberately never logged or exported.


def _show_help():
    ui.section("Modules")
    ui.kv("1  Email",       "Check email against holehe + user-scanner + blackbird")
    ui.kv("2  Username",    "Search username across 400+ platforms (4 tools)")
    ui.kv("3  Phone",       "Validate & footprint a phone number")
    ui.kv("4  Website",     "Full recon: DNS, ports, headers, WHOIS, subdomains, dirs")
    ui.kv("5  Metadata",    "Extract metadata from a file (EXIF, GPS, docs, etc.)")
    ui.kv("6  IP recon",    "Geolocate, DNS, WHOIS, open ports, Shodan")
    ui.blank()
    ui.item_dim("Dark web:  spyglass darkweb <target> [--type email|username|phone|domain|ip]")
    ui.item_dim("Password:  spyglass darkweb --password  (Pwned Passwords k-anonymity)")
    ui.item_dim("Flags: --proxy URL  --json  --csv  --report  --store  --version")
    ui.item_dim("Cases: spyglass cases [list|diff|timeline|export] <target> [--type TYPE]")
    ui.item_dim("Non-interactive: spyglass email user@example.com --json --report")


def _run_query_or_prompt(qtype, do_json, do_csv, do_report=False, do_store=False):
    if qtype == "opsec":
        _run_query("opsec", "", do_json, do_csv, do_report, do_store=do_store)
    else:
        target = ui.target_prompt(qtype)
        if target:
            _run_query(qtype, target, do_json, do_csv, do_report, do_store=do_store)


def _run_cases(subcommand, target=None, qtype=None, do_json=False):
    """Handle `spyglass cases ...` — list, diff, timeline, export."""
    subcommand = (subcommand or "list").lower()

    if subcommand == "list":
        cases = store.list_cases()
        if not cases:
            ui.empty("No stored cases. Run a query with --store first.")
            return
        ui.section("Stored cases")
        for c in cases:
            ui.kv(f"{c['target']}  [{c['qtype']}]", f"{c['count']} run(s), last {c['last']}")
        return

    if not target:
        ui.warn(f"Usage: spyglass cases {subcommand} <target> [--type TYPE]")
        return

    if subcommand == "diff":
        d = store.diff(target, qtype)
        if d.get("error"):
            ui.warn(d["error"])
            return
        ui.section(f"Diff {target}" + (f" ({qtype})" if qtype else ""))
        ui.kv("From", d["old_run"])
        ui.kv("To", d["new_run"])
        if d["added"]:
            ui.found("Added", d["added"], extract=lambda x: x)
        if d["removed"]:
            ui.only("Removed", d["removed"], extract=lambda x: x)
        if not d["added"] and not d["removed"]:
            ui.item("No entity changes between these two runs.")
        if do_json:
            export_json(d, target, "cases_diff")

    elif subcommand == "timeline":
        rows = store.timeline(target, qtype)
        if not rows:
            ui.empty("No stored runs for this target.")
            return
        ui.section(f"Timeline {target}" + (f" ({qtype})" if qtype else ""))
        for row in rows:
            ui.kv(f"{row['run_at']}  [{row['qtype']}]", f"{len(row['entities'])} entities")

    elif subcommand == "export":
        profile = store.export_profile(target)
        if not profile.get("results"):
            ui.warn(f"No stored runs for target: {target}")
            return
        export_json(profile, target, "profile")
        ui.section(f"Profile exported for {target}")

    else:
        ui.warn("Usage: spyglass cases [list|diff|timeline|export] [<target>] [--type TYPE]")


def _cli():
    proxy, do_json, do_csv, do_report, type_hint, do_password, do_store, positional = _parse_args(sys.argv[1:])

    if proxy:
        set_proxy(proxy)

    if do_password:
        _run_password_check()
        return

    # Cases subcommand (store queries).
    if positional and positional[0].lower() == "cases":
        sub = positional[1].lower() if len(positional) > 1 else "list"
        target = positional[2] if len(positional) > 2 else None
        _run_cases(sub, target, type_hint, do_json)
        return

    # Non-interactive mode: command from args
    if len(positional) >= 2:
        qtype = positional[0].lower()
        if qtype in ("email", "username", "phone", "website", "metadata", "ip",
                     "investigation", "darkweb"):
            target = " ".join(positional[1:]) if qtype == "investigation" else positional[1]
            _run_query(qtype, target, do_json, do_csv, do_report,
                       sub_type=type_hint, do_store=do_store)
        else:
            ui.warn(_USAGE)
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
            elif inp == "3":   _run_investigation(do_json, do_csv, do_report, do_store)
            elif inp == "4":   state = "utils"
            elif inp == "5":   break
            else:              ui.warn("Invalid. Enter 1-5.")

        elif state == "identity":
            if inp == "1":     _run_query_or_prompt("email", do_json, do_csv, do_report, do_store)
            elif inp == "2":   _run_query_or_prompt("username", do_json, do_csv, do_report, do_store)
            elif inp == "3":   _run_query_or_prompt("phone", do_json, do_csv, do_report, do_store)
            elif inp == "4":   _run_query_or_prompt("darkweb", do_json, do_csv, do_report, do_store)
            elif inp == "5":   state = "main"
            else:              ui.warn("Invalid. Enter 1-5.")

        elif state == "infra":
            if inp == "1":     _run_query_or_prompt("website", do_json, do_csv, do_report, do_store)
            elif inp == "2":   _run_query_or_prompt("ip", do_json, do_csv, do_report, do_store)
            elif inp == "3":   state = "main"
            else:              ui.warn("Invalid. Enter 1-3.")

        elif state == "utils":
            if inp == "1":     _run_query("opsec", "", do_json, do_csv, do_report)
            elif inp == "2":   _run_query_or_prompt("metadata", do_json, do_csv, do_report)
            elif inp == "3":   _show_help()
            elif inp == "4":   ui.banner()
            elif inp == "5":   state = "main"
            else:              ui.warn("Invalid. Enter 1-5.")


if __name__ == "__main__":
    _cli()
