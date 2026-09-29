#!/usr/bin/env python3
import sys
import re

from .email_recon import email
from .username import username
from .website import website
from .metadata import extract as metadata
from .ip import address as ip_address
from .asn import asn as asn_lookup
from .opsec import health_check as opsec_check
from .darkweb import darkweb, pwned_password
from .utils import set_proxy
from .export import json_output as export_json, csv_output as export_csv
from . import store
from . import display as ui
from . import __version__


_USAGE = ("Usage: spyglass email|username|phone|ip|asn|website|metadata|darkweb <target> "
          "[--type TYPE] [--json] [--csv] [--report] [--store] [--proxy URL]\n"
          "       spyglass website <target> [--no-vulns] [--cve-cap N] [--nvd-key KEY]\n"
          "       spyglass asn <ip|prefix|AS>   (covering prefix, origin AS, RPKI validity)\n"
          "       spyglass darkweb --password   (check a password against Pwned Passwords)\n"
          "       spyglass cases [list|diff|timeline|export] [<target>] [--type TYPE]")

_HELP = f"""Spyglass {__version__} — unified OSINT recon CLI.

USAGE
  spyglass <module> <target> [options]
  spyglass opsec                      (no target needed)
  spyglass darkweb --password         (check a password against Pwned Passwords)
  spyglass cases [list|diff|timeline|export] [<target>] [--type TYPE]
  spyglass                            (interactive menu, if no target is given)

MODULES
  email      where an address is registered, breaches, public identity
  username   which platforms have this profile
  phone      owner, carrier, region, footprints
  website    DNS, subdomains, ports, headers, tech stack, TLS, WHOIS, history, CVEs
  ip         geolocation, reverse DNS, open ports
  asn        who routes an address: covering prefix, origin AS, holder,
             RPKI validity (accepts an IP, a CIDR prefix, or an AS number)
  metadata   hidden data in a file (GPS, camera, document author)
  darkweb    .onion index search, breaches, breached passwords
  opsec      is your real IP leaking, is your proxy working

OPTIONS
  --type TYPE       darkweb target type: email|username|phone|domain|ip
                    (auto-detected when omitted)
  --json            save a timestamped JSON file
  --csv             save a timestamped CSV file
  --report          write a Markdown dossier
  --store           persist the run to the case store (default ~/.spyglass)
  --proxy URL       route through a proxy, e.g. socks5://127.0.0.1:9050
  --no-vulns        website module: skip the NVD known-vulnerability lookup
  --cve-cap N       website module: how many products to query (default 3)
  --nvd-key KEY     NVD API key; raises the rate limit from 5 to 50 per 30s.
                    Falls back to the NVD_API_KEY environment variable.
  --version         print the version and exit
  -h, --help        print this help and exit

NOTES
  --no-vulns, --cve-cap, --nvd-key and --type apply to the one-shot form
  only; they are ignored once you drop into the interactive menu. Run with no
  arguments to get the interactive menu.

REMOVED
  --top-ports N     went with the nmap port scan. Open ports now come from
                    Shodan InternetDB and are not tunable."""


def _int_or(value, default):
    """Coerce a CLI flag value to int, falling back to ``default``.

    Numeric flags arrive as raw strings from ``--flag VALUE`` and
    ``--flag=VALUE``. Passing one straight through to a slice or an
    argparse-style bound raises ``TypeError`` deep inside a probe, where the
    failure is swallowed and reported as "lookup failed" rather than as the
    obvious thing it is. A non-numeric value is a typo, so the default is used
    rather than failing the whole run.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _warn_removed_flag(name):
    """Tell the operator a flag was removed, and what replaced it.

    Rejecting loudly is the point. The alternative — accepting the flag and
    quietly ignoring it — is how a user ends up believing they got a top-1000
    port scan when they got whatever a passive source happened to know.
    """
    ui.warn(f"{name} was removed with the nmap port scan. Open ports now come "
            f"from Shodan InternetDB, which needs no flag and no API key.")
    ui.item_dim("  The ports reported are what Shodan's own scan recorded, so "
                "they may lag the target; they are never a live probe.")


def _run_query(qtype, target, do_json=False, do_csv=False, do_report=False, sub_type=None, do_store=False,
               vulns=True, nvd_key=None, cve_cap=3):
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
        # Imported here, not at module scope. phone.py needs the phonenumbers
        # package unconditionally, and importing it at the top made every
        # other entry point depend on it: `spyglass --version` and `--help`
        # exited 1 on a bare install. webapp.py already holds the same rule
        # for its handlers, and the CLI should not be laxer than the console.
        from .phone import phone

        ui.header("Checking phone", target)
        result = phone(target)
        ui.show_phone(result)
    elif qtype == "website":
        ui.header("Website recon", target)
        result = website(target, vulns=vulns, nvd_key=nvd_key, cve_cap=cve_cap)
        ui.show_website(result)
    elif qtype == "metadata":
        ui.header("Metadata extraction", target)
        result = metadata(target)
        ui.show_metadata(result)
    elif qtype == "ip":
        ui.header("IP recon", target)
        result = ip_address(target)
        ui.show_ip(result)
    elif qtype == "asn":
        ui.header("ASN / routing", target)
        result = asn_lookup(target)
        ui.show_asn(result)
    elif qtype == "darkweb":
        ui.header("Dark web search", target)
        result = darkweb(target, sub_type)
        ui.show_darkweb(result)
    elif qtype == "opsec":
        result = opsec_check()
        ui.show_opsec(result)

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


def _parse_args(argv):
    """Parse CLI flags and return (proxy, json, csv, report, type, password, store, positional)."""
    proxy = None
    do_json = False
    do_csv = False
    do_report = False
    type_hint = None
    do_password = False
    do_store = False
    vulns = True
    nvd_key = None
    cve_cap = 3
    positional = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--version":
            print(f"Spyglass {__version__}")
            raise SystemExit(0)
        if a in ("--help", "-h"):
            print(_HELP)
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
        if a == "--no-vulns":
            vulns = False
            i += 1
            continue
        if a == "--nvd-key" and i + 1 < len(argv):
            nvd_key = argv[i + 1]
            i += 2
            continue
        if a.startswith("--nvd-key="):
            nvd_key = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--cve-cap" and i + 1 < len(argv):
            cve_cap = _int_or(argv[i + 1], 3)
            i += 2
            continue
        if a.startswith("--cve-cap="):
            cve_cap = _int_or(a.split("=", 1)[1], 3)
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
        if a == "--top-ports" or a.startswith("--top-ports="):
            # Removed with the nmap port scan. Rejected explicitly rather than
            # ignored: a flag that is accepted and does nothing is worse than
            # one that tells you it no longer exists.
            _warn_removed_flag("--top-ports")
            i += 2 if a == "--top-ports" and i + 1 < len(argv) else 1
            continue
        positional.append(a)
        i += 1
    return (proxy, do_json, do_csv, do_report, type_hint, do_password,
            do_store, positional, vulns, nvd_key, cve_cap)


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
    ui.kv("4  Website",     "Full recon: DNS, ports, headers, WHOIS, subdomains, dirs, CVEs")
    ui.kv("5  Metadata",    "Extract metadata from a file (EXIF, GPS, docs, etc.)")
    ui.kv("6  IP recon",    "Geolocate, DNS, WHOIS, open ports, Shodan")
    ui.blank()
    ui.item_dim("Dark web:  spyglass darkweb <target> [--type email|username|phone|domain|ip]")
    ui.item_dim("Password:  spyglass darkweb --password  (Pwned Passwords k-anonymity)")
    ui.item_dim("Flags: --proxy URL  --json  --csv  --report  --store  --version")
    ui.item_dim("Cases: spyglass cases [list|diff|timeline|export] <target> [--type TYPE]")
    ui.item_dim("Non-interactive: spyglass email user@example.com --json --report")


def _run_query_or_prompt(qtype, do_json, do_csv, do_report=False, do_store=False, **kw):
    if qtype == "opsec":
        _run_query("opsec", "", do_json, do_csv, do_report, do_store=do_store)
    else:
        target = ui.target_prompt(qtype)
        if target:
            _run_query(qtype, target, do_json, do_csv, do_report,
                       do_store=do_store, **kw)


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
    (proxy, do_json, do_csv, do_report, type_hint, do_password, do_store,
     positional, vulns, nvd_key, cve_cap) = _parse_args(sys.argv[1:])

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

    # Non-interactive mode: command from args.
    # opsec is keyless, so it never reaches the two-positional form below.
    if len(positional) == 1 and positional[0].lower() == "opsec":
        _run_query("opsec", "", do_json, do_csv, do_report,
                   do_store=do_store)
        return

    # Non-interactive mode: command from args
    if len(positional) >= 2:
        qtype = positional[0].lower()
        if qtype in ("email", "username", "phone", "website", "metadata", "ip",
                     "darkweb", "asn"):
            target = positional[1]
            _run_query(qtype, target, do_json, do_csv, do_report,
                       sub_type=type_hint, do_store=do_store,
                       vulns=vulns, nvd_key=nvd_key, cve_cap=cve_cap)
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
            elif inp == "3":   state = "utils"
            elif inp == "4":   break
            else:              ui.warn("Invalid. Enter 1-4.")

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
            elif inp == "3":   _run_query_or_prompt("asn", do_json, do_csv, do_report, do_store)
            elif inp == "4":   state = "main"
            else:              ui.warn("Invalid. Enter 1-4.")

        elif state == "utils":
            if inp == "1":     _run_query("opsec", "", do_json, do_csv, do_report)
            elif inp == "2":   _run_query_or_prompt("metadata", do_json, do_csv, do_report)
            elif inp == "3":   _show_help()
            elif inp == "4":   ui.banner()
            elif inp == "5":   state = "main"
            else:              ui.warn("Invalid. Enter 1-5.")


def main():
    """Console-script entry point (the ``spyglass`` command).

    Exists so ``pyproject.toml`` has a public name to point at rather than the
    private ``_cli``; both do the same thing, and ``python -m spyglass`` still
    routes through ``_cli`` directly.
    """
    return _cli()


if __name__ == "__main__":
    _cli()
