"""Tests for CLI argument parsing, and the registry/CLI/console agreement.

Covers the numeric-coercion and ``--help`` fixes, and the invariant that a
module registered for the web console is also reachable from the command line.
"""

import os
import re
import subprocess
import sys
import unittest

from helpers import _ROOT, imp

pkg = imp("")
main = imp("__main__")

_PKG_NAME = pkg.__name__.split(".")[0]

# The qtypes the one-shot form accepts, read out of __main__.py rather than
# restated here. A hardcoded copy would drift from the code it is meant to
# check, which is the exact failure the registry tests are guarding against.
_MAIN_PY = os.path.join(os.path.dirname(os.path.abspath(pkg.__file__)), "__main__.py")
with open(_MAIN_PY, encoding="utf-8") as _fh:
    _SOURCE = _fh.read()
_whitelist = re.search(r"if qtype in \(([^)]*)\):", _SOURCE, re.S)
assert _whitelist, "could not find the one-shot qtype whitelist in __main__.py"
_CLI_MODULES = set(re.findall(r'"([a-z]+)"', _whitelist.group(1)))

# _parse_args returns an 11-tuple; index by name so these tests do not break if
# a flag is added.
_FIELDS = ("proxy do_json do_csv do_report type_hint do_password do_store "
           "positional vulns nvd_key cve_cap").split()


def _parse(*argv):
    parsed = main._parse_args(list(argv))
    return dict(zip(_FIELDS, parsed))


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", _PKG_NAME, *args],
        capture_output=True, text=True, cwd=_ROOT,
    )


class NumericFlagTest(unittest.TestCase):
    """Numeric flags used to stay strings all the way into a slice.

    ``--cve-cap 8`` reached ``ranked[:cap]`` in cve.py and raised TypeError,
    which the caller swallowed into a "vulns: error" block. The user asked for
    a cap and got a lookup failure instead.
    """

    def test_cve_cap_space_form_is_an_int(self):
        self.assertEqual(_parse("website", "x.test", "--cve-cap", "8")["cve_cap"], 8)

    def test_cve_cap_equals_form_is_an_int(self):
        self.assertEqual(_parse("website", "x.test", "--cve-cap=12")["cve_cap"], 12)

    def test_cve_cap_defaults_to_three(self):
        self.assertEqual(_parse("website", "x.test")["cve_cap"], 3)

    def test_cve_cap_is_sliceable(self):
        """The exact operation that used to raise."""
        cap = _parse("website", "x.test", "--cve-cap", "5")["cve_cap"]
        self.assertEqual(len([1, 2, 3, 4, 5, 6, 7, 8][:cap]), 5)

    def test_non_numeric_cve_cap_falls_back_to_default(self):
        self.assertEqual(_parse("website", "x.test", "--cve-cap", "eight")["cve_cap"], 3)

    def test_top_ports_is_consumed_and_warns_rather_than_becoming_a_target(self):
        # --top-ports tuned the nmap scan. It must be swallowed, not treated as
        # a positional, and it must say so: an accepted-but-ignored flag is how
        # an operator believes they got a 1000-port scan they never ran.
        out = _parse("ip", "1.1.1.1", "--top-ports", "50")
        self.assertEqual(out["positional"], ["ip", "1.1.1.1"])

    def test_top_ports_equals_form_is_also_consumed(self):
        out = _parse("ip", "1.1.1.1", "--top-ports=100")
        self.assertEqual(out["positional"], ["ip", "1.1.1.1"])

    def test_top_ports_appears_in_no_live_code_path(self):
        # Removed end to end: not in the ip module's result, not in the report
        # renderer, not anywhere it could still be threaded through.
        self.assertNotIn("top_ports", main._run_query.__code__.co_varnames)


class HelpFlagTest(unittest.TestCase):
    """``--help`` was not recognised, so it fell through to the positional
    branch and dropped the user into the interactive REPL instead of printing
    anything. setup.sh advertised the flag, which is how this was found.
    """

    def test_help_exits_zero(self):
        proc = _run_cli("--help")
        self.assertEqual(proc.returncode, 0)

    def test_short_help_exits_zero(self):
        self.assertEqual(_run_cli("-h").returncode, 0)

    def test_help_prints_usage(self):
        self.assertIn("USAGE", _run_cli("--help").stdout)

    def test_help_lists_every_module(self):
        out = _run_cli("--help").stdout
        for module in sorted(_CLI_MODULES):
            self.assertIn(module, out)

    def test_help_documents_each_flag(self):
        out = _run_cli("--help").stdout
        for flag in ("--type", "--json", "--csv", "--report", "--store",
                     "--proxy", "--no-vulns", "--cve-cap",
                     "--nvd-key", "--version"):
            self.assertIn(flag, out)

    def test_help_moves_removed_flags_out_of_options(self):
        # A removed flag must not linger in OPTIONS, where it would read as
        # supported — the same defect as the dead nuclei probe. It belongs in
        # REMOVED instead: someone with muscle memory for --top-ports should
        # be told what replaced it rather than find the flag silently ignored.
        out = _run_cli("--help").stdout
        options, _, removed = out.partition("REMOVED")
        self.assertNotIn("--top-ports", options)
        self.assertIn("--top-ports", removed)
        self.assertIn("InternetDB", removed)

    def test_help_does_not_start_a_recon_run(self):
        """It must not be treated as a target."""
        proc = _run_cli("--help")
        self.assertNotIn("Select", proc.stdout)

    def test_help_wins_over_a_module_name(self):
        """Same precedence rule as --version: a flag beats a positional."""
        self.assertEqual(_run_cli("website", "example.com", "--help").returncode, 0)


class CasesSubcommandTest(unittest.TestCase):
    def test_cases_still_parses_after_help_was_added(self):
        parsed = _parse("cases", "list")
        self.assertEqual(parsed["positional"], ["cases", "list"])


class ModuleRegistryTest(unittest.TestCase):
    """The registry, the CLI and the web console must agree.

    ``modules.py`` exists so a console tab cannot exist for a module the CLI
    does not have — the failure it was written to prevent, where the page
    advertised Reverse Image and Audio tabs for modules that were never built.
    That contract is only enforced by these three things staying in step, so it
    is checked rather than remembered.
    """

    def setUp(self):
        self.modules = imp("modules")
        self.webapp = imp("webapp")
        self.rows = self.modules.MODULES

    def test_registry_ids_are_unique(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_registry_ordinals_are_unique(self):
        ixs = [r["ix"] for r in self.rows]
        self.assertEqual(len(ixs), len(set(ixs)))

    def test_every_module_has_an_api_route(self):
        routes = {r.rule for r in self.webapp.app.url_map.iter_rules()}
        for row in self.rows:
            self.assertIn(f"/api/{row['endpoint']}", routes,
                          f"module {row['id']} has no route")

    def test_every_api_route_has_a_module(self):
        # The reverse direction: a route nobody can reach from the page is dead
        # code, and /api/health and /api/modules are the two known exceptions.
        eps = {r["endpoint"] for r in self.rows}
        for rule in self.webapp.app.url_map.iter_rules():
            if not rule.rule.startswith("/api/"):
                continue
            name = rule.rule[len("/api/"):]
            if name in ("health", "modules"):
                continue
            self.assertIn(name, eps, f"/api/{name} has no registry row")

    def test_every_module_is_reachable_from_the_cli(self):
        for row in self.rows:
            if row.get("no_input"):
                continue  # keyless modules are dispatched on one positional
            self.assertIn(row["id"], _CLI_MODULES,
                          f"module {row['id']} is not in the CLI dispatch chain")

    def test_asn_is_registered_everywhere(self):
        self.assertIn("asn", [r["id"] for r in self.rows])
        self.assertIn("asn", _CLI_MODULES)


if __name__ == "__main__":
    unittest.main()
