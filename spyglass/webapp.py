#!/usr/bin/env python3
"""Flask front end for Spyglass.

A thin web console over the existing CLI. Every route calls the same module
function the CLI calls and returns the same dict as JSON, so the browser can
never see a shape the terminal cannot — there is no second implementation of any
recon logic here, only a transport.

Design notes
------------
* Imports are local to each handler. Two of the modules pull heavy optional
  dependencies (torch is not among them, but ``phonenumbers`` and Pillow are), and
  a missing one should break only the route that needs it rather than the whole
  console at boot.
* Nothing is cached and nothing is written. Results live in the response, which
  keeps the store's opt-in contract intact: no recon result touches disk unless
  the operator passed ``--store`` on the command line.
* Binds to loopback by default. This process runs arbitrary recon against
  arbitrary targets with the operator's own network and credentials, so it must
  not be reachable from the LAN by accident.
"""

from __future__ import annotations

import argparse
import os
import sys

from flask import Flask, jsonify, request, send_from_directory

import importlib

_HERE = os.path.dirname(os.path.abspath(__file__))

# The package name is the checkout directory's own name — this file lives inside
# the package, so the basename is exact. Reading it rather than hardcoding
# "Spyglass-OSINT" is what lets the checkout be renamed freely. (An earlier
# version scanned the parent directory for a sibling holding __init__.py and
# utils.py, which was both more code and capable of matching the wrong package.)
_PKG = os.path.basename(_HERE)

# Running ``python webapp.py`` from inside the package puts the *package*
# directory on sys.path, not its parent, so the package cannot be imported by
# its own name. Put the parent back so ``importlib`` resolves it, and so the
# package is addressed the same way whatever the console is started from.
if os.path.dirname(_HERE) not in sys.path:
    sys.path.insert(0, os.path.dirname(_HERE))

app = Flask(__name__, static_folder=None)
app.config["JSON_SORT_KEYS"] = False

# Long recon runs are normal here: a website pass with the NVD lookup can sit
# past a minute once rate limiting is accounted for.
app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False


def _mod(name):
    """Import a Spyglass module by short name.

    The package directory contains a dash, so it cannot be imported with a plain
    ``import`` statement; ``_PKG`` carries whatever the directory is called.
    """
    return importlib.import_module(f"{_PKG}.{name}")


def _body():
    return request.get_json(silent=True) or {}


def _need(value, field="target"):
    value = (value or "").strip() if isinstance(value, str) else ""
    if not value:
        return None, (jsonify({"error": f"{field} is required"}), 400)
    return value, None


def _fail(exc):
    app.logger.exception("module call failed")
    return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500


# ─── pages ───────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory(_HERE, "index.html")


@app.get("/api/modules")
def api_modules():
    """The module list plus section labels, served from the server.

    Served rather than hardcoded in the page so a tab can never exist for a
    module that was removed or renamed — the failure the console shipped with.

    The labels matter for the same reason. Several modules return internal
    bucket keys that mean nothing to a reader (``username`` emits ``us_only``,
    which reads as "United States only"), and a console that prettifies keys
    client-side invents its own wording that then disagrees with the CLI.
    """
    # Relative, like every other import in the package. This was a bare
    # ``from modules import MODULES``, which resolved only because running
    # ``python webapp.py`` puts the script's own directory on sys.path. As soon
    # as the console was imported rather than executed — ``python -m`` from an
    # installed wheel, a WSGI server, or the test suite — ``modules`` was not a
    # top-level name and the route returned a 500.
    from .modules import MODULES
    return jsonify({
        "modules": MODULES,
        "labels": {
            "username": _mod("username").SECTION_LABELS,
        },
    })


# ─── module routes ───────────────────────────────────────

@app.post("/api/username")
def api_username():
    target, err = _need(_body().get("target"))
    if err:
        return err
    try:
        return jsonify(_mod("username").username(target))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/email")
def api_email():
    target, err = _need(_body().get("target"))
    if err:
        return err
    try:
        return jsonify(_mod("email_recon").email(target))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/phone")
def api_phone():
    target, err = _need(_body().get("target"))
    if err:
        return err
    try:
        return jsonify(_mod("phone").phone(target))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/darkweb")
def api_darkweb():
    data = _body()
    target, err = _need(data.get("target"))
    if err:
        return err
    try:
        return jsonify(_mod("darkweb").darkweb(target, data.get("type")))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/metadata")
def api_metadata():
    # The metadata module takes a filesystem path rather than an upload, which
    # is the right trade for a local-only console: no file is copied anywhere and
    # no temp copy is left behind.
    target, err = _need(_body().get("target"), "file path")
    if err:
        return err
    # normalise_path, not expanduser: a path pasted into this box arrives with
    # this OS's separators and quotes around it if it contains spaces, and the
    # console has to check the same string the module will open.
    meta = _mod("metadata")
    path = meta.normalise_path(target)
    if not os.path.isfile(path):
        return jsonify({"error": f"File not found: {path}"}), 400
    try:
        return jsonify(meta.extract(path))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/website")
def api_website():
    data = _body()
    target, err = _need(data.get("target"))
    if err:
        return err
    vulns = data.get("vulns", True)
    try:
        cve_cap = max(1, min(12, int(data.get("cve_cap", 3))))
    except (TypeError, ValueError):
        cve_cap = 3
    try:
        return jsonify(_mod("website").website(
            target,
            vulns=bool(vulns),
            nvd_key=os.environ.get("NVD_API_KEY"),
            cve_cap=cve_cap,
        ))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/ip")
def api_ip():
    data = _body()
    target, err = _need(data.get("target"))
    if err:
        return err
    try:
        # No top_ports: it tuned the nmap scan, which is gone. Ports come from
        # InternetDB and are not tunable by the caller.
        return jsonify(_mod("ip").address(target))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/asn")
def api_asn():
    data = _body()
    target, err = _need(data.get("target"))
    if err:
        return err
    try:
        return jsonify(_mod("asn").asn(target))
    except Exception as exc:
        return _fail(exc)


@app.post("/api/opsec")
def api_opsec():
    try:
        return jsonify(_mod("opsec").health_check())
    except Exception as exc:
        return _fail(exc)


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True, "package": _PKG})


def main():
    ap = argparse.ArgumentParser(description="Spyglass web console")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default loopback only)")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        app.logger.warning(
            "Binding to %s exposes this console to the network. It runs recon "
            "with your credentials and has no authentication.", args.host)

    print(f"  Spyglass console -> http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    # Two ways in, and they need different bootstrapping:
    #
    #   python -m spyglass.webapp   works directly — the package context is
    #                                established by -m, so relative imports
    #                                inside the route handlers resolve.
    #   python spyglass/webapp.py    does not: a script run sets __name__ to
    #                                "__main__" with no parent package, so every
    #                                `from .x import y` inside a handler raises
    #                                "attempted relative import with no known
    #                                parent package" — at request time, not
    #                                import time, which is why the console would
    #                                boot and then 500 on its own first request.
    #
    # Putting the *parent* of the package on sys.path and re-importing under the
    # real name gives the handlers the package context they need. Prefer -m.
    import os as _os
    import sys as _sys

    _parent = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
    if _parent not in _sys.path:
        _sys.path.insert(0, _parent)
    from spyglass.webapp import main as _main  # noqa: E402  (needs the path above)

    _main()
