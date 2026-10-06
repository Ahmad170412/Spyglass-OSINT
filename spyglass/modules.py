"""The module registry for the web console.

Kept in Python so the sidebar and the API can never disagree. An earlier build
hardcoded this list in the page, which is how the console ended up advertising a
Reverse Image and an Audio tab for modules that do not exist in the CLI.

Every entry here maps to a real callable:
    email      -> email_recon.email     username  -> username.username
    phone      -> phone.phone           website   -> website.website
    ip         -> ip.address            metadata  -> metadata.extract
    darkweb    -> darkweb.darkweb       opsec     -> opsec.health_check

Adding a tab means adding a row here and a route in webapp.py. Nothing else.
"""

import os


def _example_path(name):
    """A placeholder file path written in this OS's own syntax.

    The console renders ``ph`` verbatim, and ``/path/to/file.jpg`` reads as
    nonsense to anyone on Windows. Joining onto the real home directory gives
    an example that carries the platform's separator and drive letter, so the
    field looks like something you could actually paste into.
    """
    return os.path.join(os.path.expanduser("~"), name)


# `endpoint` is the Flask route suffix under /api/; `fields` describes the input
# surface the page should render.
MODULES = [
    {
        "id": "username", "ix": "01", "name": "Username", "icon": "user",
        "endpoint": "username",
        "sub": "Supply a handle to begin enumeration across indexed platforms.",
        "fields": [{"name": "target", "label": "Target Handle", "pfx": "@",
                    "icon": "user", "ph": "handle"}],
    },
    {
        "id": "email", "ix": "02", "name": "Email", "icon": "mail",
        "endpoint": "email",
        "sub": "Supply an address to begin verification and exposure lookup.",
        "fields": [{"name": "target", "label": "Target Address", "icon": "mail",
                    "ph": "user@example.com"}],
    },
    {
        "id": "phone", "ix": "03", "name": "Phone", "icon": "phone",
        "endpoint": "phone",
        "sub": "Supply a number to begin carrier and line-type resolution.",
        "fields": [{"name": "target", "label": "Target Number", "icon": "phone",
                    "ph": "+1 415 555 4471"}],
    },
    {
        "id": "website", "ix": "04", "name": "Website", "icon": "globe",
        "endpoint": "website",
        "sub": "Supply a domain to begin deep recon, including known CVEs.",
        "fields": [{"name": "target", "label": "Target Domain", "icon": "globe",
                    "ph": "example.com"}],
        "options": [
            {"name": "vulns", "label": "Include NVD vulnerability lookup",
             "type": "checkbox", "default": True},
            {"name": "cve_cap", "label": "Components to query", "type": "number",
             "default": 3, "min": 1, "max": 12},
        ],
    },
    {
        "id": "ip", "ix": "05", "name": "IP Address", "icon": "net",
        "endpoint": "ip",
        "sub": "Supply an address to begin geolocation and port analysis.",
        "fields": [{"name": "target", "label": "Target IP", "icon": "net",
                    "ph": "1.1.1.1"}],
    },
    {
        "id": "metadata", "ix": "06", "name": "Metadata", "icon": "meta",
        "endpoint": "metadata",
        "sub": "Supply a server-side file path to extract EXIF, XMP and document metadata.",
        "fields": [{"name": "target", "label": "File Path", "icon": "meta",
                    "ph": _example_path("photo.jpg")}],
    },
    {
        "id": "darkweb", "ix": "07", "name": "Dark Web", "icon": "moon",
        "endpoint": "darkweb",
        "sub": "Search the Tor hidden-service index and breach corpora. Keyless.",
        "fields": [
            {"name": "target", "label": "Search Term", "pfx": "\"", "icon": "moon",
             "ph": "user@example.com"},
            # Explicit selection only. The module can infer the target type, but
            # inferring it silently means a mistyped search is reported against
            # the wrong corpus, so the operator picks. ``placeholder`` renders a
            # disabled "choose one" row that carries no value, and ``required``
            # blocks the run until a real type is picked.
            {"name": "type", "label": "Target Type", "icon": "bolt", "type": "select",
             "required": True, "placeholder": "Select a type",
             "options": ["email", "username", "phone", "domain", "ip"]},
        ],
    },
    {
        "id": "opsec", "ix": "08", "name": "OPSEC", "icon": "shield",
        "endpoint": "opsec",
        "sub": "Check whether this machine is leaking its real IP or bypassing its proxy.",
        "fields": [],
        "no_input": True,
    },
    {
        "id": "asn", "ix": "09", "name": "ASN / Routing", "icon": "net",
        "endpoint": "asn",
        "sub": "Who routes this address: covering prefix, origin AS, holder, and RPKI validity.",
        # Accepts an IP, a prefix, or an AS number through one field. A type
        # picker would add a step for no benefit: the module classifies the
        # input itself and reports which reading it took in query_type.
        "fields": [{"name": "target", "label": "IP, prefix, or AS", "icon": "net",
                    "ph": "1.1.1.1, 1.1.1.0/24, or AS13335"}],
    },
]

BY_ID = {m["id"]: m for m in MODULES}
