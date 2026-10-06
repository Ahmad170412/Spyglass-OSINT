# Security Policy

## Reporting a vulnerability

Report vulnerabilities in Spyglass **privately**, through
[GitHub Security Advisories](https://github.com/Ahmad170412/Spyglass-OSINT/security/advisories/new).
That channel reaches the maintainer without publishing the issue, and you can
attach proof-of-concept detail there.

Please do not open a public issue, discussion, or pull request for an
unfixed vulnerability.

Include, where you can:

- What you did, and what you expected to happen
- The version or commit (`spyglass --version`, or `git rev-parse --short HEAD`)
- Impact: what an attacker gains, and who it affects — the operator, or a
  third party the operator pointed Spyglass at
- A minimal reproduction, or a description of the conditions needed
- Whether you have disclosed this anywhere else already

If you cannot use advisories, open an issue asking for a contact address and
put **no vulnerability detail in it** — a reply with a private channel will
follow.

### What is in scope

- Spyglass's own code in this repository
- Command or argument injection through a module's target, hostname, or file
  input
- Path traversal or arbitrary file write in `--json`, `--csv`, `--report`, the
  case store, or the web console's downloads
- The web console binding beyond loopback, missing authentication, or a route
  reachable without the operator intending it
- Case-store encryption at rest: key handling, salt reuse, or plaintext
  leaking into an export or a log
- Secrets of the operator (proxy credentials, API keys) appearing in output,
  reports, or files left on disk
- Dependency vulnerabilities reachable through a documented install path

### What is out of scope

- **The third-party tools Spyglass wraps** — maigret, sherlock, subfinder,
  blackbird, PhoneInfoga, exiftool, and the rest. Report those upstream;
  Spyglass invokes them and degrades when they are missing.
- **Third-party services and targets.** A service that is exposed, a breach
  that is already public, or a site that returns data about a person is not a
  vulnerability in Spyglass. The modules do what this README says they do.
- **Rate limits, ToS, or account action taken by an upstream source** because
  you queried it.
- **Findings that require physical access**, or social engineering of the
  operator.
- Anything you were not authorized to test.

## Good-faith research

Fixing a bug you found is welcome, and reporting it the way described above
will be treated as good faith. What is not covered:

- Accessing or exfiltrating data that is not yours
- Destroying data, or disrupting a service you were not authorized to test
- Testing third-party targets "while you were in there"
- Anything illegal where you live

Spyglass is an OSINT tool. Using it against a target without permission is
your responsibility, not something this project endorses or covers.

## Supported versions

Only the latest release and `main` receive security fixes. Fixes land on
`main` first and are cut into the next release; if you are pinned to an older
tag, upgrade or cherry-pick.

There is no bug bounty.
