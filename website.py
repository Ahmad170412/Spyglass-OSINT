#!/usr/bin/env python3
import re
import subprocess

from .utils import _run, _extract_ips, _extract_emails, _extract_phones, _extract_whois_fields, _check_tool, _DIG, _NMAP, _GOBUSTER, _HTPPX, _WHOIS, _CURL, _SHODAN

# ─── embedded wordlists ────────────────────────────────────
_SUB_LIST = """
www
mail
admin
api
blog
dev
test
staging
app
beta
cdn
docs
shop
store
support
help
portal
status
web
m
mobile
news
forum
wiki
demo
vpn
secure
signup
login
register
assets
img
css
js
static
download
files
media
video
chat
community
boards
calendar
events
maps
api2
api3
backup
db
dns
email
ftp
git
graphql
hr
iam
jenkins
jobs
kibana
ldap
localhost
logs
mail2
metrics
monitor
mx
mx1
mx2
ns1
ns2
pay
payment
phpmyadmin
pop
prod
proxy
radius
redirect
redis
remote
rest
sandbox
smtp
sql
ssh
ssl
stats
status2
svn
sync
syslog
test2
tunnel
upload
uploads
vhost
vm
vpn2
webmail
websocket
ws
www2
www3
xmlrpc
""".strip().splitlines()

_DIR_LIST = """
admin
administrator
api
app
assets
backup
backups
cache
cdn
cgi-bin
cmd
config
configuration
content
css
dashboard
db
demo
dev
docs
download
downloads
error
examples
export
favicon.ico
files
fonts
forum
graphql
help
home
html
images
img
include
includes
index
install
js
json
language
lib
library
license
login
log
logs
mail
media
migrate
mobile
modules
news
old
package
pages
panel
phpinfo.php
plugins
private
prod
public
README
readme
reports
rest
robots.txt
rss
sass
save
scripts
search
secure
server-status
service
services
session
setup
sitemap.xml
sql
src
ssh
stat
static
stats
status
storage
styles
svn
swagger
temp
template
templates
test
tmp
todo
tools
tmp
update
upload
uploads
user
users
v2
vendor
version
video
views
web
webapp
webroot
wiki
wpad.dat
www
xml
xmlrpc
""".strip().splitlines()


# ─── website recon ────────────────────────────────────────

def website(target):
    print(f"\n[*] Website recon: {target}\n")

    print("  [1/8] DNS records...")
    if _check_tool("dig", _DIG):
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            out = _run(["dig", target, rtype, "+short"])
            if out:
                vals = [l.strip() for l in out.split("\n") if l.strip()]
                if vals:
                    print(f"    {rtype}: {', '.join(vals)}")

    print("  [2/8] Shodan...")
    ips = []
    for rtype in ["A", "AAAA"]:
        out = _run(["dig", target, rtype, "+short"])
        if out:
            ips.extend(l.strip() for l in out.split("\n") if l.strip())
    ips = [ip for ip in ips if "." in ip]
    if not _check_tool("shodan", _SHODAN):
        print("    Skipping (shodan not found)")
    elif ips:
        for ip in ips:
            try:
                r = subprocess.run(
                    ["shodan", "host", ip],
                    capture_output=True, text=True, timeout=20,
                )
                data = r.stdout.strip()
                err  = r.stderr.strip()
            except Exception as e:
                data, err = "", str(e)

            if data:
                org = ""
                ports = ""
                isp = ""
                country = ""
                for line in data.split("\n"):
                    low = line.lower()
                    if "organization" in low or low.startswith("org:"):
                        org = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "isp" in low:
                        isp = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "country" in low:
                        country = line.split(":", 1)[1].strip() if ":" in line else ""
                    elif "ports" in low:
                        ports = line.split(":", 1)[1].strip() if ":" in line else ""
                parts = []
                if org: parts.append(f"Org: {org}")
                if isp: parts.append(f"ISP: {isp}")
                if country: parts.append(f"Country: {country}")
                if ports: parts.append(f"Ports: {ports}")
                if parts:
                    print(f"    {ip}: {' | '.join(parts)}")
                else:
                    print(f"    {ip}: No Shodan data")
            elif "403" in err:
                print(f"    {ip}: Free tier limit — no access for this IP")
            elif "init" in err.lower():
                print(f"    {ip}: Shodan not configured — run `shodan init <API_KEY>`")
            elif err:
                print(f"    {ip}: {err.split(chr(10))[-1].strip()}")
            else:
                print(f"    {ip}: No Shodan data")

    print("  [3/8] Port scan (nmap)...")
    if _check_tool("nmap", _NMAP):
        if ips:
            for ip in ips:
                nm = _run(
                    ["nmap", "--top-ports", "100", "-sV", "-T4", "--open", ip, "-oG", "-"],
                    timeout=120,
                )
                ports = re.findall(r"(\d+)/(open|filtered)/tcp//([^/]*?)//([^/]*?)", nm)
                if ports:
                    parts = []
                    for p, st, sv, pr in ports:
                        if pr:
                            parts.append(f"{p}/{sv} ({pr})")
                        elif sv:
                            parts.append(f"{p}/{sv}")
                        else:
                            parts.append(p)
                    print(f"    {ip}: {', '.join(parts)}")
                else:
                    print(f"    {ip}: No open ports found (or scan timed out)")
        else:
            print("    No IPs to scan")

    print("  [4/8] HTTP headers (curl -sI)...")
    if _check_tool("curl", _CURL):
        hd = _run(["curl", "-sI", "-L", f"https://{target}"])
        server = ""
        for line in hd.split("\n"):
            low = line.lower()
            if low.startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif low.startswith("x-powered-by:"):
                server += (" | " + line.split(":", 1)[1].strip()) if server else line.split(":", 1)[1].strip()
        if server:
            print(f"    Server: {server}")

    print("  [5/8] WHOIS lookup...")
    if _check_tool("whois", _WHOIS):
        wh = _run(["whois", target], timeout=30)
        fields = _extract_whois_fields(wh)
        whois_emails = _extract_emails(wh)
        whois_phones = _extract_phones(wh)

        for k, v in fields.items():
            print(f"    {k}: {v}")
        if not fields and not whois_emails and not whois_phones:
            print("    No registrant info found")
        else:
            for e in whois_emails:
                if e not in fields.values():
                    print(f"    Email: {e}")
            for p in whois_phones:
                if p not in fields.values():
                    print(f"    Phone: {p}")

    print("  [6/8] Subdomain enumeration (gobuster dns)...")
    subs = []
    if _check_tool("gobuster", _GOBUSTER):
        sd_out = _run(
            ["gobuster", "dns", "-d", target, "-w", "-", "-q"],
            timeout=60, stdin="\n".join(_SUB_LIST),
        )
        subs = re.findall(r"Found:\s*(\S+)", sd_out)
        subs = sorted(set(subs))
    if subs:
        for s in subs:
            print(f"    {s}")
        print("  [7/8] HTTP probing (httpx)...")
        if _check_tool("httpx", _HTPPX):
            hx = _run(
                ["httpx", "-silent", "-status-code", "-title",
                 "-server", "-content-length", "-timeout", "10"]
                 + [f"https://{s}" for s in subs],
                timeout=60,
            )
            for line in hx.split("\n"):
                line = line.strip()
                if line:
                    print(f"    {line}")
    else:
        print("    No subdomains found")

    print("  [8/8] Directory enumeration (gobuster dir)...")
    dirs = []
    if _check_tool("gobuster", _GOBUSTER):
        gb_out = _run(
            ["gobuster", "dir", "-u", f"https://{target}",
             "-w", "-", "-q", "-t", "20", "-k"],
            timeout=90, stdin="\n".join(_DIR_LIST),
        )
        dirs = re.findall(r"/(\S+)\s+\(Status:\s*\d+\)", gb_out)
        if not dirs:
            hint = re.findall(r"/(\S+)", gb_out)
            if hint:
                for h in sorted(set(hint))[:10]:
                    print(f"    {h}")
            else:
                print("    No directories found")
        else:
            for d in sorted(set(dirs)):
                print(f"    /{d}")
