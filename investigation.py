import concurrent.futures

from . import utils


def investigate(raw_inputs):
    inputs = {k: v.strip() for k, v in raw_inputs.items() if v and v.strip()}
    r = {"inputs": inputs}
    results = {}
    entities = {
        "emails": set(), "domains": set(), "ips": set(),
        "orgs": set(), "asns": set(), "phones": set(),
    }

    # Run the four modules concurrently — they're independent until the
    # correlation step, so investigation wall-time is the slowest module,
    # not the sum of all of them.
    def _run_email():
        if "email" not in inputs or "@" not in inputs["email"]:
            return None
        from .email import email as _email
        try:
            return _email(inputs["email"])
        except Exception as e:
            return {"error": str(e)}

    def _run_username():
        if "username" not in inputs:
            return None
        from .username import username as _username
        try:
            return _username(inputs["username"])
        except Exception as e:
            return {"error": str(e)}

    def _run_phone():
        if "phone" not in inputs:
            return None
        from .phone import phone as _phone
        try:
            return _phone(inputs["phone"])
        except Exception as e:
            return {"error": str(e)}

    def _run_website():
        if "website" not in inputs:
            return None
        from .website import website as _website
        try:
            return _website(inputs["website"])
        except Exception as e:
            return {"error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            "email": pool.submit(_run_email),
            "username": pool.submit(_run_username),
            "phone": pool.submit(_run_phone),
            "website": pool.submit(_run_website),
        }
        for key, fut in futures.items():
            res = fut.result()
            if res is not None:
                results[key] = res

    # Input-derived entities (known facts, independent of module success).
    if "email" in inputs and "@" in inputs["email"]:
        entities["emails"].add(inputs["email"])
        domain = inputs["email"].split("@")[-1]
        entities["domains"].add(domain)
        ip = _quick_resolve(domain)
        if ip:
            entities["ips"].add(ip)
    if "phone" in inputs:
        entities["phones"].add(inputs["phone"])
    if "website" in inputs:
        entities["domains"].add(inputs["website"])

    r["results"] = results
    _collect_entities(results, entities)
    r["entities"] = {k: sorted(v) for k, v in entities.items() if v}
    r["correlations"] = _correlate(inputs, results, entities)
    return r


def _collect_entities(results, entities):
    er = results.get("email", {})
    if "error" not in er:
        for key in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
            for item in er.get(key, []):
                if "domain" in item:
                    entities["domains"].add(item["domain"])

    wr = results.get("website", {})
    if "error" not in wr:
        dns = wr.get("dns_records", {})
        a_recs = dns.get("A", "")
        for ip in a_recs.replace(", ", ",").split(","):
            ip = ip.strip()
            if ip and ip.count(".") == 3:
                entities["ips"].add(ip)

        # Deep-recon additions: subdomains, TLS SANs, CSP, SPF third parties.
        for key in ("subdomains", "wayback_subdomains", "csp_domains"):
            for d in wr.get(key, []) or []:
                d = str(d).strip().lower().rstrip(".")
                if d and "." in d:
                    entities["domains"].add(d)
        tls_san = wr.get("tls", {}).get("san", "")
        for d in tls_san.split(","):
            d = d.strip().lower().rstrip(".")
            if d:
                entities["domains"].add(d)
        spf = wr.get("dns_email_security", {}).get("spf_includes", "")
        for d in spf.split(","):
            d = d.strip().lower().rstrip(".")
            if d:
                entities["domains"].add(d)

        who = wr.get("whois", {})
        for k in ("Organization", "OrgName", "org", "Org"):
            if who.get(k):
                entities["orgs"].add(who[k])
        for email_key in ("Email", "Tech Email", "Admin Email", "Registrant Email",
                          "Extra Emails"):
            val = who.get(email_key, "")
            for e in val.split(","):
                e = e.strip()
                if "@" in e:
                    entities["emails"].add(e)
                    entities["domains"].add(e.split("@")[-1])
        for phone_key in ("Phone", "Extra Phones"):
            val = who.get(phone_key, "")
            for p in val.split(","):
                p = p.strip()
                if p:
                    entities["phones"].add(p)

        for entry in wr.get("shodan", []):
            parts = entry.replace(" | ", " ").split()
            for p in parts:
                if p.startswith("Org:"):
                    entities["orgs"].add(p[4:])
                elif p.startswith("AS"):
                    entities["asns"].add(p)

    pr = results.get("phone", {})
    if "error" not in pr:
        pi = pr.get("phonenumbers", {})
        if "error" not in pi:
            if pi.get("region"):
                entities.setdefault("regions", set()).add(pi["region"])


def _correlate(inputs, results, entities):
    corr = []

    email = inputs.get("email")
    website = inputs.get("website")
    phone = inputs.get("phone")

    if email and website:
        domain = email.split("@")[-1]
        if domain == website:
            corr.append({"type": "match", "desc": "Email domain matches website target",
                         "detail": domain})
        elif domain in entities["domains"]:
            corr.append({"type": "match", "desc": "Email domain found in website WHOIS data",
                         "detail": domain})

    for er_key in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
        for item in results.get("email", {}).get(er_key, []):
            d = item.get("domain", "")
            if website and d == website:
                corr.append({"type": "match", "desc": f"Email registered on {d} (matches website)",
                             "detail": d})

    wr = results.get("website", {})
    if "error" not in wr:
        who = wr.get("whois", {})
        for email_key in ("Extra Emails", "Email", "Tech Email", "Admin Email"):
            val = who.get(email_key, "")
            if email and email in val:
                corr.append({"type": "match", "desc": "Input email found in website WHOIS",
                             "detail": email})

    er = results.get("email", {})
    if "error" not in er and "error" not in wr:
        breach = er.get("breach", {})
        who = wr.get("whois", {})
        org = who.get("Organization", "")
        if org and breach.get("found"):
            corr.append({"type": "info", "desc": f"Org \"{org}\" appears in WHOIS and breach data",
                         "detail": org})

    pr = results.get("phone", {})
    if "error" not in pr:
        pi = pr.get("phonenumbers", {})
        if "error" not in pi and "error" not in wr:
            region = pi.get("region", "").lower()
            who = wr.get("whois", {})
            wc = who.get("Country", "").lower()
            if region and wc:
                if region[:2] == wc[:2] or region in wc or wc in region:
                    corr.append({"type": "match", "desc": "Phone region matches WHOIS country",
                                 "detail": f"{region} ↔ {wc}"})

    if "error" not in wr:
        who_emails = set()
        for email_key in ("Extra Emails", "Email", "Tech Email", "Admin Email", "Registrant Email"):
            val = who.get(email_key, "")
            for e in val.split(","):
                e = e.strip()
                if "@" in e:
                    who_emails.add(e)
        if who_emails:
            corr.append({"type": "info", "desc": "Emails found in website WHOIS",
                         "detail": ", ".join(sorted(who_emails)[:5])})

    ur = results.get("username", {})
    us_keys = ["all_4", "all_3_no_bb", "all_3_no_mg", "all_3_no_sh", "all_3_no_us",
               "us+sherlock", "us+maigret", "us+blackbird",
               "sherlock+maigret", "sherlock+blackbird", "maigret+blackbird",
               "us_only", "sherlock_only", "maigret_only", "blackbird_only"]
    if "error" not in ur:
        total = sum(len(ur.get(k, [])) for k in us_keys)
        if total:
            corr.append({"type": "info", "desc": f"Username found on {total} platforms",
                         "detail": f"{total} matches across all tools"})

    # Email ↔ Username platform overlap
    er = results.get("email", {})
    if "error" not in er and "error" not in ur:
        email_domains = set()
        for key in ("both", "holehe_only", "user_scanner_only", "blackbird_only"):
            for item in er.get(key, []):
                if "domain" in item:
                    email_domains.add(item["domain"].lower())
        username_domains = set()
        for key in us_keys:
            for item in ur.get(key, []):
                if "domain" in item:
                    username_domains.add(item["domain"].lower())
        overlap = email_domains & username_domains
        if overlap:
            corr.append({"type": "match",
                         "desc": f"Email + username overlap: registered on same platforms",
                         "detail": ", ".join(sorted(overlap)[:8])})

    return corr


def _quick_resolve(domain):
    try:
        import socket
        return socket.gethostbyname(domain)
    except Exception:
        return None
