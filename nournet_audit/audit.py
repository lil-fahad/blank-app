#!/usr/bin/env python3
"""Bounded, unauthenticated security-header review; no exploitation or scanning."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class AuthorizationError(RuntimeError):
    pass


def normalize_origin(value):
    parts = urlsplit(value)
    if not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("Specify an origin URL without credentials, query or fragment")
    if parts.path not in ("", "/"):
        raise ValueError("Specify only the origin URL")
    if parts.scheme != "https":
        raise ValueError("An HTTPS origin is required")
    return urlunsplit(("https", parts.netloc.lower(), "", "", ""))


class SameOriginRedirect(HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urlsplit(newurl)
        new_origin = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "", "", ""))
        if new_origin != self.origin:
            raise AuthorizationError("Off-origin redirect blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def evaluate_headers(headers):
    lower = {name.lower(): value for name, value in headers.items()}
    csp = lower.get("content-security-policy", "")
    cookies = []
    for raw in headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else []:
        attributes = [part.strip().lower() for part in raw.split(";")[1:]]
        cookies.append({
            "secure": "secure" in attributes,
            "http_only": "httponly" in attributes,
            "same_site": any(part.startswith("samesite=") for part in attributes),
        })
    return {
        "hsts_present": bool(lower.get("strict-transport-security")),
        "csp_present": bool(csp),
        "nosniff_present": lower.get("x-content-type-options", "").lower() == "nosniff",
        "referrer_policy_present": bool(lower.get("referrer-policy")),
        "clickjacking_protection_present": "frame-ancestors" in csp.lower() or bool(lower.get("x-frame-options")),
        "cookie_flags_without_names_or_values": cookies,
        "note": "Missing headers indicate possible hardening gaps, not proven exploitable vulnerabilities.",
    }


def inspect(origin):
    opener = build_opener(SameOriginRedirect(origin))
    report = {
        "origin": origin,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": "At most one unauthenticated GET per public path; same-origin redirects only",
        "requests": [],
        "limitations": "No fuzzing, enumeration, login, injection, payment tests, exploitation or vulnerability claims.",
    }
    for path in ("/", "/robots.txt", "/sitemap.xml"):
        entry = {"path": path}
        request = Request(
            origin + path,
            headers={"User-Agent": "Authorized-Passive-Audit/1.0", "Accept": "text/html, text/plain, application/xml, */*"},
            method="GET",
        )
        try:
            with opener.open(request, timeout=10) as response:
                entry["http_status"] = response.status
                if path == "/":
                    entry["security_headers"] = evaluate_headers(response.headers)
        except HTTPError as error:
            entry["http_status"] = error.code
            if path == "/":
                entry["security_headers"] = evaluate_headers(error.headers)
        except (URLError, OSError, AuthorizationError) as error:
            entry["error"] = str(error)[:300]
        report["requests"].append(entry)
    return report


def main():
    parser = argparse.ArgumentParser(description="Three-request passive check for an authorized website")
    parser.add_argument("origin", help="Exact HTTPS origin, e.g. https://nour.net.sa")
    parser.add_argument("--output", default="report.json")
    args = parser.parse_args()
    origin = normalize_origin(args.origin)
    # Limit this GitHub workflow's script to the program's explicitly listed origin.
    if origin != "https://nour.net.sa":
        parser.error("This workflow only permits https://nour.net.sa")
    report = inspect(origin)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Report written to {args.output}")


if __name__ == "__main__":
    main()
