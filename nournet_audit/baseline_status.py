#!/usr/bin/env python3
"""Compare status codes using 6 benign GETs on one explicitly scoped origin."""
import json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, HTTPRedirectHandler, build_opener

ORIGIN = "https://nour.net.sa"
PATHS = ("/contact-us/", "/ar/contact-us/", "/ar/")
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def compare_statuses(base, marker):
    return {
        "baseline_http_status": base,
        "safe_marker_http_status": marker,
        "marker_specific_error_candidate": base < 500 and marker >= 500,
        "both_server_errors": base >= 500 and marker >= 500
    }

def fetch_status(opener, path, marker=False):
    url = ORIGIN + path + (("?" + urlencode({"s": "AUDITCANARYONLY"})) if marker else "")
    request = Request(url, method="GET", headers={"User-Agent":"Bounded-Status-Comparison/1.0"})
    try:
        try:
            r = opener.open(request, timeout=8)
        except HTTPError as e:
            r = e
        with r:
            return {"status":r.status}
    except (URLError, OSError, TimeoutError) as err:
        return {"error_type":type(err).__name__}

def run():
    opener = build_opener(NoRedirect())
    rows=[]
    for path in PATHS:
        base=fetch_status(opener,path)
        marked=fetch_status(opener,path,True)
        row={"path":path,"baseline":base,"marked":marked}
        if "status" in base and "status" in marked:
            row.update(compare_statuses(base["status"],marked["status"]))
        rows.append(row)
    return {"origin":ORIGIN,
            "checked_at_utc":datetime.now(timezone.utc).isoformat(),
            "scope":"6 unauthenticated GETs, no redirects followed, no response body or cookies stored",
            "results":rows,
            "disclaimer":"An HTTP 500 response is not in itself a security vulnerability."}

if __name__ == "__main__":
    with open("nournet-baseline-status-report.json","w",encoding="utf-8") as f:
        json.dump(run(),f,indent=2,ensure_ascii=False)
    print("Saved redacted baseline comparison.")
