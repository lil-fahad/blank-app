#!/usr/bin/env python3
"""Four low-impact same-origin GETs; benign HTML marker, no scripts."""
import html, json
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import build_opener, HTTPRedirectHandler, Request

ORIGIN = "https://nour.net.sa"
MARKER = "AUDITB5C1ONLY"
TAG = '<b data-audit="AUDITB5C1ONLY">test</b>'
PATHS = ["/contact-us/", "/ar/contact-us/", "/", "/ar/"]

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def classify(body):
    """Only report booleans; never store response HTML."""
    raw = body.decode("utf-8", "replace")
    return {
        "marker_reflected": MARKER in raw,
        "exact_markup_in_response": TAG in raw,
        "escaped_markup_in_response": html.escape(TAG, quote=True) in raw,
        "markup_decodes_in_text": TAG in html.unescape(raw),
        "note": "Reflection does not establish XSS or reportability."
    }

def probe():
    opener = build_opener(NoRedirect())
    result = {
        "origin": ORIGIN,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "method": "Four GET requests; same host only; no redirects followed; benign marker and HTML tag, no scripts",
        "results": []
    }
    for path in PATHS:
        url = ORIGIN + path + "?" + urlencode({"s": TAG})
        req = Request(url, method="GET", headers={"User-Agent": "Scoped-Benign-Canary/1.0"})
        item = {"path": path, "query": "s=BENIGN_HTML_MARKER"}
        try:
            try:
                res = opener.open(req, timeout=8)
            except HTTPError as err:
                res = err
            with res:
                item["status"] = res.status
                item["content_type"] = res.headers.get("Content-Type", "").split(";")[0][:60]
                if res.status == 200 and "text/html" in item["content_type"].lower():
                    item.update(classify(res.read(131072)))
        except (URLError, OSError, TimeoutError) as exc:
            item["error_type"] = type(exc).__name__
        result["results"].append(item)
    return result

if __name__ == "__main__":
    with open("nournet-canary-report.json", "w", encoding="utf-8") as fp:
        json.dump(probe(), fp, indent=2, ensure_ascii=False)
    print("Saved redacted canary results.")
