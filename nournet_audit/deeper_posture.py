#!/usr/bin/env python3
"""Two unauthenticated requests and one verified TLS handshake to the exact scoped host."""
import json, re, socket, ssl
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

HOST = "nour.net.sa"
ORIGIN = "https://" + HOST
PATHS = ("/", "/sitemap.xml")

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def analyze_headers(headers, status):
    h = {str(k).lower(): str(v) for k, v in headers.items() if str(k).lower() != "set-cookie"}
    cookies = headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else []
    flags = [[s.strip().lower() for s in cookie.split(";")[1:]] for cookie in cookies]
    csp = h.get("content-security-policy", "")
    directives = {v.strip().split()[0].lower() for v in csp.split(";") if v.strip()}
    sts = h.get("strict-transport-security", "")
    maxage = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)", sts, re.I)
    result = {
        "http_status": status,
        "content_type": h.get("content-type", "").split(";")[0][:80].lower(),
        "hsts": {
            "present": bool(sts),
            "max_age": int(maxage.group(1)) if maxage else None,
            "include_subdomains": bool(re.search(r"(?:^|;)\s*includesubdomains(?:\s*;|\s*$)", sts, re.I))
        },
        "csp": {
            "present": bool(csp),
            "default_src": "default-src" in directives,
            "script_src": "script-src" in directives,
            "object_src": "object-src" in directives,
            "base_uri": "base-uri" in directives,
            "frame_ancestors": "frame-ancestors" in directives,
            "unsafe_inline": "'unsafe-inline'" in csp.lower(),
            "unsafe_eval": "'unsafe-eval'" in csp.lower()
        },
        "headers": {
            "nosniff": h.get("x-content-type-options","").lower()=="nosniff",
            "referrer_policy": bool(h.get("referrer-policy")),
            "permissions_policy": bool(h.get("permissions-policy"))
        },
        "cookies": {
            "count": len(cookies),
            "missing_secure": sum("secure" not in f for f in flags),
            "missing_httponly": sum("httponly" not in f for f in flags),
            "missing_samesite": sum(not any(v.startswith("samesite=") for v in f) for f in flags)
        }
    }
    if h.get("location"):
        u = urlsplit(h["location"])
        result["redirect"] = {
            "host": u.hostname or "relative",
            "within_scope": (u.hostname in (None, HOST) and u.scheme in ("", "https"))
        }
    return result

def detect_error_leak(status, data, content_type):
    if status < 500 or not any(t in content_type for t in ("html","json","xml","text")):
        return False
    patterns = r"(?:Traceback \(most recent call last\)|SQLSTATE\[|PDOException|Stack Trace:|ORA-\d{5}|Unhandled Exception|Fatal error:)"
    return bool(re.search(patterns, data[:8192].decode("utf-8","replace"), re.I))

def tls_check():
    try:
        ctx=ssl.create_default_context()
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        with socket.create_connection((HOST,443),timeout=8) as conn:
            with ctx.wrap_socket(conn,server_hostname=HOST) as s:
                cert=s.getpeercert()
                expiry=datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),timezone.utc)
                return {
                    "certificate_verified_by_trust_store": True,
                    "negotiated_protocol": s.version(),
                    "expires_utc": expiry.strftime("%Y-%m-%d"),
                    "expires_in_days": (expiry-datetime.now(timezone.utc)).days,
                    "certificate_dns_san_count": sum(t=="DNS" for t,_ in cert.get("subjectAltName",[]))
                }
    except (OSError, ssl.SSLError, ValueError, KeyError) as e:
        return {"certificate_verified_by_trust_store": False, "error_type":type(e).__name__}

def http_check():
    op=build_opener(NoRedirect())
    out=[]
    for path in PATHS:
        req=Request(ORIGIN+path,method="GET",headers={"User-Agent":"Scoped-Passive-Posture/1.0"})
        try:
            try:
                response=op.open(req,timeout=8)
            except HTTPError as err:
                response=err
            with response:
                data=response.read(8192) if response.status>=500 else b""
                info=analyze_headers(response.headers,response.status)
                if response.status>=500:
                    info["error_debug_indicators_detected"]=detect_error_leak(response.status,data,info["content_type"])
                out.append({"path":path,**info})
        except (OSError,URLError,TimeoutError) as exc:
            out.append({"path":path,"error_type":type(exc).__name__})
    return out

if __name__=="__main__":
    result={
        "target":ORIGIN,"checked_at_utc":datetime.now(timezone.utc).isoformat(),
        "method":"One trusted TLS handshake and two GET requests, no redirection, no credentials, no exploitation",
        "tls":tls_check(),"http":http_check(),
        "limits":"No raw response bodies, cookies, tokens, certificate subjects, or redirect paths are stored. Indicators are not proof of a vulnerability."
    }
    Path("nournet-tls-posture.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    print("Redacted report written; no raw response body or cookies retained.")
