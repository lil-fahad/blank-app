#!/usr/bin/env python3
"""At most five same-origin, unauthenticated GETs; never follows redirects."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

FIXED_ORIGIN = 'https://nour.net.sa'
MAX_READ = 32768

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def origin_sitemap_paths(text, limit=2):
    result = []
    for line in text.splitlines():
        match = re.match(r'^\s*Sitemap\s*:\s*(\S+)\s*$', line, re.IGNORECASE)
        if not match:
            continue
        parsed = urlsplit(match.group(1))
        if (parsed.scheme != 'https' or parsed.netloc.lower() != 'nour.net.sa'
                or parsed.query or parsed.fragment or not parsed.path.startswith('/')
                or '..' in parsed.path or '\\' in parsed.path or '%' in parsed.path
                or not re.fullmatch(r'/[A-Za-z0-9/_\-.]+', parsed.path)):
            continue
        if parsed.path not in result and parsed.path not in ('/robots.txt','/sitemap.xml','/'):
            result.append(parsed.path)
        if len(result) >= limit:
            break
    return result

def redact_response(headers, http_status):
    h = {str(name).lower():str(v) for name,v in headers.items() if str(name).lower()!='set-cookie'}
    csp = h.get('content-security-policy','').lower()
    cookies = headers.get_all('Set-Cookie', []) if hasattr(headers,'get_all') else []
    value = {
        'http_status': http_status,
        'content_type': h.get('content-type','').split(';')[0][:80].lower(),
        'security_headers': {
            'hsts_present': bool(h.get('strict-transport-security')),
            'csp_present': bool(csp),
            'nosniff_present': h.get('x-content-type-options','').lower() == 'nosniff',
            'referrer_policy_present': bool(h.get('referrer-policy')),
            'clickjacking_policy_present': 'frame-ancestors' in csp or bool(h.get('x-frame-options')),
            'cookies_observed': len(cookies),
            'cookies_missing_secure': sum('secure' not in [x.strip().lower() for x in raw.split(';')[1:]] for raw in cookies),
            'cookies_missing_httponly': sum('httponly' not in [x.strip().lower() for x in raw.split(';')[1:]] for raw in cookies),
        }
    }
    location = h.get('location', '')
    if location:
        redirect = urlsplit(location)
        value['redirect'] = {
            'host': (redirect.hostname or 'relative')[:128],
            'within_explicit_scope': bool((redirect.hostname in (None, 'nour.net.sa')) and (redirect.scheme in ('', 'https'))),
        }
    return value

def classify_failure(status, body, content_type):
    output = {'security_vulnerability_confirmed': False, 'evidence_categories': []}
    if status < 500 or not any(s in (content_type or '').lower() for s in ('text','json','xml','html')):
        return output
    sample = body[:MAX_READ].decode('utf-8','replace').lower()
    patterns = {
       'python_traceback_marker': r'traceback \(most recent call last\)',
       'aspnet_debug_marker': r'server error in [\'\"]?/[^\s]* application|asp\.net version information',
       'database_exception_marker': r'sqlstate\[|pdoexception|sql syntax.*mysql|mysql_(?:fetch|query)|ora-\d{5}',
       'stacktrace_marker': r'exception in thread|stack trace:|at (?:[a-z][\w$]+\.){2,}[\w$]+\(',
       'runtime_exception_marker': r'uncaught (?:exception|error)|fatal error:|unhandled exception',
    }
    output['evidence_categories'] = [name for name,pattern in patterns.items() if re.search(pattern,sample)]
    return output

def request_one(opener, path):
    req = Request(FIXED_ORIGIN + path, headers={'User-Agent':'Bounded-Authorized-Passive-Check/1.0', 'Accept':'text/html,application/xml,text/plain,*/*'}, method='GET')
    try:
        try:
            response = opener.open(req, timeout=10)
        except HTTPError as exc:
            response = exc
        with response:
            data = response.read(MAX_READ) if path == '/robots.txt' or response.status >= 500 else b''
            info = redact_response(response.headers, response.status)
            if response.status >= 500:
                info['error_page_indicators'] = classify_failure(response.status, data, info['content_type'])
            return info, data if path == '/robots.txt' else b''
    except (URLError, OSError, TimeoutError) as exc:
        return {'network_error_type':type(exc).__name__, 'reachable':False}, b''

def run():
    opener = build_opener(NoRedirect())
    output = {
        'scope': FIXED_ORIGIN,
        'checked_at_utc': datetime.now(timezone.utc).isoformat(),
        'requests_limit': 5,
        'methods': 'GET only, unauthenticated, never follow redirects',
        'results': [],
        'caution': 'Passive diagnostics only. No demonstrated vulnerability. No sensitive response bodies recorded.',
    }
    robots_text = ''
    for path in ('/','/robots.txt','/sitemap.xml'):
        info, body = request_one(opener,path)
        if path == '/robots.txt' and info.get('http_status') == 200:
            robots_text = body.decode('utf-8','replace')
        output['results'].append({'path':path, **info})
    paths = origin_sitemap_paths(robots_text, 2)
    output['robots_sitemaps'] = {
        'same_origin_candidates_tested': paths,
        'note': 'Only exact-origin declared paths are eligible for the two additional requests.'
    }
    for path in paths:
        info, _ = request_one(opener,path)
        output['results'].append({'path':path,**info})
    return output

if __name__=='__main__':
    report = run()
    Path('nournet-expanded-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Wrote nournet-expanded-report.json: '+str(len(report['results']))+' bounded requests')
