import unittest
from email.message import Message
from bounded_audit import origin_sitemap_paths, redact_response, classify_failure, NoRedirect

class BoundedAuditTests(unittest.TestCase):
    def test_only_same_origin_sitemaps_and_two_paths(self):
        text = """User-agent: *
Sitemap: https://nour.net.sa/sitemap_index.xml
Sitemap: https://www.nournet.sa/sitemap.xml
Sitemap: https://nour.net.sa/sitemap-news.xml
Sitemap: http://nour.net.sa/a.xml
Sitemap: https://nour.net.sa/internal?q=1
Sitemap: https://nour.net.sa/third.xml
"""
        self.assertEqual(origin_sitemap_paths(text, limit=2), ['/sitemap_index.xml', '/sitemap-news.xml'])

    def test_prevent_duplicate_and_bad_paths(self):
        text = """Sitemap: https://nour.net.sa/a.xml
Sitemap: https://nour.net.sa/a.xml
Sitemap: https://nour.net.sa/../../admin
"""
        self.assertEqual(origin_sitemap_paths(text), ['/a.xml'])

    def test_strips_sensitive_headers_and_cookie_values(self):
        h = Message()
        h.add_header('Set-Cookie','auth=supersecret; HttpOnly; SameSite=Lax')
        h.add_header('Location','https://www.nournet.sa/session=verysecret')
        h.add_header('Strict-Transport-Security','max-age=31536000')
        out = redact_response(h, http_status=302)
        self.assertTrue(out['security_headers']['hsts_present'])
        self.assertEqual(out['redirect']['host'],'www.nournet.sa')
        self.assertFalse(out['redirect']['within_explicit_scope'])
        self.assertNotIn('supersecret',str(out))
        self.assertNotIn('verysecret',str(out))

    def test_500_body_fingerprint_only_no_sensitive_literals(self):
        result = classify_failure(500,b'Internal Server Error SQLSTATE[HY000] password=sensitive DB_PASS=secret','text/plain')
        self.assertIn('database_exception_marker',result['evidence_categories'])
        self.assertNotIn('sensitive',str(result))
        self.assertNotIn('secret',str(result))

    def test_plain_500_not_vulnerability(self):
        result = classify_failure(500,b'Internal Server Error','text/html')
        self.assertEqual(result['security_vulnerability_confirmed'],False)
        self.assertEqual(result['evidence_categories'],[])

    def test_no_redirect_following(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://nour.net.sa/next'))

if __name__ == '__main__': unittest.main()
