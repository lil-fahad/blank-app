import unittest
from benign_canary import classify, NoRedirect

class Tests(unittest.TestCase):
    def test_escaped_markup_not_raw(self):
        value=b'&lt;b data-audit=&quot;AUDITB5C1ONLY&quot;&gt;test&lt;/b&gt;'
        r=classify(value)
        self.assertTrue(r["marker_reflected"])
        self.assertTrue(r["escaped_markup_in_response"])
        self.assertFalse(r["exact_markup_in_response"])
    def test_plain_marker_not_markup(self):
        r=classify(b'AUDITB5C1ONLY')
        self.assertTrue(r["marker_reflected"])
        self.assertFalse(r["exact_markup_in_response"])
    def test_raw_markup_detected(self):
        self.assertTrue(classify(b'<b data-audit="AUDITB5C1ONLY">test</b>')["exact_markup_in_response"])
    def test_no_response_body_stored(self):
        self.assertNotIn("SECRET",str(classify(b'SECRET USER RECORD')))
    def test_never_follow_redirect(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,"",{},"https://elsewhere.example"))
