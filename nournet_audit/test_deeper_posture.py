import unittest
from email.message import Message
from deeper_posture import analyze_headers, detect_error_leak, NoRedirect

class TestScopedPosture(unittest.TestCase):
    def test_cookie_values_never_enter_summary(self):
        h=Message()
        h.add_header("Set-Cookie","private_id=SECRET123; HttpOnly; SameSite=Lax")
        result=analyze_headers(h,200)
        self.assertEqual(result["cookies"]["missing_secure"],1)
        self.assertEqual(result["cookies"]["missing_httponly"],0)
        self.assertNotIn("SECRET123",str(result))
        self.assertNotIn("private_id",str(result))

    def test_csp_checks_are_indicators_only(self):
        h=Message()
        h.add_header("Content-Security-Policy","default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'")
        result=analyze_headers(h,301)
        self.assertTrue(result["csp"]["unsafe_inline"])
        self.assertTrue(result["csp"]["frame_ancestors"])

    def test_off_origin_redirect_is_reported_without_path(self):
        h=Message()
        h.add_header("Location","https://www.nournet.sa/secret?token=secret")
        result=analyze_headers(h,301)
        self.assertFalse(result["redirect"]["within_scope"])
        self.assertEqual(result["redirect"]["host"],"www.nournet.sa")
        self.assertNotIn("secret",str(result))

    def test_no_redirect_is_followed(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,"",{},"https://example.com/"))

    def test_error_body_not_saved(self):
        message=b"PDOException SQLSTATE[HY000] password=supersecret"
        self.assertTrue(detect_error_leak(500,message,"text/html"))
        self.assertFalse(detect_error_leak(200,message,"text/html"))
        self.assertFalse(detect_error_leak(500,b"Internal server error","text/html"))

if __name__=="__main__":
    unittest.main()
