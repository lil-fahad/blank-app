import unittest
from email.message import Message
from audit import normalize_origin, evaluate_headers, AuthorizationError, SameOriginRedirect


class AuditTests(unittest.TestCase):
    def test_normalizes_allowed_origin(self):
        self.assertEqual(normalize_origin("https://nour.net.sa/"), "https://nour.net.sa")

    def test_rejects_unrelated_paths_and_query(self):
        with self.assertRaises(ValueError):
            normalize_origin("https://nour.net.sa/customer/123")
        with self.assertRaises(ValueError):
            normalize_origin("https://nour.net.sa/?id=abc")

    def test_rejects_http(self):
        with self.assertRaises(ValueError):
            normalize_origin("http://nour.net.sa")

    def test_blocks_off_origin_redirect(self):
        redirect = SameOriginRedirect("https://nour.net.sa")
        with self.assertRaises(AuthorizationError):
            redirect.redirect_request(None, None, 302, "", {}, "https://example.com/")

    def test_evaluates_cookie_flags_without_values(self):
        headers = Message()
        headers.add_header("Set-Cookie", "my-secret=do-not-leak; Secure; HttpOnly; SameSite=Lax")
        headers.add_header("Content-Security-Policy", "frame-ancestors 'none'")
        headers.add_header("Strict-Transport-Security", "max-age=31536000")
        result = evaluate_headers(headers)
        self.assertTrue(result["hsts_present"])
        self.assertTrue(result["clickjacking_protection_present"])
        self.assertEqual(result["cookie_flags_without_names_or_values"], [
            {"secure": True, "http_only": True, "same_site": True}
        ])
        self.assertNotIn("do-not-leak", str(result))


if __name__ == "__main__":
    unittest.main()
