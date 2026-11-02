import unittest
from baseline_status import compare_statuses, NoRedirect
class Tests(unittest.TestCase):
    def test_query_specific_error(self):
        self.assertTrue(compare_statuses(200,500)["marker_specific_error_candidate"])
    def test_existing_error_not_query_specific(self):
        r=compare_statuses(500,500)
        self.assertFalse(r["marker_specific_error_candidate"])
        self.assertTrue(r["both_server_errors"])
    def test_both_success(self):
        self.assertFalse(compare_statuses(200,200)["marker_specific_error_candidate"])
    def test_no_off_origin_redirect(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,"",{},"https://example.com/"))
