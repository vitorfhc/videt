import json
import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from bypass_analyzer import fetch_diff


class TestFetchDiff(unittest.TestCase):

    def _make_response(self, payload):
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_concatenates_file_patches_with_headers(self):
        payload = {
            "files": [
                {"filename": "src/foo.py", "patch": "@@ -1 +1 @@\n-old\n+new"},
                {"filename": "src/bar.py", "patch": "@@ -2 +2 @@\n-x\n+y"},
            ]
        }
        with patch('urllib.request.urlopen', return_value=self._make_response(payload)):
            result = fetch_diff("owner", "repo", "abc123")
        self.assertIn("--- a/src/foo.py", result)
        self.assertIn("@@ -1 +1 @@\n-old\n+new", result)
        self.assertIn("--- a/src/bar.py", result)

    def test_truncates_at_8000_chars(self):
        long_patch = "x" * 10000
        payload = {"files": [{"filename": "big.py", "patch": long_patch}]}
        with patch('urllib.request.urlopen', return_value=self._make_response(payload)):
            result = fetch_diff("owner", "repo", "abc123")
        self.assertLessEqual(len(result), 8000)

    def test_returns_error_message_on_network_failure(self):
        with patch('urllib.request.urlopen', side_effect=Exception("timeout")):
            result = fetch_diff("owner", "repo", "abc123")
        self.assertIn("Error fetching diff", result)

    def test_skips_files_without_patch(self):
        payload = {
            "files": [
                {"filename": "binary.bin"},
                {"filename": "code.py", "patch": "@@ -1 +1 @@\n-a\n+b"},
            ]
        }
        with patch('urllib.request.urlopen', return_value=self._make_response(payload)):
            result = fetch_diff("owner", "repo", "abc123")
        self.assertNotIn("binary.bin", result)
        self.assertIn("code.py", result)


if __name__ == '__main__':
    unittest.main()
