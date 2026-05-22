import json
import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from io import BytesIO

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from bypass_analyzer import fetch_diff, analyze_bypass


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


class TestAnalyzeBypass(unittest.TestCase):

    def _make_api_response(self, bypass_dict):
        body = json.dumps({
            "content": [{"text": json.dumps(bypass_dict)}]
        }).encode()
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_returns_parsed_bypass_dict(self):
        expected = {"bypassRisk": "high", "reasoning": "missing sep", "example": "../etc"}
        with patch('urllib.request.urlopen', return_value=self._make_api_response(expected)):
            result = analyze_bypass("key", "diff content", "PathTraversal", "added realpath check")
        self.assertEqual(result["bypassRisk"], "high")
        self.assertEqual(result["reasoning"], "missing sep")
        self.assertEqual(result["example"], "../etc")

    def test_sends_correct_model_and_max_tokens(self):
        expected = {"bypassRisk": "none", "reasoning": "ok", "example": ""}
        captured = {}
        def fake_urlopen(req, timeout=None):
            captured['body'] = json.loads(req.data)
            return self._make_api_response(expected)
        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            analyze_bypass("key", "diff", "XSS", "escaped output")
        self.assertEqual(captured['body']['model'], "claude-haiku-4-5-20251001")
        self.assertEqual(captured['body']['max_tokens'], 512)

    def test_diff_appears_in_prompt(self):
        expected = {"bypassRisk": "none", "reasoning": "ok", "example": ""}
        captured = {}
        def fake_urlopen(req, timeout=None):
            captured['body'] = json.loads(req.data)
            return self._make_api_response(expected)
        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            analyze_bypass("key", "UNIQUE_DIFF_MARKER", "SQLi", "parameterized query")
        prompt = captured['body']['messages'][0]['content']
        self.assertIn("UNIQUE_DIFF_MARKER", prompt)


if __name__ == '__main__':
    unittest.main()
