import json
import sys
import os
import unittest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from bypass_analyzer import fetch_diff, analyze_bypass, build_bypass_display, main


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

    def test_truncates_at_20000_chars(self):
        long_patch = "x" * 25000
        payload = {"files": [{"filename": "big.py", "patch": long_patch}]}
        with patch('urllib.request.urlopen', return_value=self._make_response(payload)):
            result = fetch_diff("owner", "repo", "abc123")
        self.assertLessEqual(len(result), 20000)

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
        self.assertEqual(captured['body']['model'], "claude-sonnet-4-6")
        self.assertEqual(captured['body']['max_tokens'], 1500)

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

    def test_strips_markdown_fences(self):
        inner = {"bypassRisk": "low", "reasoning": "minor edge case", "example": ""}
        fenced = f"```json\n{json.dumps(inner)}\n```"
        body = json.dumps({"content": [{"text": fenced}]}).encode()
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__ = lambda s: resp
        resp.__exit__ = MagicMock(return_value=False)
        with patch('urllib.request.urlopen', return_value=resp):
            result = analyze_bypass("key", "diff", "XSS", "escaped output")
        self.assertEqual(result["bypassRisk"], "low")

    def test_raises_on_unexpected_bypass_risk(self):
        bad = {"bypassRisk": "unknown", "reasoning": "can't tell", "example": ""}
        with patch('urllib.request.urlopen', return_value=self._make_api_response(bad)):
            with self.assertRaises(ValueError):
                analyze_bypass("key", "diff", "XSS", "escaped output")

    def test_affected_code_and_poc_appear_in_prompt(self):
        expected = {"bypassRisk": "none", "reasoning": "ok", "example": ""}
        captured = {}
        def fake_urlopen(req, timeout=None):
            captured['body'] = json.loads(req.data)
            return self._make_api_response(expected)
        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            analyze_bypass(
                "key", "diff", "XSS", "escaped output",
                affected_code="AFFECTED_MARKER",
                proof_of_concept="POC_MARKER",
            )
        user_content = captured['body']['messages'][0]['content']
        self.assertIn("AFFECTED_MARKER", user_content)
        self.assertIn("POC_MARKER", user_content)

    def test_prompt_caching_header_and_structure(self):
        expected = {"bypassRisk": "none", "reasoning": "ok", "example": ""}
        captured = {}
        def fake_urlopen(req, timeout=None):
            captured['req'] = req
            captured['body'] = json.loads(req.data)
            return self._make_api_response(expected)
        with patch('urllib.request.urlopen', side_effect=fake_urlopen):
            analyze_bypass("key", "diff", "XSS", "escaped output")
        self.assertEqual(
            captured['req'].get_header('Anthropic-beta'),
            'prompt-caching-2024-07-31',
        )
        system = captured['body']['system']
        self.assertIsInstance(system, list)
        self.assertEqual(system[0]['type'], 'text')
        self.assertEqual(system[0]['cache_control'], {'type': 'ephemeral'})


class TestBuildBypassDisplay(unittest.TestCase):

    def test_none_risk(self):
        result = build_bypass_display({"bypassRisk": "none", "reasoning": "ok", "example": ""})
        self.assertEqual(result, "✅ Fix looks complete")

    def test_low_risk(self):
        result = build_bypass_display({"bypassRisk": "low", "reasoning": "minor concern", "example": ""})
        self.assertEqual(result, "⚠️ minor concern")

    def test_medium_risk_includes_example(self):
        result = build_bypass_display({"bypassRisk": "medium", "reasoning": "partial fix", "example": "payload"})
        self.assertEqual(result, "🟡 partial fix — payload")

    def test_high_risk_includes_example(self):
        result = build_bypass_display({"bypassRisk": "high", "reasoning": "bypassable", "example": "../etc"})
        self.assertEqual(result, "🔴 bypassable — ../etc")

    def test_unknown_risk(self):
        result = build_bypass_display({"bypassRisk": "unknown", "reasoning": "", "example": ""})
        self.assertEqual(result, "❓ Analysis unavailable")


class TestMain(unittest.TestCase):

    def _make_api_response(self, bypass_dict):
        body = json.dumps({"content": [{"text": json.dumps(bypass_dict)}]}).encode()
        resp = MagicMock()
        resp.read.return_value = body
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def _make_github_response(self):
        payload = {"files": [{"filename": "fix.py", "patch": "@@ -1 +1 @@\n-bad\n+good"}]}
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode()
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_main_writes_enriched_results(self):
        findings = [
            {
                "repo": {"owner": "acme", "repo": "app"},
                "commit": {"sha": "abc123", "url": "https://github.com/acme/app/commit/abc123",
                           "message": "fix", "author": "dev", "date": "2026-01-01T00:00:00Z"},
                "analysis": {"vulnerabilityType": "PathTraversal", "description": "added realpath"},
            }
        ]
        bypass = {"bypassRisk": "high", "reasoning": "missing sep", "example": "../evil"}

        call_count = [0]
        def fake_urlopen(req, timeout=None):
            call_count[0] += 1
            if "api.anthropic.com" in req.full_url:
                return self._make_api_response(bypass)
            return self._make_github_response()

        out_path = os.path.join(tempfile.gettempdir(), "test_enriched.json")
        env = {
            "RESULTS": json.dumps(findings),
            "ANTHROPIC_API_KEY": "test-key",
            "ENRICHED_OUTPUT": out_path,
        }
        with patch('urllib.request.urlopen', side_effect=fake_urlopen), \
             patch.dict('os.environ', env):
            main()

        self.assertEqual(call_count[0], 2)  # one GitHub call + one Anthropic call

        with open(out_path) as f:
            enriched = json.load(f)

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["bypassAnalysis"]["bypassRisk"], "high")

    def test_main_passes_affected_code_and_poc_to_analyzer(self):
        findings = [
            {
                "repo": {"owner": "acme", "repo": "app"},
                "commit": {"sha": "abc123", "url": "https://github.com/acme/app/commit/abc123",
                           "message": "fix", "author": "dev", "date": "2026-01-01T00:00:00Z"},
                "analysis": {
                    "vulnerabilityType": "XSS",
                    "description": "escaped output",
                    "affectedCode": "AFFECTED_CODE_MARKER",
                    "proofOfConcept": "POC_MARKER",
                },
            }
        ]
        bypass = {"bypassRisk": "none", "reasoning": "ok", "example": ""}
        captured = {}

        def fake_urlopen(req, timeout=None):
            if "api.anthropic.com" in req.full_url:
                body = json.loads(req.data)
                captured['user_content'] = body['messages'][0]['content']
                return self._make_api_response(bypass)
            return self._make_github_response()

        out_path = os.path.join(tempfile.gettempdir(), "test_enriched_poc.json")
        env = {
            "RESULTS": json.dumps(findings),
            "ANTHROPIC_API_KEY": "test-key",
            "ENRICHED_OUTPUT": out_path,
        }
        with patch('urllib.request.urlopen', side_effect=fake_urlopen), \
             patch.dict('os.environ', env):
            main()

        self.assertIn("AFFECTED_CODE_MARKER", captured['user_content'])
        self.assertIn("POC_MARKER", captured['user_content'])

    def test_main_handles_per_finding_error_gracefully(self):
        findings = [
            {
                "repo": {"owner": "acme", "repo": "app"},
                "commit": {"sha": "deadbeef", "url": "", "message": "", "author": "", "date": ""},
                "analysis": {"vulnerabilityType": "XSS", "description": "escaped"},
            }
        ]
        out_path = os.path.join(tempfile.gettempdir(), "test_enriched_err.json")
        env = {
            "RESULTS": json.dumps(findings),
            "ANTHROPIC_API_KEY": "test-key",
            "ENRICHED_OUTPUT": out_path,
        }
        with patch('urllib.request.urlopen', side_effect=Exception("network error")), \
             patch.dict('os.environ', env):
            main()

        with open(out_path) as f:
            enriched = json.load(f)

        self.assertEqual(enriched[0]["bypassAnalysis"]["bypassRisk"], "unknown")


if __name__ == '__main__':
    unittest.main()
