# Bypass Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After the Sonnet judge confirms a vulnerability finding, fetch its diff from GitHub and call Claude Haiku to detect implementation flaws in the fix, then surface a "Fix Quality" field in the Discord embed.

**Architecture:** A new stdlib-only Python script `scripts/bypass-analyzer.py` runs as a GitHub Actions step between the scan step and the Discord notification step. It reads confirmed findings from the `RESULTS` env var, fetches each commit diff via the GitHub REST API, calls Haiku with a focused prompt, and writes enriched results to `/tmp/enriched-results.json`. The Discord step is modified to read from that file and include a bypass field in each embed.

**Tech Stack:** Python 3 (stdlib only: `json`, `os`, `urllib.request`), Claude Haiku API (`claude-haiku-4-5-20251001`), GitHub REST API (public, no auth), GitHub Actions workflow YAML, `jq` (already present on ubuntu-latest).

---

### Task 1: Create `scripts/bypass-analyzer.py` with `fetch_diff`

**Files:**
- Create: `scripts/bypass-analyzer.py`
- Create: `test/test_bypass_analyzer.py`

- [ ] **Step 1: Write the failing test for `fetch_diff`**

Create `test/test_bypass_analyzer.py`:

```python
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
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
cd /Users/busfactor/Projects/videt
python3 -m pytest test/test_bypass_analyzer.py::TestFetchDiff -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'bypass_analyzer'`

- [ ] **Step 3: Create `scripts/bypass-analyzer.py` with `fetch_diff`**

```python
import json
import os
import urllib.request


def fetch_diff(owner, repo, sha):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "videt-bypass-analyzer",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        return f"# Error fetching diff: {e}"

    parts = []
    for f in data.get("files", []):
        patch = f.get("patch")
        if patch:
            parts.append(f"--- a/{f['filename']}\n{patch}")

    combined = "\n".join(parts)
    return combined[:8000]
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
python3 -m pytest test/test_bypass_analyzer.py::TestFetchDiff -v
```

Expected: 4 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/bypass-analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: add fetch_diff to bypass-analyzer"
```

---

### Task 2: Add `analyze_bypass` to the script

**Files:**
- Modify: `scripts/bypass-analyzer.py`
- Modify: `test/test_bypass_analyzer.py`

- [ ] **Step 1: Write the failing tests for `analyze_bypass`**

Add `from bypass_analyzer import analyze_bypass` to the import block at the top of `test/test_bypass_analyzer.py`, then append these classes:

```python


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
        self.assertEqual(captured['body']['max_tokens'], 256)

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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest test/test_bypass_analyzer.py::TestAnalyzeBypass -v 2>&1 | head -20
```

Expected: `ImportError: cannot import name 'analyze_bypass'`

- [ ] **Step 3: Add `analyze_bypass` to `scripts/bypass-analyzer.py`**

Append after `fetch_diff`:

```python
_BYPASS_PROMPT = """\
You are a security code reviewer. A commit was identified as a security fix.
Analyze whether the implementation has bypasses or subtle flaws that still allow exploitation.
Only consider what is visible in the diff — do not speculate about other code paths.

Vulnerability type: {vuln_type}
Fix description: {fix_description}

Diff:
{diff}

Respond with JSON only (no markdown):
{{
  "bypassRisk": "none|low|medium|high",
  "reasoning": "one concise sentence",
  "example": "concrete bypass technique or payload if risk is not none, else empty string"
}}"""


def analyze_bypass(api_key, diff, vuln_type, fix_description):
    prompt = _BYPASS_PROMPT.format(
        vuln_type=vuln_type,
        fix_description=fix_description,
        diff=diff,
    )
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return json.loads(data["content"][0]["text"].strip())
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
python3 -m pytest test/test_bypass_analyzer.py::TestAnalyzeBypass -v
```

Expected: 3 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/bypass-analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: add analyze_bypass to bypass-analyzer"
```

---

### Task 3: Add `build_bypass_display` and `main` to the script

**Files:**
- Modify: `scripts/bypass-analyzer.py`
- Modify: `test/test_bypass_analyzer.py`

- [ ] **Step 1: Write the failing tests**

Add `import tempfile` and `from bypass_analyzer import build_bypass_display, main` to the import block at the top of `test/test_bypass_analyzer.py`, then append these classes:

```python


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

        with open(out_path) as f:
            enriched = json.load(f)

        self.assertEqual(len(enriched), 1)
        self.assertEqual(enriched[0]["bypassAnalysis"]["bypassRisk"], "high")

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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python3 -m pytest test/test_bypass_analyzer.py::TestBuildBypassDisplay test/test_bypass_analyzer.py::TestMain -v 2>&1 | head -20
```

Expected: `ImportError: cannot import name 'build_bypass_display'`

- [ ] **Step 3: Add `build_bypass_display` and `main` to `scripts/bypass-analyzer.py`**

Append after `analyze_bypass`:

```python
def build_bypass_display(bypass_analysis):
    risk = bypass_analysis.get("bypassRisk", "unknown")
    reasoning = bypass_analysis.get("reasoning", "")
    example = bypass_analysis.get("example", "")
    if risk == "none":
        return "✅ Fix looks complete"
    if risk == "low":
        return f"⚠️ {reasoning}"
    if risk == "medium":
        return f"🟡 {reasoning} — {example}"
    if risk == "high":
        return f"🔴 {reasoning} — {example}"
    return "❓ Analysis unavailable"


def main():
    results_raw = os.environ.get("RESULTS", "[]")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    out_path = os.environ.get("ENRICHED_OUTPUT", "/tmp/enriched-results.json")

    findings = json.loads(results_raw)
    enriched = []

    for finding in findings:
        owner = finding["repo"]["owner"]
        repo = finding["repo"]["repo"]
        sha = finding["commit"]["sha"]
        vuln_type = finding.get("analysis", {}).get("vulnerabilityType", "Unknown")
        fix_desc = finding.get("analysis", {}).get("description", "")

        diff = fetch_diff(owner, repo, sha)

        try:
            bypass = analyze_bypass(api_key, diff, vuln_type, fix_desc)
        except Exception as e:
            bypass = {
                "bypassRisk": "unknown",
                "reasoning": f"Analysis failed: {e}",
                "example": "",
            }

        finding["bypassAnalysis"] = bypass
        enriched.append(finding)

    with open(out_path, "w") as f:
        json.dump(enriched, f)

    print(f"Analyzed {len(enriched)} finding(s)")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run all tests and confirm they pass**

```bash
python3 -m pytest test/test_bypass_analyzer.py -v
```

Expected: all tests PASSED (12 total).

- [ ] **Step 5: Commit**

```bash
git add scripts/bypass-analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: add build_bypass_display and main to bypass-analyzer"
```

---

### Task 4: Add the new workflow step

**Files:**
- Modify: `.github/workflows/vulnerability-monitor.yml:47` (insert before "Notify Discord")

- [ ] **Step 1: Insert the new step before "Notify Discord" in the workflow**

In `.github/workflows/vulnerability-monitor.yml`, insert the following block between the `- id: scan` step (ends at line 46) and the `- name: Notify Discord` step (starts at line 48):

```yaml
      - name: Analyze fix bypass potential
        if: steps.scan.outputs.vulnerabilities-found > 0
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          RESULTS: ${{ steps.scan.outputs.results }}
        run: python3 scripts/bypass-analyzer.py
```

The file should now have this order of steps:
1. `actions/checkout@v4`
2. `id: scan` (the vulnerability-spoiler-alert-action)
3. `name: Analyze fix bypass potential` ← new
4. `name: Notify Discord`
5. `name: Commit state changes`

- [ ] **Step 2: Validate the YAML is well-formed**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/vulnerability-monitor.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/vulnerability-monitor.yml
git commit -m "feat: add bypass analysis workflow step"
```

---

### Task 5: Update the Discord notification step

**Files:**
- Modify: `.github/workflows/vulnerability-monitor.yml` (the "Notify Discord" step)

The Discord step currently gets results from `RESULTS: ${{ steps.scan.outputs.results }}`. We need it to read from `/tmp/enriched-results.json` instead, and add a "Fix Quality" embed field.

- [ ] **Step 1: Remove the `RESULTS` env var from the Discord step and read from file instead**

In the `env:` block of the "Notify Discord" step, remove this line:
```yaml
          RESULTS: ${{ steps.scan.outputs.results }}
```

Then change the first line of the `run:` block from:
```bash
          echo "$RESULTS" | jq -c '.[:5][]' | while read -r vuln; do
```
to:
```bash
          jq -c '.[:5][]' /tmp/enriched-results.json | while read -r vuln; do
```

- [ ] **Step 2: Add bypass variable extraction to the Discord step's run block**

After the existing `commit_date=$(...)` extraction line, add:

```bash
            bypass_risk=$(echo "$vuln" | jq -r '.bypassAnalysis.bypassRisk // "unknown"')
            bypass_reasoning=$(echo "$vuln" | jq -r '.bypassAnalysis.reasoning // ""')
            bypass_example=$(echo "$vuln" | jq -r '.bypassAnalysis.example // ""')
            case "$bypass_risk" in
              none)    bypass_display="✅ Fix looks complete" ;;
              low)     bypass_display="⚠️ $bypass_reasoning" ;;
              medium)  bypass_display="🟡 $bypass_reasoning — $bypass_example" ;;
              high)    bypass_display="🔴 $bypass_reasoning — $bypass_example" ;;
              *)       bypass_display="❓ Analysis unavailable" ;;
            esac
```

- [ ] **Step 3: Add the "Fix Quality" field to the jq payload**

In the `payload=$(jq -n ...)` block, add `--arg bypass_display "$bypass_display"` to the argument list, and add the field to the `fields` array:

```bash
            payload=$(jq -n \
              --arg title "[${severity^^}] Possible silent patch — $repo" \
              --arg url "$issue_url" \
              --argjson color "$color" \
              --arg vuln_type "$vuln_type" \
              --arg commit_link "[$commit_short]($commit_url)" \
              --arg author "$author" \
              --arg commit_msg "$commit_msg" \
              --arg ts "$commit_date" \
              --arg bypass_display "$bypass_display" \
              '{embeds:[{title:$title,url:$url,color:$color,timestamp:$ts,
                fields:[
                  {name:"Type",value:$vuln_type,inline:true},
                  {name:"Commit",value:$commit_link,inline:true},
                  {name:"Author",value:$author,inline:true},
                  {name:"Message",value:$commit_msg,inline:false},
                  {name:"Fix Quality",value:$bypass_display,inline:false}
                ],
                footer:{text:"videt vulnerability monitor"}}]}')
```

- [ ] **Step 4: Validate the YAML**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/vulnerability-monitor.yml'))" && echo "YAML OK"
```

Expected: `YAML OK`

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/vulnerability-monitor.yml
git commit -m "feat: add bypass Fix Quality field to Discord embed"
```

---

### Task 6: Smoke-test the script end-to-end locally

**Files:**
- No file changes — verification only

- [ ] **Step 1: Run the full test suite**

```bash
python3 -m pytest test/test_bypass_analyzer.py -v
```

Expected: all 12 tests PASSED, no warnings.

- [ ] **Step 2: Dry-run `main` with a synthetic fixture**

```bash
RESULTS='[{"repo":{"owner":"vitorfhc","repo":"videt"},"commit":{"sha":"5f6afc87dc851defa387d1b187a5466aec05f48c","url":"https://github.com/vitorfhc/videt/commit/5f6afc87dc851defa387d1b187a5466aec05f48c","message":"Fix path traversal in file download handler","author":"vitorfhc","date":"2026-01-01T00:00:00Z"},"analysis":{"vulnerabilityType":"PathTraversal","description":"added os.path.realpath and startswith check"}}]' \
ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
ENRICHED_OUTPUT=/tmp/dry-run-enriched.json \
python3 scripts/bypass-analyzer.py && \
jq '.[0].bypassAnalysis' /tmp/dry-run-enriched.json
```

Expected: JSON object with `bypassRisk`, `reasoning`, `example` fields. The `reasoning` should mention the missing trailing separator or similar path traversal bypass (the fix in `test/handler.py` uses `startswith(base)` without a `/` suffix, which is bypassable).

- [ ] **Step 3: Confirm no regressions across the full test directory**

```bash
python3 -m pytest test/ -v
```

Expected: all tests pass.
