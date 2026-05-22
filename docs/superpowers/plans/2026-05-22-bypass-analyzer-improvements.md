# Bypass Analyzer Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve bypass analysis depth by feeding unused context fields into the prompt, upgrading the model, adding prompt caching, and raising the diff truncation limit.

**Architecture:** All changes are confined to `scripts/bypass_analyzer.py` and its test file. `_BYPASS_PROMPT` is replaced by a `_SYSTEM_PROMPT` (static instructions, cached) and a `_USER_TEMPLATE` (variable fields). `analyze_bypass()` gains two optional parameters (`affected_code`, `proof_of_concept`). `main()` extracts these fields from each finding and passes them through.

**Tech Stack:** Python stdlib only (`urllib`, `json`, `os`), Anthropic Messages API, pytest

---

## File Map

- Modify: `scripts/bypass_analyzer.py` — all logic changes
- Modify: `test/test_bypass_analyzer.py` — test updates and new tests

---

### Task 1: Raise diff truncation limit

**Files:**
- Modify: `scripts/bypass_analyzer.py` (line 29)
- Modify: `test/test_bypass_analyzer.py` (`TestFetchDiff`)

- [ ] **Step 1: Update the truncation test**

In `test/test_bypass_analyzer.py`, replace `test_truncates_at_8000_chars`:

```python
def test_truncates_at_20000_chars(self):
    long_patch = "x" * 25000
    payload = {"files": [{"filename": "big.py", "patch": long_patch}]}
    with patch('urllib.request.urlopen', return_value=self._make_response(payload)):
        result = fetch_diff("owner", "repo", "abc123")
    self.assertLessEqual(len(result), 20000)
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
cd /Users/busfactor/Projects/videt && .venv/bin/pytest test/test_bypass_analyzer.py::TestFetchDiff::test_truncates_at_20000_chars -v
```

Expected: `FAILED` — method name not found (old name was `test_truncates_at_8000_chars`), or the assertion fails if the old 8000-char limit is still in place.

- [ ] **Step 3: Update fetch_diff truncation limit**

In `scripts/bypass_analyzer.py`, change line 29:

```python
    return combined[:20000]
```

- [ ] **Step 4: Run all fetch_diff tests to confirm they pass**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestFetchDiff -v
```

Expected: 4 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/bypass_analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: raise diff truncation limit from 8000 to 20000 chars"
```

---

### Task 2: Upgrade model and token budget

**Files:**
- Modify: `scripts/bypass_analyzer.py` (`analyze_bypass`)
- Modify: `test/test_bypass_analyzer.py` (`TestAnalyzeBypass`)

- [ ] **Step 1: Update the model/token test**

In `test/test_bypass_analyzer.py`, replace the assertions inside `test_sends_correct_model_and_max_tokens`:

```python
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
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestAnalyzeBypass::test_sends_correct_model_and_max_tokens -v
```

Expected: `FAILED` — `AssertionError: 'claude-haiku-4-5-20251001' != 'claude-sonnet-4-6'`

- [ ] **Step 3: Update model and max_tokens in analyze_bypass**

In `scripts/bypass_analyzer.py`, update the payload dict inside `analyze_bypass`:

```python
    payload = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
```

- [ ] **Step 4: Run all analyze_bypass tests to confirm they pass**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestAnalyzeBypass -v
```

Expected: 5 tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/bypass_analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: upgrade bypass analyzer to claude-sonnet-4-6 with 1500 max_tokens"
```

---

### Task 3: New params, prompt restructure, and prompt caching

**Files:**
- Modify: `scripts/bypass_analyzer.py` (`_BYPASS_PROMPT`, `analyze_bypass`)
- Modify: `test/test_bypass_analyzer.py` (`TestAnalyzeBypass`)

- [ ] **Step 1: Write failing test for new params**

Add to `TestAnalyzeBypass` in `test/test_bypass_analyzer.py`:

```python
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
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestAnalyzeBypass::test_affected_code_and_poc_appear_in_prompt -v
```

Expected: `FAILED` — `TypeError: analyze_bypass() got an unexpected keyword argument 'affected_code'`

- [ ] **Step 3: Write failing test for prompt caching**

Add to `TestAnalyzeBypass` in `test/test_bypass_analyzer.py`:

```python
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
```

- [ ] **Step 4: Run the test to confirm it fails**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestAnalyzeBypass::test_prompt_caching_header_and_structure -v
```

Expected: `FAILED` — `KeyError: 'system'` or similar.

- [ ] **Step 5: Restructure analyze_bypass**

In `scripts/bypass_analyzer.py`, replace `_BYPASS_PROMPT` and the `analyze_bypass` function entirely:

```python
_SYSTEM_PROMPT = """\
You are a security code reviewer. A commit was identified as a security fix.
Analyze whether the implementation has bypasses or subtle flaws that still allow exploitation.
Only consider what is visible in the diff — do not speculate about other code paths.

Respond with JSON only (no markdown):
{
  "bypassRisk": "none|low|medium|high",
  "reasoning": "one to two concise paragraphs",
  "example": "concrete bypass technique or payload if risk is not none, else empty string"
}"""

_USER_TEMPLATE = """\
Vulnerability type: {vuln_type}
Fix description: {fix_description}
Vulnerable code before patch: {affected_code}
Original proof of concept: {proof_of_concept}

Diff:
{diff}"""


def analyze_bypass(api_key, diff, vuln_type, fix_description, affected_code="", proof_of_concept=""):
    user_content = (
        _USER_TEMPLATE
        .replace("{vuln_type}", vuln_type)
        .replace("{fix_description}", fix_description)
        .replace("{affected_code}", affected_code)
        .replace("{proof_of_concept}", proof_of_concept)
        .replace("{diff}", diff)
    )
    payload = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 1500,
        "system": [{"type": "text", "text": _SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user_content}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "anthropic-beta": "prompt-caching-2024-07-31",
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    text = data["content"][0]["text"].strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    result = json.loads(text)
    if result.get("bypassRisk") not in ("none", "low", "medium", "high"):
        raise ValueError(f"unexpected bypassRisk value: {result.get('bypassRisk')!r}")
    return result
```

- [ ] **Step 6: Run all analyze_bypass tests to confirm they pass**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestAnalyzeBypass -v
```

Expected: 7 tests PASSED.

- [ ] **Step 7: Run full test suite to confirm no regressions**

```bash
.venv/bin/pytest test/ -v
```

Expected: all tests PASSED.

- [ ] **Step 8: Commit**

```bash
git add scripts/bypass_analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: add affected_code/poc params, system/user split, and prompt caching to bypass analyzer"
```

---

### Task 4: Extract affectedCode and proofOfConcept in main()

**Files:**
- Modify: `scripts/bypass_analyzer.py` (`main`)
- Modify: `test/test_bypass_analyzer.py` (`TestMain`)

- [ ] **Step 1: Add a test verifying main() passes the new fields to the analyzer**

Add a new test to `TestMain` in `test/test_bypass_analyzer.py`:

```python
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
```

- [ ] **Step 2: Run the test to confirm it fails**

```bash
.venv/bin/pytest test/test_bypass_analyzer.py::TestMain::test_main_passes_affected_code_and_poc_to_analyzer -v
```

Expected: `FAILED` — `AssertionError: 'AFFECTED_CODE_MARKER' not found in ...`

- [ ] **Step 3: Update main() to extract and pass the new fields**

In `scripts/bypass_analyzer.py`, update the `main()` function loop. Replace the block that extracts finding fields and calls `analyze_bypass`:

```python
        try:
            owner = finding["repo"]["owner"]
            repo = finding["repo"]["repo"]
            sha = finding["commit"]["sha"]
            vuln_type = finding.get("analysis", {}).get("vulnerabilityType", "Unknown")
            fix_desc = finding.get("analysis", {}).get("description", "")
            affected_code = finding.get("analysis", {}).get("affectedCode", "")
            proof_of_concept = finding.get("analysis", {}).get("proofOfConcept", "")

            diff = fetch_diff(owner, repo, sha)
            if diff.startswith("# Error fetching diff:") or not diff.strip():
                raise ValueError(f"diff unavailable: {diff[:120]}")
            bypass = analyze_bypass(api_key, diff, vuln_type, fix_desc, affected_code, proof_of_concept)
```

- [ ] **Step 4: Run all tests to confirm everything passes**

```bash
.venv/bin/pytest test/ -v
```

Expected: all tests PASSED.

- [ ] **Step 5: Commit**

```bash
git add scripts/bypass_analyzer.py test/test_bypass_analyzer.py
git commit -m "feat: pass affectedCode and proofOfConcept from findings into bypass analyzer"
```
