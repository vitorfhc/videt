# Bypass Analyzer Improvements Design

**Date:** 2026-05-22  
**Status:** Approved  
**Scope:** `scripts/bypass_analyzer.py` and `test/test_bypass_analyzer.py`

## Goal

Improve the depth and accuracy of bypass analysis by feeding the model more relevant context, using a stronger model with more room to reason, and caching static prompt content across calls in the same run.

## Changes

### 1. Context enrichment

The action's analysis step already produces `affectedCode` (vulnerable code before the patch) and `proofOfConcept` (concrete exploit PoC) per finding. The bypass analyzer currently ignores both fields, passing only `vulnerabilityType` and `description` to the model.

`main()` will extract these two additional fields from each finding and pass them through to `analyze_bypass()`. The prompt will include them so the model can verify whether the PoC still works after the patch and whether the affected code path is fully covered.

Updated user message template:

```
Vulnerability type: {vuln_type}
Fix description: {fix_description}
Vulnerable code before patch: {affected_code}
Original proof of concept: {proof_of_concept}

Diff:
{diff}
```

### 2. Model and token budget

- Model: `claude-haiku-4-5-20251001` → `claude-sonnet-4-6`
- `max_tokens`: 512 → 1500

Haiku at 512 tokens cannot reason through multi-step bypass chains. Sonnet has meaningfully stronger security reasoning and 1500 tokens gives it room to work through the logic before producing the JSON. Cost impact is negligible — bypass analysis only runs on confirmed findings, not every scanned commit.

### 3. Prompt caching

Split the single `user` message into a `system` content block (static instructions) and a `user` message (variable fields: vuln type, diff, affected code, PoC).

Add `cache_control: {"type": "ephemeral"}` to the system block and the `anthropic-beta: prompt-caching-2024-07-31` header to the request. This caches the static instructions across multiple findings processed in the same hourly run.

API shape:

```python
{
    "model": "claude-sonnet-4-6",
    "system": [{"type": "text", "text": STATIC_INSTRUCTIONS, "cache_control": {"type": "ephemeral"}}],
    "messages": [{"role": "user", "content": variable_content}],
    "max_tokens": 1500
}
```

### 4. Diff truncation limit

Raise from 8000 → 20000 characters. Large security patches in multi-file repos (Keycloak, WebClients, etc.) can exceed 8000 chars, causing the truncation to hide whether all code paths were covered by the fix.

## Implementation notes

- `_BYPASS_PROMPT` is replaced by two constants: `_SYSTEM_PROMPT` (static instructions) and `_USER_TEMPLATE` (variable fields with `{placeholders}`)
- `analyze_bypass(api_key, diff, vuln_type, fix_description)` gains two new parameters: `affected_code` and `proof_of_concept` (both default to empty string for backwards compatibility)
- No new external dependencies — stdlib only (`urllib`, `json`, `os`)

## Test changes

| Test | Change |
|------|--------|
| `test_sends_correct_model_and_max_tokens` | Assert `claude-sonnet-4-6` and `max_tokens: 1500` |
| `test_diff_appears_in_prompt` | Update to check `messages[0].content` under new structure |
| `test_truncates_at_8000_chars` | Rename to `test_truncates_at_20000_chars`, update threshold |
| New: `test_affected_code_and_poc_appear_in_prompt` | Verify both new fields appear in the user message |
| New: `test_prompt_caching_header_and_structure` | Verify `anthropic-beta` header present and system block has `cache_control` |
