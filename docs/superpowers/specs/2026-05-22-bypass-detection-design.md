# Bypass Detection for Confirmed Vulnerability Findings

**Date:** 2026-05-22
**Status:** Approved

## Problem

videt detects silent security patches — commits that fix vulnerabilities before a CVE is assigned. Currently, once a finding is confirmed, there is no analysis of whether the fix itself is correct. A defender who acts on a videt alert might believe they are protected when the patch still has an exploitable flaw (e.g., a path traversal fix using `startswith` without a trailing separator).

## Goal

For each confirmed finding, determine whether the fix implementation has bypasses or subtle implementation flaws — surfaced in the Discord embed, at negligible extra cost.

## Scope

- **Trigger:** Confirmed findings only (post-judge). Does not run on triage-only commits.
- **Bypass type:** Implementation flaws visible in the commit diff. Does not analyze other code paths or architectural gaps.
- **Output:** Discord embed only. GitHub Issues are unchanged.

## Pipeline

**Before:**
```
commits → Haiku triage (25% pass) → Sonnet judge → GitHub Issue + Discord
```

**After:**
```
commits → Haiku triage (25% pass) → Sonnet judge → bypass-analyzer.py → GitHub Issue + Discord (enriched)
```

The bypass step is gated by `if: steps.scan.outputs.vulnerabilities-found > 0`, identical to the existing Discord step.

## New Component: `scripts/bypass-analyzer.py`

A self-contained Python script using stdlib only (no pip installs required on the GitHub Actions runner).

### Inputs

- `RESULTS` env var: the raw JSON array from `steps.scan.outputs.results`
- `ANTHROPIC_API_KEY` env var: existing secret, no new secrets needed

### Per-finding logic

1. **Fetch diff** — `GET https://api.github.com/repos/{owner}/{repo}/commits/{sha}` with `Accept: application/json`. Collect `files[].patch` fields, concatenate, truncate at 8 000 characters. No GitHub token required for public repos.
2. **Call Haiku** — send diff + vuln type + fix description. Max 256 output tokens.
3. **Parse response** — extract `bypassRisk`, `reasoning`, `example` from JSON output.
4. **Append** `bypassAnalysis` object to the finding.

### Output

Writes `/tmp/enriched-results.json` — the original results array with `bypassAnalysis` added to each element.

### Error handling

If diff fetch or Haiku call fails for a finding, `bypassAnalysis` is set to `{"bypassRisk": "unknown", "reasoning": "Analysis unavailable", "example": ""}`. The step does not fail the workflow on per-finding errors.

## Haiku Prompt

```
You are a security code reviewer. A commit was identified as a security fix.
Analyze whether the implementation has bypasses or subtle flaws that still allow exploitation.
Only consider what is visible in the diff — do not speculate about other code paths.

Vulnerability type: {vuln_type}
Fix description: {fix_description}

Diff:
{diff}

Respond with JSON only (no markdown):
{
  "bypassRisk": "none|low|medium|high",
  "reasoning": "one concise sentence",
  "example": "concrete bypass technique or payload if risk is not none, else empty string"
}
```

`max_tokens: 256` keeps output cost negligible.

## Workflow Changes

### New step (insert before "Notify Discord")

```yaml
- name: Analyze fix bypass potential
  if: steps.scan.outputs.vulnerabilities-found > 0
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    RESULTS: ${{ steps.scan.outputs.results }}
  run: python3 scripts/bypass-analyzer.py
```

### Discord step changes

1. Change results source:
   - Before: `RESULTS: ${{ steps.scan.outputs.results }}`
   - After: read from `/tmp/enriched-results.json` via `RESULTS=$(cat /tmp/enriched-results.json)`

2. Add bypass variables from each finding:
   ```bash
   bypass_risk=$(echo "$vuln" | jq -r '.bypassAnalysis.bypassRisk // "unknown"')
   bypass_text=$(echo "$vuln" | jq -r '.bypassAnalysis.reasoning // ""')
   bypass_example=$(echo "$vuln" | jq -r '.bypassAnalysis.example // ""')
   ```

3. Build bypass display value:
   - `none` → `✅ Fix looks complete`
   - `low` → `⚠️ {reasoning}`
   - `medium` → `🟡 {reasoning} — {example}`
   - `high` → `🔴 {reasoning} — {example}`
   - `unknown` → `❓ Analysis unavailable`

4. Add one new embed field:
   ```json
   {"name": "Fix Quality", "value": "{bypass_display}", "inline": false}
   ```

## Cost Impact

Haiku pricing: ~$0.25/M input tokens, ~$1.25/M output tokens.

Per finding: ~2 500 input tokens (8 000-char diff ≈ 2 000 tokens + prompt overhead) + 100 output tokens.
- Input: 2 500 × $0.00000025 = **$0.000625**
- Output: 100 × $0.00000125 = **$0.000125**
- Total per finding: **~$0.00075**

At 10 confirmed findings/day: ~$0.23/month. At 1/day: ~$0.023/month. Negligible against the $21/month baseline.

## Example Output (Discord embed field)

| Scenario | Fix Quality field |
|---|---|
| Correct fix | ✅ Fix looks complete |
| Minor concern | ⚠️ The startswith check may not prevent sibling-directory paths |
| Exploitable flaw | 🔴 Missing path separator allows /var/app/files-evil bypass — try path `../files-evil/secret` |
