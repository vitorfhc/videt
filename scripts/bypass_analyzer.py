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


_BYPASS_PROMPT = """\
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
}"""


def analyze_bypass(api_key, diff, vuln_type, fix_description):
    prompt = (
        _BYPASS_PROMPT
        .replace("{vuln_type}", vuln_type)
        .replace("{fix_description}", fix_description)
        .replace("{diff}", diff)
    )
    payload = json.dumps({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 512,
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
