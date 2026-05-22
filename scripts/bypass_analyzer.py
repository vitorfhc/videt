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
