# videt

Automated monitor for **silent security patches** — detects vulnerability fixes in major open-source projects before a CVE is publicly assigned.

## What problem does this solve?

There's a dangerous window between when a security patch lands in source code and when it gets a CVE number. During this "negative-day" period, the vulnerability is effectively public (anyone can read the diff) but most defenders haven't acted yet. videt closes that gap by alerting you the moment a suspicious commit is detected.

## How it works

1. A GitHub Action runs every hour
2. [`vulnerability-spoiler-alert-action`](https://github.com/spaceraccoon/vulnerability-spoiler-alert-action) fetches recent commits from each monitored repo
3. Claude AI triages commits for security relevance, then a judge model verifies findings
4. Confirmed findings create a labeled GitHub Issue in this repo
5. A Discord embed is sent immediately with severity, type, commit link, and issue link

## Monitored repositories

See [vulnerability-monitor.yml](.github/workflows/vulnerability-monitor.yml).

## Setup

Fork this repo, then add two repository secrets under **Settings → Secrets and variables → Actions**:

| Secret | Value |
|--------|-------|
| `ANTHROPIC_API_KEY` | Your Anthropic API key from [console.anthropic.com](https://console.anthropic.com) |
| `DISCORD_WEBHOOK_URL` | Webhook URL from your Discord server (see below) |

The workflow runs automatically on the next hour tick. You can also trigger it manually from the **Actions** tab.

### Discord webhook setup

1. Open your Discord server → **Server Settings → Integrations → Webhooks**
2. Click **New Webhook**, choose a channel, copy the URL
3. Add it as the `DISCORD_WEBHOOK_URL` secret above

## Outputs

- **GitHub Issues** — one per confirmed finding, labelled `vulnerability` and `severity:critical/high/medium/low`
- **Discord embeds** — colour-coded by severity (red → critical, orange → high, yellow → medium, green → low), linking to the issue and commit

## Disclaimer

All findings are AI-generated and advisory only. Verify independently before taking action. Expect false positives.
