# Security policy

Veil is early, pre-1.0 software. Review the
[deployment guide](docs/deployment.md) before storing real secrets. There is no published
security-support schedule for older versions.

## Report a vulnerability

Do not disclose a vulnerability in a public issue, pull request, or discussion.

If the repository's **Security** tab offers **Report a vulnerability**, use that private form.
If the form is unavailable, open an issue requesting a private reporting channel without
including the vulnerability, affected endpoints, exploit steps, logs, or attachments.
Wait for a private channel before sharing details. A private reporting form is not available
until the repository settings enable it.

In a private report, include the affected version and source commit, the expected security
boundary, the observed behavior, and a reproduction with synthetic values.

Never send real credentials, vault exports, database files, recovery codes, device keys, or
signing seeds, even in a private report. Remove personal information from diagnostics.

For ordinary bugs without a security impact, use the bug report template in GitHub Issues.
