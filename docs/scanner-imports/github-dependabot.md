# Import GitHub Dependabot repository alerts

A Dependabot alert identifies a vulnerable dependency in **one repository**.
This is a different source from GitHub code scanning and from repository or
global GHSA publications. A GHSA describes affected software; it does not by
itself establish that your repository uses it.

## Export an authorized repository

Use the official GitHub CLI and a fine-grained token or GitHub App installation
with **Dependabot alerts: read** for the intended repository. Dependabot alerts
must be available to the caller. The SDK reads a saved export offline: it does
not fetch private alerts or reuse GitHub credentials for publication.

```bash
set -eu
umask 077
out=$(mktemp -d)
gh api --hostname github.com --method GET --paginate \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  'repos/OWNER/REPO/dependabot/alerts?per_page=100' > "$out/pages.tmp"
jq -e -s 'if length > 0 and all(.[]; type == "array")
  then (add // []) else error("expected alert pages") end' \
  "$out/pages.tmp" > "$out/alerts.tmp"
mv "$out/alerts.tmp" "$out/dependabot.json"
```

Use your actual GitHub hostname and replace `OWNER/REPO` in both steps.
Keep the export outside the checkout. Do not filter to open alerts if you want
closed, dismissed, or reopened history. `--paginate` follows GitHub's
`Link` header; `per_page=100` alone fetches only the first page. Keep the
read and conversion as separate commands: a successful `jq` must not hide a
failed request. A `403` or `404` is not an empty backlog.

## Preview and import

```bash
export CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1
codex-security publish findings "$out/dependabot.json" \
  --to local --repository ./project --provider github \
  --source-key github.com/OWNER/REPO/dependabot --dry-run --format json
```

Review the destination, ready records and exclusions, then remove `--dry-run`.
For Cloud use an authorized repository ID or URL with `--to cloud`. For local
imports a configured remote must agree with the source. Keep the same source
key on replay. A REST list array or an intentionally selected alert is evidence,
not proof that a past export was complete or nothing else is vulnerable.

| GitHub field                     | Codex Security interpretation                                                                                                                                                      |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Repository alert URL and number  | A source occurrence scoped to host, repository and Dependabot. Two alert numbers referencing the same GHSA remain distinct.                                                        |
| Dependency and manifest path     | Reported package, ecosystem and safe repository-relative manifest path; not a vulnerable line of code.                                                                             |
| Matched `security_vulnerability` | Vulnerable version range and first patched version, when present. A manifest constraint is not an installed version; the advisory's other affected packages are not findings here. |
| Advisory identifiers             | GHSA/CVE aliases and vendor evidence, not the source occurrence ID.                                                                                                                |
| State and timestamps             | GitHub's triage and update history. `dismissed` or `fixed` is not a Codex assessment. Omission from a later selection does not delete an occurrence.                               |

Read local evidence with `codex-security findings imported ./project --format json`.
The embedded GHSA is not a disclosure published by the consumer repository.
The importer keeps its source status and advisory details in the native alert
instead of classifying the alert itself as a repository-published advisory.
It rejects conflicting alert identities, advisory packages or ranges, and
manifest URIs; an additional vendor field cannot override the native source.
For large repositories, keep the export for replay and do not combine multiple
repositories under one source key or destination.

References: [GitHub REST repository Dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository),
[GitHub CLI API and pagination](https://cli.github.com/manual/gh_api).
