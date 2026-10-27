import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import { record, relativePath, requiredText, text } from "./scanner-import.js";

export function isGitHubDependabotAlert(
  value: unknown,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    ("security_vulnerability" in value ||
      ("dependency" in value && "security_advisory" in value) ||
      [value["url"], value["html_url"]].some(
        (url) =>
          typeof url === "string" &&
          /\/(?:dependabot\/alerts|security\/dependabot)\//u.test(url),
      ))
  );
}

function identity(alert: Record<string, unknown>) {
  if (
    alert["source"] === "github-code-scanning" ||
    alert["source"] === "github-security-advisory"
  )
    throw new Error(
      "Dependabot alert conflicts with its GitHub source family.",
    );
  const number = alert["number"];
  if (typeof number !== "number" || !Number.isSafeInteger(number) || number < 1)
    throw new Error("Dependabot alert number must be a positive safe integer.");
  const url = requiredText(alert["html_url"], "Dependabot html_url");
  const match =
    /^https:\/\/([^/?#@\\\s]+)\/([a-z0-9_.-]+)\/([a-z0-9_.-]+)\/security\/dependabot\/([0-9]+)$/iu.exec(
      url,
    );
  if (
    !match ||
    match[4] !== String(number) ||
    match.slice(2, 4).some((part) => /^\.{1,2}$/u.test(part))
  )
    throw new Error(
      "Dependabot html_url must identify the repository and alert number.",
    );
  const host = match[1]!.toLowerCase();
  const hostname = new URL(url).hostname;
  const repository = `${match[2]}/${match[3]}`.toLowerCase();
  const repositoryUrl = `https://${host}/${repository}`;
  const apiBase = isGitHubCloudHost(hostname)
    ? `https://api.${host}`
    : `https://${host}/api/v3`;
  const apiRepo = `${apiBase}/repos/${repository}`;
  if (
    requiredText(alert["url"], "Dependabot API url").toLowerCase() !==
    `${apiRepo}/dependabot/alerts/${number}`
  )
    throw new Error(
      "Dependabot API url and html_url must identify the same host, repository and alert number.",
    );
  if ("repository" in alert) {
    const declared = record(alert["repository"], "Dependabot repository");
    if (
      text(declared["full_name"])?.toLowerCase() !== repository ||
      ("html_url" in declared &&
        text(declared["html_url"])?.toLowerCase() !== repositoryUrl) ||
      ("url" in declared && text(declared["url"])?.toLowerCase() !== apiRepo)
    )
      throw new Error(
        "Dependabot repository metadata conflicts with its alert URLs.",
      );
  }
  return {
    repositoryUrl,
    sourceId: `${host}/${repository}/dependabot/${number}`,
    url,
  };
}

export function dependabotEvidenceRepositoryUrls(
  sourceData: unknown,
  expectedSourceFindingId?: string,
): string[] {
  if (!isGitHubDependabotAlert(sourceData)) return [];
  const { sourceId, repositoryUrl } = identity(sourceData);
  if (
    expectedSourceFindingId !== undefined &&
    expectedSourceFindingId !== sourceId
  )
    throw new CodexSecurityError(
      "The normalized source finding ID does not match the original Dependabot alert.",
    );
  return [repositoryUrl];
}

function selectedAlerts(input: unknown) {
  const selection = Array.isArray(input) ? input : [input];
  let rows: unknown[] = selection;
  if (selection.some(Array.isArray)) {
    if (
      !selection.every(Array.isArray) ||
      (selection.length > 1 && selection.some((page) => page.length === 0))
    )
      throw new Error(
        "Dependabot input must not mix alerts, incomplete pages or empty pages in a paginated selection.",
      );
    rows = selection.flat();
  }
  if (!rows.every(isGitHubDependabotAlert))
    throw new Error(
      "Expected complete native Dependabot repository alerts, not mixed families, page shapes or API envelopes.",
    );
  return rows;
}

function evidence(alert: Record<string, unknown>, url: string) {
  const dependency = record(alert["dependency"], "Dependabot dependency");
  const advisory = record(
    alert["security_advisory"],
    "Dependabot security_advisory",
  );
  const vulnerability = record(
    alert["security_vulnerability"],
    "Dependabot security_vulnerability",
  );
  const pkg = record(vulnerability["package"], "Dependabot matched package");
  const name = requiredText(pkg["name"], "Dependabot package name");
  const ecosystem = requiredText(
    pkg["ecosystem"],
    "Dependabot package ecosystem",
  );
  const observed = record(
    dependency["package"],
    "Dependabot dependency package",
  );
  if (observed["name"] !== name || observed["ecosystem"] !== ecosystem)
    throw new Error(
      "Dependabot dependency and matched vulnerability packages disagree.",
    );
  const rawPath = dependency["manifest_path"];
  const path =
    typeof rawPath === "string" && /^[a-z][a-z\d+.-]*:/iu.test(rawPath)
      ? null
      : relativePath(rawPath);
  if (rawPath != null && !path)
    throw new Error(
      "Dependabot manifest_path must be a repository-relative path.",
    );
  const ghsa = requiredText(advisory["ghsa_id"], "Dependabot GHSA ID");
  if (!/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/iu.test(ghsa))
    throw new Error("Dependabot security_advisory must identify a GHSA.");
  const range = requiredText(
    vulnerability["vulnerable_version_range"],
    "Dependabot matched vulnerable version range",
  );
  const affected = advisory["vulnerabilities"];
  if (
    !Array.isArray(affected) ||
    !affected.some(
      (entry) =>
        isRecord(entry) &&
        isRecord(entry["package"]) &&
        entry["package"]["name"] === name &&
        entry["package"]["ecosystem"] === ecosystem &&
        entry["vulnerable_version_range"] === range,
    )
  )
    throw new Error(
      "Dependabot advisory does not cover the matched package and vulnerable range.",
    );
  const state = alert["state"];
  if (
    typeof state !== "string" ||
    !["open", "dismissed", "auto_dismissed", "fixed"].includes(state)
  )
    throw new Error(
      "Dependabot alert state must be open, dismissed, auto_dismissed or fixed.",
    );
  const updated =
    Date.parse(requiredText(alert["updated_at"], "Dependabot updated_at")) /
    1000;
  if (!Number.isFinite(updated) || updated < 0)
    throw new Error("Dependabot updated_at must be a valid timestamp.");
  const patch = vulnerability["first_patched_version"];
  const fixed =
    patch === null
      ? []
      : [
          requiredText(
            record(patch, "Dependabot first_patched_version")["identifier"],
            "Dependabot patched version",
          ),
        ];
  const severity = requiredText(
    vulnerability["severity"],
    "Dependabot matched severity",
  );
  if (!["critical", "high", "medium", "low"].includes(severity))
    throw new Error("Invalid Dependabot matched vulnerability severity.");
  const aliases = Array.isArray(advisory["identifiers"])
    ? advisory["identifiers"].flatMap((item) => {
        const value = isRecord(item) ? text(item["value"]) : null;
        if (
          value &&
          (item["type"] === "GHSA" || /^GHSA-/iu.test(value)) &&
          value.toUpperCase() !== ghsa.toUpperCase()
        )
          throw new Error(
            "Dependabot advisory identifiers disagree on the GHSA.",
          );
        return value === null ? [] : [value];
      })
    : [];
  return {
    title: requiredText(advisory["summary"], "Dependabot advisory summary"),
    description: text(advisory["description"]),
    severity,
    url,
    advisory_ids: [
      ...new Set(
        [ghsa, text(advisory["cve_id"]), ...aliases].filter(
          (value): value is string => value !== null,
        ),
      ),
    ],
    packages: [
      {
        name,
        ecosystem,
        manifest_path: path,
        vulnerable_version_range: range,
        fixed_versions: fixed,
      },
    ],
    locations: path ? [{ path }] : [],
    source_updated_at: Math.floor(updated),
    source_data: structuredClone(alert),
  };
}

export function normalizeGitHubDependabotAlerts(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const alerts = selectedAlerts(input);
  const result: ExternalFindings = {
    read: alerts.length,
    findings: [],
    excluded: [],
  };
  const ids = new Set<string>();
  let sourceRepository: string | undefined;
  for (const [index, alert] of alerts.entries()) {
    const { repositoryUrl, sourceId, url } = identity(alert);
    if (sourceRepository !== undefined && sourceRepository !== repositoryUrl)
      throw new CodexSecurityError(
        "Select Dependabot alerts from only one GitHub host and repository.",
      );
    sourceRepository = repositoryUrl;
    if (ids.has(sourceId))
      throw new CodexSecurityError(
        `Duplicate source finding id ${JSON.stringify(sourceId)}. Select each Dependabot alert once.`,
      );
    ids.add(sourceId);
    const inputEvidence = evidence(alert, url);
    try {
      if (target === "cloud" && Buffer.byteLength(sourceId) > 512)
        throw new Error(
          "Source finding ID exceeds the Cloud limit of 512 UTF-8 bytes.",
        );
      result.findings.push({
        source_finding_id: sourceId,
        evidence: validateExternalEvidence(inputEvidence, target),
      });
    } catch (error) {
      result.excluded.push({
        position: index + 1,
        source_finding_id: sourceId,
        reason: errorMessage(error),
      });
    }
  }
  return result;
}
