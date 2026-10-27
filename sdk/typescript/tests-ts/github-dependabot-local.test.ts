import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { githubDependabotAlert } from "./support/github-dependabot-fixtures.js";

test("two Dependabot alerts for one advisory retain separate repository histories", async () => {
  const fixture = await localFindingsFixture({
    remote: "git@github.com:example/project.git",
  });
  try {
    const path = join(fixture.root, "dependabot.json.gz");
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "github.com/example/project/dependabot",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = async (findings: unknown[]) => {
      await writeFile(path, gzipSync(JSON.stringify(findings)));
      return prepareLocalExternalImport(path, options, dependencies);
    };
    const first = githubDependabotAlert(1);
    const second = githubDependabotAlert(2);
    const saved = await prepare([first, second]);
    expect((await saved.import()).counts.created).toBe(2);
    expect(
      (await (await prepare([second, first])).import()).counts.unchanged,
    ).toBe(2);
    expect(
      (
        await (
          await prepare([
            { ...first, state: "fixed", fixed_at: "2026-01-03T00:00:00Z" },
          ])
        ).import()
      ).counts.updated,
    ).toBe(1);
    expect((await (await prepare([])).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 0,
    });
    const records = await listLocalExternalFindings(options, dependencies);
    expect(records.map((record) => record.version).sort()).toEqual([1, 2]);
    expect(
      records.every(({ assessment }) => assessment.state === "not_assessed"),
    ).toBe(true);
    await expect(
      prepare([githubDependabotAlert(3, "example/other")]),
    ).rejects.toThrow(/remote|repository/i);
    const altered = structuredClone(saved.preview);
    altered.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://github.com/example/other" },
    };
    await expect(
      prepareNormalizedLocalImport(altered, options, dependencies),
    ).rejects.toThrow(/original Dependabot alert/i);
    const relabeled = structuredClone(saved.preview);
    relabeled.findings.splice(1);
    relabeled.findings[0]!.source_finding_id =
      saved.preview.findings[1]!.source_finding_id;
    await expect(
      prepareNormalizedLocalImport(relabeled, options, dependencies),
    ).rejects.toThrow(/occurrence|source finding|identity|alert ID/i);
  } finally {
    await fixture.dispose();
  }
});
