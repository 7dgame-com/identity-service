import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("Work Package 4 Develop completion CI", () => {
  it("emits the revision-bound regression artifact only for a Develop push without SHA image tags", async () => {
    const workflow = await readFile(".github/workflows/ci-cd.yml", "utf8");
    const regressionStep = workflow.slice(
      workflow.indexOf("- name: Generate Develop completion regression evidence"),
      workflow.indexOf("- name: Build TypeScript")
    );
    expect(regressionStep).toContain("github.event_name == 'push' && github.ref == 'refs/heads/develop'");
    expect(regressionStep).toContain("--expected-revision=${{ github.sha }}");
    expect(regressionStep).toContain("name: identity-develop-regression-evidence");
    expect(regressionStep).toContain("retention-days: 30");
    expect(workflow).not.toMatch(/type=(?:raw,value=sha-|sha\b)/);
    expect(workflow).not.toContain("sha-${{ github.sha }}");
  });
});
