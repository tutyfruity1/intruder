import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app.js";
import { JsonStore } from "./store.js";

describe("Phase 2 and 3 workspace APIs", () => {
  it("imports OpenAPI requests and exports JSON/SARIF reports", async () => {
    const app = createApp(new JsonStore("data-test-phase23-import"));
    const workspace = await request(app).post("/api/workspaces").send({ name: "Import project" });
    expect(workspace.status).toBe(201);
    const id = workspace.body.workspace.id;
    const imported = await request(app).post(`/api/workspaces/${id}/import`).send({
      format: "openapi",
      document: { openapi: "3.0.0", servers: [{ url: "http://localhost:3001" }], paths: { "/health": { get: { summary: "health" } } } }
    });
    expect(imported.status).toBe(201);
    expect(imported.body.imported).toBe(1);
    const finding = await request(app).post(`/api/workspaces/${id}/findings`).send({ title: "Example", description: "Observed metadata", severity: "medium", endpoint: "http://localhost:3001/health" });
    expect(finding.status).toBe(201);
    const json = await request(app).get(`/api/workspaces/${id}/report?format=json`);
    expect(json.body.report.findings).toHaveLength(1);
    const sarif = await request(app).get(`/api/workspaces/${id}/report?format=sarif`);
    expect(sarif.body.report.runs[0].results[0].level).toBe("warning");
  });

  it("provides request diffs and safe scenario approval gates", async () => {
    const app = createApp(new JsonStore("data-test-phase23-scenarios"));
    const workspace = await request(app).post("/api/workspaces").send({ name: "Safety project" });
    const id = workspace.body.workspace.id;
    const diff = await request(app).post("/api/requests/diff").send({
      left: { method: "GET", url: "http://localhost/a", headers: {} },
      right: { method: "POST", url: "http://localhost/b", headers: { "x-test": "1" } }
    });
    expect(diff.body.equal).toBe(false);
    const scenario = await request(app).post(`/api/workspaces/${id}/scenarios`).send({
      name: "High risk metadata review",
      steps: [{ action: "metadata", label: "Review only", risk: "high" }]
    });
    expect(scenario.status).toBe(201);
    const scenarioId = scenario.body.scenario.id;
    const dryRun = await request(app).post(`/api/scenarios/${scenarioId}/dry-run`);
    expect(dryRun.body.dryRun).toBe(true);
    expect(dryRun.body.approvalRequired).toBe(true);
    expect(dryRun.body.executable).toBe(false);
    const approved = await request(app).post(`/api/scenarios/${scenarioId}/approve`).send({ approved: true, note: "Reviewed locally" });
    expect(approved.body.scenario.status).toBe("approved");
    const afterApproval = await request(app).post(`/api/scenarios/${scenarioId}/dry-run`);
    expect(afterApproval.body.executable).toBe(true);
    expect(afterApproval.body.steps[0].wouldExecute).toBe(false);
  });
});
