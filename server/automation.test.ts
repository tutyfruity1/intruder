import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app.js";
import { JsonStore } from "./store.js";

describe("safe automation runner", () => {
  it("enforces supported steps, approval, bounds, lifecycle, and evidence", async () => {
    const app = createApp(new JsonStore("data-test-automation"));
    const workspace = await request(app).post("/api/workspaces").send({ name: "Automation" });
    const id = workspace.body.workspace.id;
    const unsupported = await request(app).post(`/api/workspaces/${id}/scenarios`).send({ name: "unsafe", steps: [{ action: "shell", label: "never" }] });
    expect(unsupported.status).toBe(400);
    const scenario = await request(app).post(`/api/workspaces/${id}/scenarios`).send({ name: "safe", steps: [{ action: "metadata", label: "inspect", risk: "low" }] });
    const scenarioId = scenario.body.scenario.id;
    const blocked = await request(app).post(`/api/scenarios/${scenarioId}/runs`).send({});
    expect(blocked.status).toBe(400);
    await request(app).post(`/api/scenarios/${scenarioId}/approve`).send({ approved: true });
    const created = await request(app).post(`/api/scenarios/${scenarioId}/runs`).send({ maxSteps: 1, maxRequests: 1, timeoutMs: 1000 });
    expect(created.status).toBe(201);
    const started = await request(app).post(`/api/automation/runs/${created.body.run.id}/start`);
    expect(started.status).toBe(202);
    await new Promise((resolve) => setTimeout(resolve, 80));
    const progress = await request(app).get(`/api/automation/runs/${created.body.run.id}/progress`);
    expect(progress.body.run.status).toBe("completed");
    expect(progress.body.run.results).toHaveLength(1);
    const evidence = await request(app).get(`/api/workspaces/${id}/evidence`);
    expect(evidence.body.evidence.some((item: { title: string }) => item.title.includes("Automation run"))).toBe(true);
  });

  it("requires Authorized Testing Mode for request and recon execution", async () => {
    const app = createApp(new JsonStore("data-test-automation-auth"));
    const workspace = await request(app).post("/api/workspaces").send({ name: "Auth" });
    const scenario = await request(app).post(`/api/workspaces/${workspace.body.workspace.id}/scenarios`).send({
      name: "request", steps: [{ action: "request", label: "local", risk: "low", request: { method: "GET", url: "http://localhost/", headers: {} } }]
    });
    await request(app).post(`/api/scenarios/${scenario.body.scenario.id}/approve`).send({ approved: true });
    const run = await request(app).post(`/api/scenarios/${scenario.body.scenario.id}/runs`).send({});
    expect(run.status).toBe(400);
    expect(run.body.error).toContain("Authorized Testing Mode");
  });
});
