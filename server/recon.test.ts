import { afterEach, describe, expect, it } from "vitest";
import request from "supertest";
import fs from "node:fs/promises";
import { createApp } from "./app.js";
import { JsonStore } from "./store.js";

const directories: string[] = [];
afterEach(async () => {
  for (const directory of directories.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

describe("recon lifecycle", () => {
  it("collects only supplied passive inputs and redacts secrets", async () => {
    const directory = `data-test-recon-${process.pid}-${Date.now()}`;
    directories.push(directory);
    const response = await request(createApp(new JsonStore(directory))).post("/api/recon/runs").send({
      mode: "passive", urls: ["https://example.test/path?token=secret"], metadata: { Authorization: "Bearer secret", title: "ok" }
    });
    expect(response.status).toBe(201);
    expect(response.body.run.status).toBe("completed");
    expect(JSON.stringify(response.body.run)).not.toContain("Bearer secret");
    expect(response.body.run.findings.some((item: { value: string }) => item.value.includes("[REDACTED]"))).toBe(true);
  });

  it("creates active recon runs", async () => {
    const directory = `data-test-recon-auth-${process.pid}-${Date.now()}`;
    directories.push(directory);
    const app = createApp(new JsonStore(directory));
    const run = await request(app).post("/api/recon/active").send({ urls: ["http://127.0.0.1/"], authorized: true });
    expect(run.status).toBe(202);
    expect(run.body.run.mode).toBe("active");
  });
});
