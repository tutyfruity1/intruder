import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app.js";
import { JsonStore } from "./store.js";

describe("API basics", () => {
  it("reports health and default settings", async () => {
    const app = createApp(new JsonStore("data-test-api"));
    expect((await request(app).get("/api/health")).body.ok).toBe(true);
    const settings = await request(app).get("/api/settings");
    expect(settings.status).toBe(200);
    expect(settings.body.settings.allowPrivateHosts).toBe(true);
  });
  it("rejects unsafe repeater targets", async () => {
    const response = await request(createApp(new JsonStore("data-test-security"))).post("/api/repeater/request").send({ method: "GET", url: "http://8.8.8.8/" });
    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/private|allowed|unsafe/i);
  });
});
