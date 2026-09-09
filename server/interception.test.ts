import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "./app.js";
import { LocalProxy } from "./proxy.js";
import { JsonStore } from "./store.js";

const cleanup: Array<() => Promise<void>> = [];
const directories: string[] = [];

async function listen(server: http.Server) {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as net.AddressInfo).port;
}

async function freePort() {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function proxyRequest(port: number, method: string, url: string, body?: string) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: url, headers: body ? { "content-length": Buffer.byteLength(body) } : undefined }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      res.on("end", () => resolve({ status: res.statusCode || 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

async function waitForPending(proxy: LocalProxy) {
  for (let i = 0; i < 20; i += 1) {
    const pending = await proxy.pendingInterceptions();
    if (pending.length) return pending[0];
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("request was not intercepted");
}

afterEach(async () => {
  for (const close of cleanup.splice(0)) await close();
  for (const directory of directories.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

describe("HTTP interception", () => {
  it("pauses, edits, continues, and records the original target", async () => {
    const target = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      req.on("end", () => res.end(`${req.method} ${req.url} ${req.headers["x-edited"] || ""} ${Buffer.concat(chunks).toString()}`));
    });
    const targetPort = await listen(target);
    cleanup.push(() => new Promise((resolve) => target.close(() => resolve())));
    const directory = `data-test-intercept-${process.pid}-${Date.now()}`;
    directories.push(directory);
    const store = new JsonStore(directory);
    await store.saveSettings({ interceptEnabled: true, interceptionTimeout: 5000 });
    const proxy = new LocalProxy(store);
    const selected = await freePort();
    await proxy.start(selected);
    cleanup.push(async () => { await proxy.stop(); });
    const client = proxyRequest(selected, "POST", `http://127.0.0.1:${targetPort}/before`, "body");
    const pending = await waitForPending(proxy);
    expect(pending.request.url).toContain("/before");
    const updated = await proxy.updatePending(pending.id, { method: "PUT", url: `http://127.0.0.1:${targetPort}/after`, headers: { "x-edited": "yes" }, body: "changed" });
    expect(updated.request.method).toBe("PUT");
    await proxy.continuePending(pending.id);
    const result = await client;
    expect(result.status).toBe(200);
    expect(result.body).toContain("PUT /after yes changed");
    const traffic = await store.traffic();
    expect(traffic[0].interceptionStatus).toBe("continued");
    expect(traffic[0].originalRequest?.url).toContain("/before");
    expect(traffic[0].request.url).toContain("/after");
  });

  it("supports API pending/update/drop endpoints without forwarding", async () => {
    const target = http.createServer((_req, res) => res.end("forwarded"));
    const targetPort = await listen(target);
    cleanup.push(() => new Promise((resolve) => target.close(() => resolve())));
    const directory = `data-test-intercept-api-${process.pid}-${Date.now()}`;
    directories.push(directory);
    const store = new JsonStore(directory);
    await store.saveSettings({ interceptEnabled: true, interceptionTimeout: 5000 });
    const app = createApp(store);
    const proxy = app.locals.proxy as LocalProxy;
    const proxyPort = await freePort();
    await proxy.start(proxyPort);
    cleanup.push(async () => { await proxy.stop(); });
    const client = proxyRequest(proxyPort, "GET", `http://127.0.0.1:${targetPort}/drop`);
    const pending = await waitForPending(proxy);
    const list = await request(app).get("/api/interception/pending");
    expect(list.status).toBe(200);
    expect(list.body.items).toHaveLength(1);
    const update = await request(app).put(`/api/interception/pending/${pending.id}`).send({ url: `http://127.0.0.1:${targetPort}/edited` });
    expect(update.status).toBe(200);
    const dropped = await request(app).post(`/api/interception/pending/${pending.id}/drop`);
    expect(dropped.status).toBe(200);
    expect((await client).status).toBe(502);
    expect((await store.traffic())[0].interceptionStatus).toBe("dropped");
  });

  it("enforces the queue limit, timeout, and edited-target security policy", async () => {
    const target = http.createServer((_req, res) => res.end("forwarded"));
    const targetPort = await listen(target);
    cleanup.push(() => new Promise((resolve) => target.close(() => resolve())));
    const directory = `data-test-intercept-limits-${process.pid}-${Date.now()}`;
    directories.push(directory);
    const store = new JsonStore(directory);
    await store.saveSettings({ interceptEnabled: true, maxPendingIntercepted: 1, interceptionTimeout: 1000 });
    const proxy = new LocalProxy(store);
    const proxyPort = await freePort();
    await proxy.start(proxyPort);
    cleanup.push(async () => { await proxy.stop(); });
    const first = proxyRequest(proxyPort, "GET", `http://127.0.0.1:${targetPort}/first`);
    await waitForPending(proxy);
    expect((await proxyRequest(proxyPort, "GET", `http://127.0.0.1:${targetPort}/second`)).status).toBe(503);
    const pending = (await proxy.pendingInterceptions())[0];
    const updated = await proxy.updatePending(pending.id, { url: "http://8.8.8.8/" });
    expect(updated.request.url).toBe("http://8.8.8.8/");
    expect((await first).status).toBe(504);
    expect((await store.traffic()).some((item) => item.interceptionStatus === "timed_out")).toBe(true);
  });
});
