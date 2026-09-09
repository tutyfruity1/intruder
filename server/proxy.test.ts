import fs from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { LocalProxy } from "./proxy.js";
import { JsonStore } from "./store.js";

const stores: string[] = [];
const servers: Array<http.Server | LocalProxy> = [];

async function freePort() {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function connectRequest(port: number) {
  return new Promise<string>((resolve, reject) => {
    const socket = net.createConnection(port, "127.0.0.1");
    let data = "";
    socket.on("connect", () => socket.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"));
    socket.on("data", (chunk) => { data += chunk.toString("utf8"); });
    socket.on("end", () => resolve(data));
    socket.on("error", reject);
  });
}

function request(port: number, method: string, path: string) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      res.on("end", () => resolve({ status: res.statusCode || 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    if (server instanceof LocalProxy) await server.stop();
    else await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  for (const directory of stores.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

describe("local HTTP proxy", () => {
  it("forwards absolute-form HTTP requests and persists traffic", async () => {
    const target = http.createServer((req, res) => {
      res.setHeader("content-type", "text/plain");
      res.end(`received ${req.method} ${req.url}`);
    });
    servers.push(target);
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", () => resolve()));
    const targetPort = (target.address() as net.AddressInfo).port;
    const directory = `data-test-proxy-${process.pid}-${Date.now()}`;
    stores.push(directory);
    const store = new JsonStore(directory);
    const proxy = new LocalProxy(store);
    servers.push(proxy);
    const proxyPort = await freePort();
    await proxy.start(proxyPort);

    const result = await request(proxyPort, "GET", `http://127.0.0.1:${targetPort}/hello`);
    expect(result.status).toBe(200);
    expect(result.body).toBe("received GET /hello");
    const traffic = await store.traffic();
    expect(traffic).toHaveLength(1);
    expect(traffic[0].source).toBe("proxy");
    expect(traffic[0].request.url).toContain("/hello");
    expect(traffic[0].response?.status).toBe(200);
  });

  it("blocks public targets and CONNECT without forwarding", async () => {
    const directory = `data-test-proxy-${process.pid}-${Date.now()}`;
    stores.push(directory);
    const proxy = new LocalProxy(new JsonStore(directory));
    servers.push(proxy);
    const proxyPort = await freePort();
    await proxy.start(proxyPort);

    const blocked = await request(proxyPort, "GET", "http://8.8.8.8/");
    expect(blocked.status).toBe(403);
    expect(blocked.body).toMatch(/private|allowed|unsafe/i);
    const connect = await connectRequest(proxyPort);
    expect(connect).toMatch(/501/);
    expect(connect).toMatch(/CONNECT|MITM/i);
  });
});
