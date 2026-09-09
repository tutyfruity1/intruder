import http from "node:http";
import net from "node:net";
import fs from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { executeRequest } from "./request.js";
import { isSafeIp, resolveAllowedHost, validateRequestUrl } from "./security.js";
import { JsonStore } from "./store.js";

const servers: http.Server[] = [];
const stores: string[] = [];

async function listen(server: http.Server) {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as net.AddressInfo).port;
}

afterEach(async () => {
  for (const server of servers.splice(0)) await new Promise<void>((resolve) => server.close(() => resolve()));
  for (const directory of stores.splice(0)) await fs.rm(directory, { recursive: true, force: true });
});

describe("configurable SSRF policy", () => {
  it("supports explicit CIDR, IPv4 and IPv6 rules only in authorized mode", async () => {
    const settings = {
      allowedHosts: [],
      authorizedTestingMode: true,
      authorizedTargets: ["127.0.0.0/8", "[::1]"],
      authorizedAllowLoopback: true,
      authorizedAllowIpv4: true,
      authorizedAllowIpv6: true,
      allowPrivateHosts: false,
      maxIntruderRequests: 10
    };
    await expect(resolveAllowedHost(validateRequestUrl("http://127.0.0.1/", settings), settings)).resolves.toEqual(["127.0.0.1"]);
    await expect(resolveAllowedHost(validateRequestUrl("http://[::1]/", settings), settings)).resolves.toEqual(["::1"]);
    await expect(resolveAllowedHost(validateRequestUrl("http://127.0.0.2/", settings), settings)).resolves.toEqual(["127.0.0.2"]);
    await expect(resolveAllowedHost(validateRequestUrl("http://10.0.0.1/", settings), settings)).rejects.toThrow(/allowlist/i);
  });

  it("rejects ambiguous/public targets and keeps safe mode strict", () => {
    expect(isSafeIp("0.0.0.0")).toBe(false);
    expect(() => validateRequestUrl("http://user:pass@127.0.0.1/", { allowedHosts: [], allowPrivateHosts: true, maxIntruderRequests: 10 })).toThrow(/credentials/i);
    expect(() => validateRequestUrl("http://127.0.0.1:8080/", {
      allowedHosts: [],
      authorizedTestingMode: true,
      authorizedTargets: ["127.0.0.0/8"],
      authorizedAllowLoopback: true,
      authorizedAllowIpv4: true,
      authorizedAllowNonStandardPorts: false,
      allowPrivateHosts: false,
      maxIntruderRequests: 10
    })).toThrow(/non-standard/i);
  });

  it("revalidates every redirect destination and follows only when explicitly enabled", async () => {
    const server = http.createServer((req, res) => {
      if (req.url === "/start") {
        res.writeHead(302, { location: "/final" });
        res.end();
      } else res.end("final");
    });
    const port = await listen(server);
    servers.push(server);
    const directory = `data-test-policy-${process.pid}-${Date.now()}`;
    stores.push(directory);
    const store = new JsonStore(directory);
    const base = {
      allowedHosts: [],
      authorizedTestingMode: true,
      authorizedTargets: [`127.0.0.1:${port}`],
      authorizedAllowLoopback: true,
      authorizedAllowIpv4: true,
      authorizedAllowNonStandardPorts: true,
      authorizedAllowRedirects: true,
      maxRedirects: 3,
      allowPrivateHosts: false,
      maxIntruderRequests: 10,
      requestTimeout: 3000
    };
    await store.saveSettings(base);
    const response = await executeRequest({ method: "GET", url: `http://127.0.0.1:${port}/start`, headers: {} }, store);
    expect(response.status).toBe(200);
    expect(response.body).toBe("final");
    const audit = await store.audit();
    expect(audit.some((item) => item.url.endsWith("/final") && item.action === "allow")).toBe(true);
  });
});
