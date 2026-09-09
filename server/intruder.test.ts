import { describe, expect, it } from "vitest";
import { generateIntruderRequests } from "./intruder.js";
import { isSafeIp, validateRequestUrl } from "./security.js";

const request = { method: "GET" as const, url: "http://localhost/search?q=§value§&p=§page§", headers: {}, body: undefined };

describe("intruder generation", () => {
  it("creates sniper requests per marker", () => {
    const values = generateIntruderRequests(request, "sniper", ["a", "b"]);
    expect(values).toHaveLength(4);
    expect(values[0].url).toContain("q=a");
    expect(values[1].url).toContain("q=b");
  });
  it("caps combinatorial plans", () => {
    expect(() => generateIntruderRequests(request, "clusterBomb", ["1", "2", "3"], 5)).toThrow(/maximum/);
  });
  it("uses separate named dictionaries for pitchfork and cluster bomb", () => {
    const values = generateIntruderRequests(request, "pitchfork", ["fallback"], 10, [], { value: ["a", "b"], page: ["1", "2"] });
    expect(values.map((item) => item.url)).toEqual(["http://localhost/search?q=a&p=1", "http://localhost/search?q=b&p=2"]);
    const combinations = generateIntruderRequests(request, "clusterBomb", [], 10, [], { value: ["a", "b"], page: ["1", "2"] });
    expect(combinations).toHaveLength(4);
  });
  it("transforms payloads before applying them", () => {
    const values = generateIntruderRequests({ ...request, url: "http://localhost/search?q=§value§" }, "sniper", ["hello world"], 10, [{ operation: "urlEncode" }]);
    expect(values[0].url).toContain("q=hello%20world");
  });
});

describe("security", () => {
  it("allows development ranges and rejects public IPs", () => {
    expect(isSafeIp("127.0.0.1")).toBe(true);
    expect(isSafeIp("192.168.1.20")).toBe(true);
    expect(isSafeIp("0.0.0.0")).toBe(false);
    expect(isSafeIp("::1")).toBe(true);
    expect(isSafeIp("8.8.8.8")).toBe(false);
    expect(() => validateRequestUrl("file:///etc/passwd", { allowedHosts: [], allowPrivateHosts: true, maxIntruderRequests: 10 })).toThrow();
  });
});
