import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import { validateRequestUrl, resolveAllowedHost } from "./security.js";
import type { RequestInput, ResponseData } from "./types.js";
import { JsonStore } from "./store.js";

export const MAX_BODY = 1024 * 1024;

function requestOnce(url: URL, address: string, request: RequestInput, timeoutMs: number, maxResponseSize: number): Promise<ResponseData> {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === "https:" ? https : http;
    const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
    const options: https.RequestOptions = {
      protocol: url.protocol,
      hostname: address,
      port,
      path: `${url.pathname}${url.search}`,
      method: request.method,
      headers: request.headers,
      ...(timeoutMs > 0 ? { timeout: timeoutMs } : {}),
      rejectUnauthorized: false,
      lookup: (_hostname, _options, callback) => callback(null, address, address.includes(":") ? 6 : 4)
    };
    if (url.protocol === "https:") options.servername = url.hostname.replace(/^\[|\]$/g, "");
    const started = Date.now();
    const outgoing = transport.request(options, (incoming) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let truncated = false;
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        const headers: Record<string, string> = {};
        Object.entries(incoming.headers).forEach(([key, value]) => { headers[key] = Array.isArray(value) ? value.join(", ") : value || ""; });
        resolve({ status: incoming.statusCode || 0, statusText: incoming.statusMessage || "", headers, body: Buffer.concat(chunks).toString("utf8"), durationMs: Date.now() - started, ...(truncated ? { truncated: true } : {}) });
      };
      incoming.on("data", (chunk: Buffer) => {
        total += chunk.length;
        if (maxResponseSize <= 0) {
          chunks.push(chunk);
        } else {
          const remaining = Math.max(0, maxResponseSize - (total - chunk.length));
          if (remaining > 0) chunks.push(Buffer.from(chunk).subarray(0, remaining));
          if (total > maxResponseSize) truncated = true;
        }
      });
      incoming.on("end", finish);
      incoming.on("aborted", finish);
      incoming.on("error", (error) => { if (!settled) reject(error); });
    });
    outgoing.on("timeout", () => outgoing.destroy(new Error("Request timed out")));
    outgoing.on("error", reject);
    if (!["GET", "HEAD"].includes(request.method) && request.body !== undefined) outgoing.write(request.body);
    outgoing.end();
  });
}

export async function executeRequest(request: RequestInput, store: JsonStore): Promise<ResponseData> {
  const settings = await store.settings();
  let url = validateRequestUrl(request.url, settings);
  let redirects = 0;
  const started = Date.now();
  while (true) {
    let addresses: string[];
    try {
      addresses = await resolveAllowedHost(url, settings);
      await store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "allow", url: url.toString(), reason: redirects ? `redirect destination ${redirects}` : "target matched active policy", mode: settings.authorizedTestingMode ? "authorized" : "safe" });
    } catch (error) {
      const reason = error instanceof Error ? error.message : "target rejected by policy";
      await store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "block", url: url.toString(), reason, mode: settings.authorizedTestingMode ? "authorized" : "safe" });
      throw error;
    }
    const response = await requestOnce(url, addresses[0], request, settings.requestTimeout ?? 10000, settings.maxResponseSize ?? 5 * 1024 * 1024);
    const location = response.headers.location;
    if (!(response.status >= 300 && response.status < 400 && location)) {
      return { ...response, durationMs: Date.now() - started };
    }
    redirects += 1;
    if (redirects > (settings.maxRedirects ?? 5)) throw new Error("Redirect chain exceeds the configured maximum");
    url = validateRequestUrl(new URL(location, url).toString(), settings);
  }
}
