import crypto from "node:crypto";
import type { ReconFinding, ReconRun, ReconMode, RequestInput } from "./types.js";
import { executeRequest } from "./request.js";
import { validateRequestUrl, resolveAllowedHost, type SecuritySettings } from "./security.js";
import { JsonStore } from "./store.js";

const MAX_URLS = 20;
const MAX_METADATA = 100;
const secret = /(authorization|cookie|set-cookie|token|secret|password|api[-_]?key|session)/i;
export const redact = (value: string) => value
  .replace(/([?&](?:token|secret|password|api[-_]?key|session|auth(?:orization)?)[^=]*=)[^&#\s]*/gi, "$1[REDACTED]")
  .replace(/(["']?(?:authorization|cookie|set-cookie|token|secret|password|api[-_]?key|session)["']?\s*[:=]\s*)[^,;\s]+/gi, "$1[REDACTED]");

function suppliedUrls(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_URLS) throw new Error(`At most ${MAX_URLS} URLs are required`);
  const urls = [...new Set(value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean))];
  urls.forEach((raw) => {
    let parsed: URL;
    try { parsed = new URL(raw); } catch { throw new Error("Recon URLs must be valid"); }
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error("Recon URLs must be HTTP(S) URLs without credentials");
  });
  return urls;
}

function passiveFindings(urls: string[], metadata: unknown): ReconFinding[] {
  const findings: ReconFinding[] = urls.map((value) => ({ kind: "url", value: redact(value) }));
  if (!metadata || typeof metadata !== "object") return findings;
  for (const [key, raw] of Object.entries(metadata as Record<string, unknown>).slice(0, MAX_METADATA)) {
    if (secret.test(key)) continue;
    const value = typeof raw === "string" ? redact(raw).slice(0, 4096) : JSON.stringify(raw).slice(0, 4096);
    findings.push({ kind: "metadata", value: `${key}: ${value}` });
  }
  return findings.slice(0, MAX_URLS + MAX_METADATA);
}

export async function createReconRun(store: JsonStore, mode: ReconMode, body: any): Promise<ReconRun> {
  if (mode !== "passive" && mode !== "active") throw new Error("Unsupported recon mode");
  const urls = suppliedUrls(body?.urls);
  const run: ReconRun = {
    id: crypto.randomUUID(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    mode, status: mode === "passive" ? "completed" : "queued", urls: urls.map(redact), findings: [],
    ...(mode === "active" ? { profile: "http" as const, authorized: true } : {})
  };
  if (mode === "passive") run.findings = passiveFindings(urls, body?.metadata);
  await store.addRecon(run);
  return run;
}

export async function runActiveRecon(store: JsonStore, run: ReconRun, settings: SecuritySettings) {
  try {
    const initial = await store.recon(run.id);
    if (initial?.status === "cancelled") return;
    run.status = "running"; run.updatedAt = new Date().toISOString(); await store.updateRecon(run);
    try {
      for (const raw of run.urls) {
        const current = await store.recon(run.id);
        if (current?.status === "cancelled") return;
        const url = validateRequestUrl(raw, settings);
        await resolveAllowedHost(url, settings);
        const request: RequestInput = { method: "GET", url: raw, headers: {} };
        try {
          const response = await executeRequest(request, store);
          run.findings.push({ kind: "profile", value: `${url.origin} status=${response.status} content-type=${response.headers["content-type"] || "unknown"}` });
        } catch (error) {
          run.findings.push({ kind: "profile", value: `${url.origin} error=${redact(error instanceof Error ? error.message : "request failed")}` });
        }
        run.updatedAt = new Date().toISOString(); await store.updateRecon(run);
      }
      run.status = "completed";
    } catch (error) {
      run.status = "failed"; run.error = redact(error instanceof Error ? error.message : "recon failed");
    }
    run.updatedAt = new Date().toISOString(); await store.updateRecon(run);
  } catch {
    /* ignore background recon persistence errors on shutdown */
  }
}
