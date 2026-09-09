import crypto from "node:crypto";
import path from "node:path";
import express, { type Request, type Response } from "express";
import cors from "cors";
import { generateIntruderRequests, type IntruderMode } from "./intruder.js";
import { validateRequestUrl, validateResolvedHost } from "./security.js";
import { JsonStore } from "./store.js";
import type { RequestInput, ResponseData, ProjectWorkspace, Finding, Evidence, RequestCollection, ScenarioManifest, ScenarioStep, ScenarioRisk, AutomationRun, AutomationStepResult } from "./types.js";
import { executeRequest } from "./request.js";
import { LocalProxy } from "./proxy.js";
import { validatePayloadTransforms } from "./transformations.js";
import { createReconRun, runActiveRecon } from "./recon.js";

const MAX_BODY = 1024 * 1024;
const methods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const blockedHeaders = new Set(["host", "connection", "content-length", "transfer-encoding"]);
const scenarioRisks = new Set<ScenarioRisk>(["low", "medium", "high"]);

function input(value: unknown): RequestInput {
  if (!value || typeof value !== "object") throw new Error("Request object is required");
  const data = value as Partial<RequestInput>;
  if (!methods.has(data.method || "")) throw new Error("Unsupported HTTP method");
  if (typeof data.url !== "string" || data.url.length > 4096) throw new Error("A valid URL is required");
  const headers: Record<string, string> = {};
  if (data.headers && typeof data.headers === "object") for (const [key, val] of Object.entries(data.headers)) {
    if (Object.keys(headers).length >= 50 || key.length > 256 || typeof val !== "string" || val.length > 8192) throw new Error("Invalid request headers");
    if (!blockedHeaders.has(key.toLowerCase())) headers[key] = val;
  }
  if (data.body !== undefined && (typeof data.body !== "string" || data.body.length > MAX_BODY)) throw new Error("Request body exceeds 1 MB");
  return { method: data.method as RequestInput["method"], url: data.url, headers, body: data.body };
}

export function createApp(store = new JsonStore()) {
  const app = express();
  const proxy = new LocalProxy(store);
  app.locals.proxy = proxy;
  app.use(cors({ origin: [/^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/] }));
  app.use(express.json({ limit: "2mb" }));
  app.use(express.static(path.resolve("dist/client")));
  app.get("/api/health", (_req, res) => res.json({ ok: true, service: "local-http-lab" }));
  app.get("/api/settings", async (_req, res, next) => { try { res.json({ settings: await store.settings() }); } catch (e) { next(e); } });
  app.put("/api/settings", async (req, res, next) => { try { res.json({ settings: await store.saveSettings(req.body || {}) }); } catch (e) { next(e); } });
  app.get("/api/history", async (_req, res, next) => { try { res.json({ items: await store.history() }); } catch (e) { next(e); } });
  app.post("/api/history", async (req, res, next) => { try {
    const item = req.body;
    if (!item?.id || !item?.request) throw new Error("A history item with id and request is required");
    await store.addHistory(item);
    res.status(201).json({ item });
  } catch (e) { next(e); } });
  app.delete("/api/history", async (_req, res, next) => { try { await store.clearHistory(); res.json({ ok: true }); } catch (e) { next(e); } });
  app.delete("/api/history/:id", async (req, res, next) => { try {
    await store.deleteHistory(req.params.id);
    res.json({ ok: true });
  } catch (e) { next(e); } });
  app.get(["/api/proxy/ca.crt", "/api/ca.crt"], (_req, res) => {
    const pem = proxy.getCaCertPem();
    res.setHeader("content-type", "application/x-x509-ca-cert");
    res.setHeader("content-disposition", 'attachment; filename="local-http-lab-ca.crt"');
    res.send(pem);
  });
  app.get("/api/proxy/status", async (_req, res, next) => {
    try {
      const current = proxy.status();
      const settings = await store.settings();
      const interception = await proxy.interceptionStatus();
      res.json({ proxy: {
        ...current,
        ...interception,
        interception,
        port: current.running ? current.port : (settings.proxyPort ?? current.port),
        mode: settings.proxyMode,
        allowExternalHosts: settings.allowExternalHosts,
        maxConcurrent: settings.proxyMaxConcurrent
      } });
    } catch (e) { next(e); }
  });
  app.post("/api/proxy/start", async (req, res, next) => {
    try {
      const port = req.body?.port === undefined ? undefined : Number(req.body.port);
      const status = await proxy.start(port);
      if (port !== undefined) await store.saveSettings({ ...(await store.settings()), proxyPort: status.port });
      res.json({ proxy: status });
    } catch (e) { next(e); }
  });
  app.post("/api/proxy/stop", async (_req, res, next) => { try { res.json({ proxy: await proxy.stop() }); } catch (e) { next(e); } });
  app.get(["/api/proxy/interception/status", "/api/interception/status"], async (_req, res, next) => {
    try { res.json({ interception: await proxy.interceptionStatus() }); } catch (e) { next(e); }
  });
  app.post(["/api/proxy/interception/toggle", "/api/interception/toggle"], async (req, res, next) => {
    try {
      const current = await store.settings();
      const enabled = typeof req.body?.enabled === "boolean" ? req.body.enabled : !current.interceptEnabled;
      const settings = await store.saveSettings({ ...current, interceptEnabled: enabled });
      res.json({ interception: await proxy.interceptionStatus(), enabled: settings.interceptEnabled });
    } catch (e) { next(e); }
  });
  app.get(["/api/proxy/interception/pending", "/api/interception/pending"], async (_req, res, next) => {
    try { res.json({ items: await proxy.pendingInterceptions() }); } catch (e) { next(e); }
  });
  app.get(["/api/proxy/interception/pending/:id", "/api/interception/pending/:id"], async (req, res, next) => {
    try {
      const item = await proxy.getPending(String(req.params.id));
      if (!item) return res.status(404).json({ error: "Intercepted request not found" });
      return res.json({ item });
    } catch (e) { return next(e); }
  });
  app.put(["/api/proxy/interception/pending/:id", "/api/interception/pending/:id"], async (req, res, next) => {
    try { res.json({ item: await proxy.updatePending(String(req.params.id), req.body) }); } catch (e) { next(e); }
  });
  app.post(["/api/proxy/interception/pending/:id/continue", "/api/interception/pending/:id/continue"], async (req, res, next) => {
    try { res.json({ item: await proxy.continuePending(String(req.params.id), req.body && Object.keys(req.body).length ? req.body : undefined) }); } catch (e) { next(e); }
  });
  app.post(["/api/proxy/interception/pending/:id/drop", "/api/interception/pending/:id/drop"], async (req, res, next) => {
    try { res.json({ item: await proxy.dropPending(String(req.params.id)) }); } catch (e) { next(e); }
  });
  // DELETE is a convenient cancellation alias for clients that model a pending
  // interception as a resource.
  app.delete(["/api/proxy/interception/pending/:id", "/api/interception/pending/:id"], async (req, res, next) => {
    try { res.json({ item: await proxy.dropPending(String(req.params.id), "Request cancelled by user") }); } catch (e) { next(e); }
  });
  app.get("/api/traffic", async (req, res, next) => {
    try {
      const query = typeof req.query.q === "string" ? req.query.q.toLowerCase() : "";
      const items = (await store.traffic()).filter((item) => !query || `${item.request.method} ${item.request.url} ${item.error || ""}`.toLowerCase().includes(query));
      res.json({ items });
    } catch (e) { next(e); }
  });
  app.get("/api/traffic/:id", async (req, res, next) => {
    try {
      const item = (await store.traffic()).find((entry) => entry.id === req.params.id);
      if (!item) return res.status(404).json({ error: "Traffic item not found" });
      return res.json({ item });
    } catch (e) { return next(e); }
  });
  app.get("/api/audit", async (req, res, next) => {
    try {
      const query = typeof req.query.q === "string" ? req.query.q.toLowerCase() : "";
      const action = req.query.action === "allow" || req.query.action === "block" ? req.query.action : undefined;
      const mode = req.query.mode === "safe" || req.query.mode === "authorized" ? req.query.mode : undefined;
      const items = (await store.audit()).filter((item) => (!action || item.action === action) && (!mode || item.mode === mode) &&
        (!query || `${item.url} ${item.reason}`.toLowerCase().includes(query)));
      res.json({ items });
    } catch (e) { next(e); }
  });
  app.get("/api/workspaces", async (_req, res, next) => { try { res.json({ workspaces: await store.workspaces() }); } catch (e) { next(e); } });
  app.post("/api/workspaces", async (req, res, next) => { try {
    const now = new Date().toISOString();
    const workspace: ProjectWorkspace = { id: crypto.randomUUID(), name: String(req.body?.name || "").trim(), description: String(req.body?.description || "").trim(), target: String(req.body?.target || "").trim(), scope: String(req.body?.scope || "").trim(), createdAt: now, updatedAt: now };
    if (!workspace.name || workspace.name.length > 200) throw new Error("Workspace name is required");
    res.status(201).json({ workspace: await store.saveWorkspace(workspace) });
  } catch (e) { next(e); } });
  app.put("/api/workspaces/:id", async (req, res, next) => { try {
    const current = await store.workspace(req.params.id); if (!current) return res.status(404).json({ error: "Workspace not found" });
    const workspace = { ...current, ...req.body, id: current.id, updatedAt: new Date().toISOString() } as ProjectWorkspace;
    if (!workspace.name?.trim()) throw new Error("Workspace name is required");
    return res.json({ workspace: await store.saveWorkspace(workspace) });
  } catch (e) { return next(e); } });
  app.delete("/api/workspaces/:id", async (req, res, next) => { try { await store.deleteWorkspace(req.params.id); res.json({ ok: true }); } catch (e) { next(e); } });
  app.get("/api/workspaces/:id/findings", async (req, res, next) => { try { res.json({ findings: await store.findings(req.params.id) }); } catch (e) { next(e); } });
  app.post("/api/workspaces/:id/findings", async (req, res, next) => { try {
    if (!await store.workspace(req.params.id)) return res.status(404).json({ error: "Workspace not found" });
    const now = new Date().toISOString();
    const finding: Finding = { id: crypto.randomUUID(), workspaceId: req.params.id, title: String(req.body?.title || "").trim(), description: String(req.body?.description || "").trim(), severity: req.body?.severity || "info", status: req.body?.status || "open", endpoint: String(req.body?.endpoint || "").trim() || undefined, remediation: String(req.body?.remediation || "").trim() || undefined, evidenceIds: [], createdAt: now, updatedAt: now };
    if (!finding.title) throw new Error("Finding title is required");
    res.status(201).json({ finding: await store.saveFinding(finding) });
  } catch (e) { next(e); } });
  app.put("/api/findings/:id", async (req, res, next) => { try {
    const finding = (await store.findings()).find((item) => item.id === req.params.id); if (!finding) return res.status(404).json({ error: "Finding not found" });
    const updated = { ...finding, ...req.body, id: finding.id, workspaceId: finding.workspaceId, updatedAt: new Date().toISOString() } as Finding;
    return res.json({ finding: await store.saveFinding(updated) });
  } catch (e) { return next(e); } });
  app.delete("/api/findings/:id", async (req, res, next) => { try { await store.deleteFinding(req.params.id); res.json({ ok: true }); } catch (e) { next(e); } });
  app.get("/api/workspaces/:id/evidence", async (req, res, next) => { try { res.json({ evidence: await store.evidence(req.params.id) }); } catch (e) { next(e); } });
  app.post("/api/workspaces/:id/evidence", async (req, res, next) => { try {
    if (!await store.workspace(req.params.id)) return res.status(404).json({ error: "Workspace not found" });
    const evidence: Evidence = { id: crypto.randomUUID(), workspaceId: req.params.id, findingId: req.body?.findingId || undefined, title: String(req.body?.title || "").trim(), kind: req.body?.kind || "note", content: String(req.body?.content || ""), createdAt: new Date().toISOString() };
    if (!evidence.title || !evidence.content) throw new Error("Evidence title and content are required");
    res.status(201).json({ evidence: await store.saveEvidence(evidence) });
  } catch (e) { next(e); } });
  app.delete("/api/evidence/:id", async (req, res, next) => { try { await store.deleteEvidence(req.params.id); res.json({ ok: true }); } catch (e) { next(e); } });
  app.get("/api/workspaces/:id/report", async (req, res, next) => { try {
    const workspace = await store.workspace(req.params.id); if (!workspace) return res.status(404).json({ error: "Workspace not found" });
    const findings = await store.findings(req.params.id); const evidence = await store.evidence(req.params.id);
    const markdown = [`# ${workspace.name}`, "", workspace.description || "", workspace.target ? `**Target:** ${workspace.target}` : "", workspace.scope ? `**Scope:** ${workspace.scope}` : "", "", "## Findings", ...findings.map((item) => `### [${item.severity.toUpperCase()}] ${item.title}\n\n- Status: ${item.status}\n- Endpoint: ${item.endpoint || "—"}\n\n${item.description}\n\n**Remediation:** ${item.remediation || "—"}`), "", "## Evidence", ...evidence.map((item) => `### ${item.title}\n\n*${item.kind}* — ${item.content}`)].join("\n");
    const format = req.query.format === "json" || req.query.format === "sarif" ? req.query.format : "markdown";
    if (format === "json") return res.json({ format, report: { workspace, findings, evidence } });
    if (format === "sarif") {
      const sarif = { version: "2.1.0", $schema: "https://json.schemastore.org/sarif-2.1.0.json", runs: [{ tool: { driver: { name: "Local HTTP Lab", informationUri: "https://localhost" } }, results: findings.map((item) => ({ ruleId: item.id, level: item.severity === "critical" || item.severity === "high" ? "error" : item.severity === "medium" ? "warning" : "note", message: { text: item.description || item.title }, locations: item.endpoint ? [{ physicalLocation: { artifactLocation: { uri: item.endpoint } } }] : undefined })) }] };
      return res.json({ format, report: sarif });
    }
    return res.json({ format, workspace, findings, evidence, markdown });
  } catch (e) { next(e); } });
  app.get("/api/workspaces/:id/collections", async (req, res, next) => { try { res.json({ collections: await store.collections(req.params.id) }); } catch (e) { next(e); } });
  app.post("/api/workspaces/:id/collections", async (req, res, next) => { try {
    if (!await store.workspace(req.params.id)) return res.status(404).json({ error: "Workspace not found" });
    const requests = Array.isArray(req.body?.requests) ? req.body.requests.map(input) : [];
    const name = String(req.body?.name || "").trim(); if (!name) throw new Error("Collection name is required");
    const now = new Date().toISOString();
    const collection: RequestCollection = { id: crypto.randomUUID(), workspaceId: req.params.id, name, description: String(req.body?.description || "").trim() || undefined, requests, createdAt: now, updatedAt: now };
    return res.status(201).json({ collection: await store.saveCollection(collection) });
  } catch (e) { return next(e); } });
  app.delete("/api/collections/:id", async (req, res, next) => { try { await store.deleteCollection(req.params.id); res.json({ ok: true }); } catch (e) { next(e); } });
  app.post("/api/workspaces/:id/import", async (req, res, next) => { try {
    if (!await store.workspace(req.params.id)) return res.status(404).json({ error: "Workspace not found" });
    const format = req.body?.format; const document = req.body?.document;
    if (format !== "openapi" && format !== "har") throw new Error("Import format must be openapi or har");
    if (!document || typeof document !== "object") throw new Error("Import document is required");
    const requests: RequestInput[] = [];
    if (format === "har") {
      const entries = Array.isArray(document.log?.entries) ? document.log.entries : [];
      for (const entry of entries.slice(0, 1000)) {
        const request = entry?.request; if (!request || typeof request.url !== "string") continue;
        requests.push(input({ method: request.method || "GET", url: request.url, headers: Object.fromEntries((Array.isArray(request.headers) ? request.headers : []).filter((h: any) => typeof h?.name === "string" && typeof h?.value === "string").map((h: any) => [h.name, h.value])), body: request.postData?.text }));
      }
    } else {
      const base = String(document.servers?.[0]?.url || (document.host ? `${document.schemes?.[0] || "http"}://${document.host}${document.basePath || ""}` : "http://localhost"));
      for (const [route, pathItem] of Object.entries(document.paths || {})) for (const [method, operation] of Object.entries(pathItem as object)) {
        if (!methods.has(method.toUpperCase())) continue;
        const op = operation as any; requests.push(input({ method: method.toUpperCase(), url: `${base}${route}`, headers: {}, body: undefined }));
        if (requests.length >= 1000) break;
      }
    }
    const now = new Date().toISOString();
    const collection: RequestCollection = { id: crypto.randomUUID(), workspaceId: req.params.id, name: String(req.body?.name || `${format.toUpperCase()} import`), description: `Imported ${format.toUpperCase()} requests`, requests, createdAt: now, updatedAt: now };
    return res.status(201).json({ collection: await store.saveCollection(collection), imported: requests.length });
  } catch (e) { return next(e); } });
  app.post("/api/requests/diff", async (req, res, next) => { try {
    const left = input(req.body?.left); const right = input(req.body?.right);
    const headerKeys = new Set([...Object.keys(left.headers), ...Object.keys(right.headers)]);
    const headers = [...headerKeys].filter((key) => left.headers[key] !== right.headers[key]).map((key) => ({ key, left: left.headers[key], right: right.headers[key] }));
    return res.json({ equal: left.method === right.method && left.url === right.url && left.body === right.body && headers.length === 0, changes: { method: left.method === right.method ? undefined : [left.method, right.method], url: left.url === right.url ? undefined : [left.url, right.url], body: left.body === right.body ? undefined : [left.body, right.body], headers } });
  } catch (e) { return next(e); } });
  app.get("/api/workspaces/:id/scenarios", async (req, res, next) => { try { res.json({ scenarios: await store.scenarios(req.params.id) }); } catch (e) { next(e); } });
  app.post("/api/workspaces/:id/scenarios", async (req, res, next) => { try {
    if (!await store.workspace(req.params.id)) return res.status(404).json({ error: "Workspace not found" });
    const rawSteps = Array.isArray(req.body?.steps) ? req.body.steps : [];
    if (rawSteps.length > 100) throw new Error("A scenario may contain at most 100 steps");
    const steps: ScenarioStep[] = rawSteps.map((step: any, index: number) => {
      if (!["request", "recon", "metadata"].includes(step?.action)) throw new Error(`Unsupported scenario step type: ${String(step?.action || "unknown")}`);
      return { id: crypto.randomUUID(), action: step.action, label: String(step?.label || `Step ${index + 1}`), target: typeof step?.target === "string" ? step.target : undefined, request: step?.request ? input(step.request) : undefined, risk: scenarioRisks.has(step?.risk) ? step.risk : "low" };
    });
    const risk: ScenarioRisk = steps.some((step) => step.risk === "high") ? "high" : steps.some((step) => step.risk === "medium") ? "medium" : "low";
    const now = new Date().toISOString(); const scenario: ScenarioManifest = { id: crypto.randomUUID(), workspaceId: req.params.id, name: String(req.body?.name || "").trim(), description: String(req.body?.description || "").trim() || undefined, steps, risk, status: risk === "high" ? "pending_approval" : "draft", createdAt: now, updatedAt: now };
    if (!scenario.name) throw new Error("Scenario name is required");
    return res.status(201).json({ scenario: await store.saveScenario(scenario) });
  } catch (e) { return next(e); } });
  app.post("/api/scenarios/:id/approve", async (req, res, next) => { try {
    const scenario = await store.scenario(req.params.id); if (!scenario) return res.status(404).json({ error: "Scenario not found" });
    if (req.body?.approved !== true) { scenario.status = "rejected"; } else { scenario.status = "approved"; scenario.approval = { approved: true, note: typeof req.body?.note === "string" ? req.body.note : undefined, approvedAt: new Date().toISOString(), approvedBy: "local-user" }; }
    scenario.updatedAt = new Date().toISOString(); return res.json({ scenario: await store.saveScenario(scenario) });
  } catch (e) { return next(e); } });
  app.post("/api/scenarios/:id/dry-run", async (req, res, next) => { try {
    const scenario = await store.scenario(req.params.id); if (!scenario) return res.status(404).json({ error: "Scenario not found" });
    return res.json({ dryRun: true, executable: scenario.risk !== "high" || scenario.status === "approved", approvalRequired: scenario.risk === "high" && scenario.status !== "approved", scenarioId: scenario.id, steps: scenario.steps.map((step) => ({ id: step.id, action: step.action, label: step.label, target: step.target, risk: step.risk, wouldExecute: false })) });
  } catch (e) { return next(e); } });
  const activeAutomation = new Map<string, { cancel: boolean }>();
  const waitForResume = async (id: string) => {
    while (true) {
      const run = await store.automationRun(id);
      if (!run || run.status === "cancelled") return false;
      if (run.status !== "paused") return true;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  };
  const runAutomation = async (run: AutomationRun, scenario: ScenarioManifest, settings: Awaited<ReturnType<JsonStore["settings"]>>) => {
    const signal = activeAutomation.get(run.id);
    try {
      if (!signal || signal.cancel || (await store.automationRun(run.id))?.status === "cancelled") { run.status = "cancelled"; return; }
      run.status = "running"; run.updatedAt = new Date().toISOString(); await store.saveAutomationRun(run);
      for (let index = 0; index < scenario.steps.length && index < run.limits.maxSteps; index += 1) {
        if (!signal || signal.cancel) { run.status = "cancelled"; break; }
        if (!await waitForResume(run.id)) { run.status = "cancelled"; break; }
        const step = scenario.steps[index];
        run.currentStep = index;
        const startedAt = new Date().toISOString();
        const result: AutomationStepResult = { stepId: step.id, action: step.action, status: "completed", startedAt, completedAt: startedAt };
        try {
          if (run.dryRun || step.action === "metadata") {
            result.value = run.dryRun ? `would execute: ${step.label}` : `metadata: ${step.label}`;
          } else if (step.action === "request") {
            if (!step.request) throw new Error("Request step requires a request");
            if (run.requestsExecuted >= run.limits.maxRequests) throw new Error("Automation request limit exceeded");
            const response = await Promise.race([
              executeRequest(step.request, store),
              new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Automation step timed out")), run.limits.timeoutMs))
            ]);
            run.requestsExecuted += 1; result.response = response;
            await store.addHistory({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), request: step.request, response });
          } else if (step.action === "recon") {
            const target = step.target ? [step.target] : [];
            const recon = await createReconRun(store, "passive", { urls: target, metadata: { label: step.label } });
            result.findings = recon.findings;
          }
        } catch (error) {
          result.status = "failed"; result.error = error instanceof Error ? error.message : "Automation step failed";
          run.results.push(result); run.status = "failed"; run.error = result.error; break;
        }
        result.completedAt = new Date().toISOString(); run.results.push(result);
        run.updatedAt = new Date().toISOString(); await store.saveAutomationRun(run);
      }
      if (run.status === "running") run.status = run.currentStep + 1 >= Math.min(scenario.steps.length, run.limits.maxSteps) ? "completed" : "completed";
    } catch (error) { run.status = "failed"; run.error = error instanceof Error ? error.message : "Automation failed"; }
    finally {
      run.updatedAt = new Date().toISOString(); await store.saveAutomationRun(run);
      activeAutomation.delete(run.id);
      await store.addAudit({ id: crypto.randomUUID(), createdAt: run.updatedAt, action: run.status === "failed" ? "block" : "allow", url: `automation://${run.id}`, reason: `automation run ${run.status}`, mode: settings.authorizedTestingMode ? "authorized" : "safe" });
      if (run.workspaceId) {
        const evidence = await store.saveEvidence({ id: crypto.randomUUID(), workspaceId: run.workspaceId, title: `Automation run ${run.id}`, kind: "note", content: JSON.stringify({ status: run.status, results: run.results, limits: run.limits }, null, 2), createdAt: run.updatedAt });
        void evidence;
      }
    }
  };
  const getAutomationRun = async (id: string, res: Response) => {
    const run = await store.automationRun(id);
    if (!run) { res.status(404).json({ error: "Automation run not found" }); return undefined; }
    return run;
  };
  app.get("/api/workspaces/:id/automation-runs", async (req, res, next) => { try { res.json({ runs: await store.automationRuns(req.params.id) }); } catch (e) { next(e); } });
  app.get("/api/scenarios/:id/runs", async (req, res, next) => { try { const scenario = await store.scenario(req.params.id); if (!scenario) return res.status(404).json({ error: "Scenario not found" }); res.json({ runs: (await store.automationRuns()).filter((run) => run.scenarioId === scenario.id) }); } catch (e) { next(e); } });
  app.get(["/api/automation/runs/:id", "/api/automation/runs/:id/progress"], async (req, res, next) => { try { const run = await getAutomationRun(String(req.params.id), res); if (run) res.json({ run, progress: { currentStep: run.currentStep, totalSteps: run.limits.maxSteps, requestsExecuted: run.requestsExecuted, results: run.results } }); } catch (e) { next(e); } });
  app.post(["/api/scenarios/:id/runs", "/api/automation/runs"], async (req, res, next) => { try {
    const scenario = req.params.id ? await store.scenario(String(req.params.id)) : await store.scenario(String(req.body?.scenarioId || ""));
    if (!scenario) return res.status(404).json({ error: "Scenario not found" });
    const settings = await store.settings();
    const dryRun = req.body?.dryRun === true;
    for (const step of scenario.steps) {
      if (step.action === "request" && !step.request) throw new Error(`Request step "${step.label}" requires a request`);
      if (step.action === "recon" && !step.target) throw new Error(`Recon step "${step.label}" requires a target`);
    }
    if (!dryRun && scenario.status !== "approved") throw new Error("Scenario requires explicit approval before execution");
    const limits = { maxSteps: Math.min(100, Math.max(1, Number(req.body?.maxSteps) || 100)), maxRequests: Math.min(100, Math.max(0, Number(req.body?.maxRequests) || 20)), timeoutMs: Math.min(60000, Math.max(100, Number(req.body?.timeoutMs) || 10000)) };
    const now = new Date().toISOString();
    const run: AutomationRun = { id: crypto.randomUUID(), scenarioId: scenario.id, workspaceId: scenario.workspaceId, createdAt: now, updatedAt: now, status: "queued", dryRun, limits, currentStep: 0, requestsExecuted: 0, results: [] };
    await store.saveAutomationRun(run);
    await store.addAudit({ id: crypto.randomUUID(), createdAt: now, action: "allow", url: `automation://${scenario.id}`, reason: dryRun ? "automation dry-run created" : "automation run queued", mode: settings.authorizedTestingMode ? "authorized" : "safe" });
    if (req.body?.start === true) { activeAutomation.set(run.id, { cancel: false }); void runAutomation(run, scenario, settings); }
    return res.status(201).json({ run });
  } catch (e) { return next(e); } });
  app.post("/api/automation/runs/:id/start", async (req, res, next) => { try {
    const run = await getAutomationRun(req.params.id, res); if (!run) return;
    const scenario = await store.scenario(run.scenarioId); if (!scenario) throw new Error("Scenario not found");
    const settings = await store.settings();
    if (!run.dryRun && scenario.status !== "approved") throw new Error("Scenario requires explicit approval before execution");
    if (["running", "paused", "completed"].includes(run.status)) throw new Error("Automation run has already started");
    run.status = "running"; await store.saveAutomationRun(run);
    activeAutomation.set(run.id, { cancel: false }); void runAutomation(run, scenario, settings); res.status(202).json({ run });
  } catch (e) { next(e); } });
  app.post("/api/automation/runs/:id/pause", async (req, res, next) => { try { const run = await getAutomationRun(req.params.id, res); if (!run) return; if (run.status !== "running") throw new Error("Only running automation runs can be paused"); run.status = "paused"; run.updatedAt = new Date().toISOString(); res.json({ run: await store.saveAutomationRun(run) }); } catch (e) { next(e); } });
  app.post("/api/automation/runs/:id/resume", async (req, res, next) => { try { const run = await getAutomationRun(req.params.id, res); if (!run) return; if (run.status !== "paused") throw new Error("Only paused automation runs can be resumed"); run.status = "running"; run.updatedAt = new Date().toISOString(); res.json({ run: await store.saveAutomationRun(run) }); } catch (e) { next(e); } });
  app.post("/api/automation/runs/:id/cancel", async (req, res, next) => { try { const run = await getAutomationRun(req.params.id, res); if (!run) return; if (["queued", "running", "paused"].includes(run.status)) { const signal = activeAutomation.get(run.id); if (signal) signal.cancel = true; run.status = "cancelled"; run.updatedAt = new Date().toISOString(); } res.json({ run: await store.saveAutomationRun(run) }); } catch (e) { next(e); } });
  app.get("/api/recon/runs", async (_req, res, next) => { try { res.json({ runs: await store.recons() }); } catch (e) { next(e); } });
  app.get(["/api/recon/runs/:id", "/api/recon/runs/:id/status"], async (req, res, next) => { try {
    const run = await store.recon(String(req.params.id)); if (!run) return res.status(404).json({ error: "Recon run not found" });
    return res.json({ run });
  } catch (e) { return next(e); } });
  app.post("/api/recon/passive", async (req, res, next) => { try {
    const run = await createReconRun(store, "passive", req.body);
    await store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "allow", url: "recon://passive", reason: "passive recon from explicitly supplied URLs and metadata", mode: "safe" });
    res.status(201).json({ run });
  } catch (e) { next(e); } });
  app.post("/api/recon/active", async (req, res, next) => { try {
    const settings = await store.settings();
    for (const raw of Array.isArray(req.body?.urls) ? req.body.urls : []) {
      if (typeof raw !== "string") throw new Error("Recon URLs must be strings");
      const url = validateRequestUrl(raw, settings);
      await validateResolvedHost(url, settings);
    }
    const run = await createReconRun(store, "active", req.body);
    await store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "allow", url: "recon://active", reason: "active recon created", mode: "authorized" });
    void runActiveRecon(store, run, settings);
    res.status(202).json({ run });
  } catch (e) { next(e); } });
  app.post("/api/recon/runs/:id/cancel", async (req, res, next) => { try {
    const run = await store.cancelRecon(req.params.id); if (!run) return res.status(404).json({ error: "Recon run not found" });
    await store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "allow", url: "recon://run", reason: "recon run cancelled", mode: run.authorized ? "authorized" : "safe" });
    return res.json({ run });
  } catch (e) { return next(e); } });
  app.post("/api/recon/runs", async (req, res, next) => {
    try {
      const mode = req.body?.mode;
      const settings = await store.settings();
      if (mode !== "passive" && mode !== "active") throw new Error("Recon mode must be passive or active");
      if (mode === "active") {
        for (const raw of Array.isArray(req.body?.urls) ? req.body.urls : []) {
          if (typeof raw !== "string") throw new Error("Recon URLs must be strings");
          await validateResolvedHost(validateRequestUrl(raw, settings), settings);
        }
      }
      const run = await createReconRun(store, mode, req.body);
      await store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "allow", url: `recon://${mode}`, reason: `${mode} recon run created`, mode: mode === "active" ? "authorized" : "safe" });
      if (mode === "active") void runActiveRecon(store, run, settings);
      res.status(mode === "active" ? 202 : 201).json({ run });
    } catch (e) { next(e); }
  });
  app.delete("/api/recon/runs/:id", async (req, res, next) => {
    try {
      const run = await store.cancelRecon(req.params.id); if (!run) return res.status(404).json({ error: "Recon run not found" });
      return res.json({ run });
    } catch (e) { return next(e); }
  });
  app.delete("/api/traffic", async (_req, res, next) => { try { await store.clearTraffic(); res.json({ ok: true }); } catch (e) { next(e); } });
  app.delete("/api/traffic/:id", async (req, res, next) => { try { await store.deleteTraffic(req.params.id); res.json({ ok: true }); } catch (e) { next(e); } });
  const repeater = async (req: Request, res: Response, next: (err?: unknown) => void) => {
    let request: RequestInput;
    try { request = input(req.body);     const response = await executeRequest(request, store); await store.addHistory({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), request, response }); res.json({ response }); } catch (e) {
      const message = e instanceof Error ? e.message : "Request failed";
      try { if (request!) await store.addHistory({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), request, error: message }); } catch { /* persistence must not mask request error */ }
      res.status(400).json({ error: message });
    }
  };
  app.post("/api/request", repeater);
  app.post("/api/repeater/request", repeater);
  const intruder = async (req: Request, res: Response, next: (err?: unknown) => void, run: boolean) => {
    try {
      const request = input(req.body?.request);
      const mode = req.body?.mode as IntruderMode;
      if (!["sniper", "batteringRam", "pitchfork", "clusterBomb"].includes(mode)) throw new Error("Unsupported intruder mode");
      const payloads = Array.isArray(req.body?.payloads) ? req.body.payloads.filter((p: unknown): p is string => typeof p === "string").slice(0, 1000) : [];
      const payloadDictionaries: Record<string, string[]> = {};
      const dictionaryInput = req.body?.payloadDictionaries ?? req.body?.payloadsByPosition;
      if (dictionaryInput !== undefined) {
        if (!dictionaryInput || typeof dictionaryInput !== "object" || Array.isArray(dictionaryInput)) throw new Error("Payload dictionaries must be an object");
        for (const [name, values] of Object.entries(dictionaryInput)) {
          if (Object.keys(payloadDictionaries).length >= 50 || name.length > 128 || !Array.isArray(values)) throw new Error("Invalid payload dictionaries");
          if (values.length > 1000 || values.some((value) => typeof value !== "string")) throw new Error("Each payload dictionary must contain at most 1000 text values");
          payloadDictionaries[name] = values as string[];
        }
      }
      const transformations = validatePayloadTransforms(req.body?.transformations);
      const settings = await store.settings();
      validateRequestUrl(request.url, settings);
      const generated = generateIntruderRequests(request, mode, payloads, settings.maxIntruderRequests, transformations, payloadDictionaries);
      // Apply the same request-size and header validation to expanded candidates.
      generated.forEach((candidate) => input(candidate));
      if (!run) return res.json({ requests: generated, count: generated.length });
      const concurrency = Math.min(10, Math.max(1, Number(req.body?.concurrency) || settings.defaultConcurrency || 3));
      const delay = Math.min(10000, Math.max(0, Number(req.body?.delay) || settings.defaultDelay || 0));
      const results: Array<{ request: RequestInput; response?: ResponseData; error?: string }> = [];
      let cursor = 0;
      const worker = async () => {
        while (cursor < generated.length) {
          const index = cursor++;
          if (index > 0 && delay) await new Promise((resolve) => setTimeout(resolve, delay));
          const candidate = generated[index];
          try { results[index] = { request: candidate, response: await executeRequest(candidate, store) }; }
          catch (e) { results[index] = { request: candidate, error: e instanceof Error ? e.message : "Request failed" }; }
        }
      }
      await Promise.all(Array.from({ length: Math.min(concurrency, generated.length) }, worker));
      for (const result of results) {
        if (result.response) await store.addHistory({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), request: result.request, response: result.response });
        else await store.addHistory({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), request: result.request, error: result.error });
      }
      return res.json({ results });
    } catch (e) { return next(e); }
  };
  app.post("/api/intruder/generate", (req, res, next) => void intruder(req, res, next, false));
  app.post("/api/intruder/run", (req, res, next) => void intruder(req, res, next, true));
  app.use((error: unknown, _req: Request, res: Response, _next: unknown) => res.status(400).json({ error: error instanceof Error ? error.message : "Bad request" }));
  return app;
}
