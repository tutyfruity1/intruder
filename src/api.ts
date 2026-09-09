import type { HistoryItem, PendingInterceptedRequest, ProxyStatus, RequestInput, ResponseData, TrafficItem } from "./types";
export interface ProjectWorkspace { id: string; name: string; description?: string; target?: string; scope?: string; createdAt: string; updatedAt: string; }
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "confirmed" | "resolved" | "false-positive";
export interface Finding { id: string; workspaceId: string; title: string; description: string; severity: FindingSeverity; status: FindingStatus; endpoint?: string; remediation?: string; evidenceIds: string[]; createdAt: string; updatedAt: string; }
export interface Evidence { id: string; workspaceId: string; findingId?: string; title: string; kind: "note" | "request" | "response" | "screenshot" | "file"; content: string; createdAt: string; }
export interface RequestCollection { id: string; workspaceId: string; name: string; description?: string; requests: RequestInput[]; createdAt: string; updatedAt: string; }
export interface ScenarioManifest { id: string; workspaceId: string; name: string; description?: string; risk: "low" | "medium" | "high"; status: "draft" | "pending_approval" | "approved" | "rejected"; steps: Array<{ id: string; action: "request" | "recon" | "metadata"; label: string; target?: string; risk: "low" | "medium" | "high" }>; createdAt: string; updatedAt: string; }
export type AutomationRunStatus = "queued" | "running" | "paused" | "completed" | "cancelled" | "failed";
export interface AutomationRun { id: string; scenarioId: string; workspaceId: string; status: AutomationRunStatus; dryRun: boolean; limits: { maxSteps: number; maxRequests: number; timeoutMs: number }; currentStep: number; requestsExecuted: number; results: Array<{ stepId: string; action: string; status: string; value?: string; error?: string; response?: ResponseData }>; createdAt: string; updatedAt: string; error?: string; }

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { headers: { "content-type": "application/json", ...(init?.headers ?? {}) }, ...init });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload as T;
}

export const api = {
  request: (request: RequestInput) => call<{ response: ResponseData }>("/api/request", { method: "POST", body: JSON.stringify(request) }),
  history: () => call<{ items: HistoryItem[] }>("/api/history"),
  clearHistory: () => call<{ ok: boolean }>("/api/history", { method: "DELETE" }),
  proxyStatus: () => call<{ proxy: ProxyStatus }>("/api/proxy/status"),
  startProxy: (port?: number) => call<{ proxy: ProxyStatus }>("/api/proxy/start", { method: "POST", body: JSON.stringify(port === undefined ? {} : { port }) }),
  stopProxy: () => call<{ proxy: ProxyStatus }>("/api/proxy/stop", { method: "POST" }),
  interceptionStatus: () => call<{ interception: { enabled: boolean; pending: number; maxPending: number; timeoutMs: number } }>("/api/proxy/interception/status"),
  toggleInterception: (enabled?: boolean) => call<{ enabled: boolean }>(`/api/proxy/interception/toggle`, { method: "POST", body: JSON.stringify(enabled === undefined ? {} : { enabled }) }),
  pendingInterceptions: () => call<{ items: PendingInterceptedRequest[] }>("/api/proxy/interception/pending"),
  updateInterception: (id: string, request: RequestInput) => call<{ item: PendingInterceptedRequest }>(`/api/proxy/interception/pending/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(request) }),
  continueInterception: (id: string, request?: RequestInput) => call<{ item: TrafficItem }>(`/api/proxy/interception/pending/${encodeURIComponent(id)}/continue`, { method: "POST", body: JSON.stringify(request || {}) }),
  dropInterception: (id: string) => call<{ item: TrafficItem }>(`/api/proxy/interception/pending/${encodeURIComponent(id)}/drop`, { method: "POST" }),
  traffic: (query = "") => call<{ items: TrafficItem[] }>(`/api/traffic${query ? `?q=${encodeURIComponent(query)}` : ""}`),
  deleteTraffic: (id: string) => call<{ ok: boolean }>(`/api/traffic/${encodeURIComponent(id)}`, { method: "DELETE" }),
  clearTraffic: () => call<{ ok: boolean }>("/api/traffic", { method: "DELETE" }),
  audit: () => call<{ items: Array<{ id: string; createdAt: string; action: "allow" | "block"; url: string; reason: string; mode: "safe" | "authorized" }> }>("/api/audit"),
  settings: () => call<{ settings: AppSettings }>("/api/settings"),
  saveSettings: (settings: Partial<AppSettings>) => call("/api/settings", { method: "PUT", body: JSON.stringify(settings) }),
  generateIntruder: (payload: object) => call<{ requests: RequestInput[]; count: number }>("/api/intruder/generate", { method: "POST", body: JSON.stringify(payload) }),
  runIntruder: (payload: object) => call<{ results: Array<{ request: RequestInput; response?: ResponseData; error?: string }> }>("/api/intruder/run", { method: "POST", body: JSON.stringify(payload) })
  ,
  reconRuns: () => call<{ runs: ReconRun[] }>("/api/recon/runs"),
  createPassiveRecon: (urls: string[], metadata?: object) => call<{ run: ReconRun }>("/api/recon/passive", { method: "POST", body: JSON.stringify({ urls, metadata }) }),
  createActiveRecon: (urls: string[], authorized: boolean) => call<{ run: ReconRun }>("/api/recon/active", { method: "POST", body: JSON.stringify({ urls, authorized }) }),
  cancelRecon: (id: string) => call<{ run: ReconRun }>(`/api/recon/runs/${encodeURIComponent(id)}/cancel`, { method: "POST" })
  ,
  workspaces: () => call<{ workspaces: ProjectWorkspace[] }>("/api/workspaces"),
  createWorkspace: (payload: Partial<ProjectWorkspace>) => call<{ workspace: ProjectWorkspace }>("/api/workspaces", { method: "POST", body: JSON.stringify(payload) }),
  deleteWorkspace: (id: string) => call<{ ok: boolean }>(`/api/workspaces/${encodeURIComponent(id)}`, { method: "DELETE" }),
  findings: (workspaceId: string) => call<{ findings: Finding[] }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/findings`),
  createFinding: (workspaceId: string, payload: Partial<Finding>) => call<{ finding: Finding }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/findings`, { method: "POST", body: JSON.stringify(payload) }),
  updateFinding: (id: string, payload: Partial<Finding>) => call<{ finding: Finding }>(`/api/findings/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(payload) }),
  deleteFinding: (id: string) => call<{ ok: boolean }>(`/api/findings/${encodeURIComponent(id)}`, { method: "DELETE" }),
  evidence: (workspaceId: string) => call<{ evidence: Evidence[] }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/evidence`),
  createEvidence: (workspaceId: string, payload: Partial<Evidence>) => call<{ evidence: Evidence }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/evidence`, { method: "POST", body: JSON.stringify(payload) }),
  deleteEvidence: (id: string) => call<{ ok: boolean }>(`/api/evidence/${encodeURIComponent(id)}`, { method: "DELETE" }),
  report: (workspaceId: string, format: "markdown" | "json" | "sarif" = "markdown") => call<any>(`/api/workspaces/${encodeURIComponent(workspaceId)}/report?format=${format}`),
  collections: (workspaceId: string) => call<{ collections: RequestCollection[] }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/collections`),
  createCollection: (workspaceId: string, payload: Partial<RequestCollection>) => call<{ collection: RequestCollection }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/collections`, { method: "POST", body: JSON.stringify(payload) }),
  importRequests: (workspaceId: string, format: "openapi" | "har", document: object, name?: string) => call<{ collection: RequestCollection; imported: number }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/import`, { method: "POST", body: JSON.stringify({ format, document, name }) }),
  diffRequests: (left: RequestInput, right: RequestInput) => call<{ equal: boolean; changes: Record<string, unknown> }>("/api/requests/diff", { method: "POST", body: JSON.stringify({ left, right }) }),
  scenarios: (workspaceId: string) => call<{ scenarios: ScenarioManifest[] }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/scenarios`),
  createScenario: (workspaceId: string, payload: object) => call<{ scenario: ScenarioManifest }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/scenarios`, { method: "POST", body: JSON.stringify(payload) }),
  approveScenario: (id: string, approved: boolean, note?: string) => call<{ scenario: ScenarioManifest }>(`/api/scenarios/${encodeURIComponent(id)}/approve`, { method: "POST", body: JSON.stringify({ approved, note }) }),
  dryRunScenario: (id: string) => call<{ dryRun: boolean; executable: boolean; approvalRequired: boolean; steps: unknown[] }>(`/api/scenarios/${encodeURIComponent(id)}/dry-run`, { method: "POST" }),
  automationRuns: (workspaceId: string) => call<{ runs: AutomationRun[] }>(`/api/workspaces/${encodeURIComponent(workspaceId)}/automation-runs`),
  createAutomationRun: (scenarioId: string, payload: { dryRun?: boolean; start?: boolean; maxSteps?: number; maxRequests?: number; timeoutMs?: number } = {}) => call<{ run: AutomationRun }>(`/api/scenarios/${encodeURIComponent(scenarioId)}/runs`, { method: "POST", body: JSON.stringify(payload) }),
  startAutomationRun: (id: string) => call<{ run: AutomationRun }>(`/api/automation/runs/${encodeURIComponent(id)}/start`, { method: "POST" }),
  pauseAutomationRun: (id: string) => call<{ run: AutomationRun }>(`/api/automation/runs/${encodeURIComponent(id)}/pause`, { method: "POST" }),
  resumeAutomationRun: (id: string) => call<{ run: AutomationRun }>(`/api/automation/runs/${encodeURIComponent(id)}/resume`, { method: "POST" }),
  cancelAutomationRun: (id: string) => call<{ run: AutomationRun }>(`/api/automation/runs/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  automationProgress: (id: string) => call<{ run: AutomationRun; progress: unknown }>(`/api/automation/runs/${encodeURIComponent(id)}/progress`)
};

export interface ReconRun {
  id: string;
  createdAt: string;
  updatedAt: string;
  mode: "passive" | "active";
  status: "queued" | "running" | "completed" | "cancelled" | "failed";
  urls: string[];
  findings: Array<{ kind: string; value: string }>;
  error?: string;
  authorized?: boolean;
}

export interface AppSettings {
  allowedHosts: string[];
  externalAllowedHosts: string[];
  authorizedTestingMode: boolean;
  authorizedTargets: string[];
  authorizedAllowLocalhost: boolean;
  authorizedAllowLoopback: boolean;
  authorizedAllowPrivateRanges: boolean;
  authorizedAllowLinkLocal: boolean;
  authorizedAllowInternalDns: boolean;
  authorizedAllowIpv4: boolean;
  authorizedAllowIpv6: boolean;
  authorizedAllowRedirects: boolean;
  authorizedAllowNonStandardPorts: boolean;
  maxRedirects: number;
  allowExternalHosts: boolean;
  proxyMode: "local" | "allowlist";
  allowPrivateHosts: boolean;
  maxIntruderRequests: number;
  requestTimeout: number;
  maxResponseSize: number;
  defaultConcurrency: number;
  defaultDelay: number;
  proxyPort: number;
  interceptEnabled: boolean;
  maxPendingIntercepted: number;
  interceptionTimeout: number;
  proxyMaxConcurrent: number;
  proxyRateLimitPerMinute: number;
  proxyConnectionTimeout: number;
  proxyAllowedConnectPorts: number[];
}
