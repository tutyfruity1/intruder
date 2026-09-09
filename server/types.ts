export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT";
export interface RequestInput { method: HttpMethod; url: string; headers: Record<string, string>; body?: string; }
export type PayloadDictionaries = Record<string, string[]>;
export type { PayloadTransform, PayloadTransformOperation } from "./transformations.js";
export interface ResponseData { status: number; statusText: string; headers: Record<string, string>; body: string; durationMs: number; truncated?: boolean; }
export interface HistoryItem { id: string; createdAt: string; request: RequestInput; response?: ResponseData; error?: string; }
export interface TrafficItem extends HistoryItem {
  source: "proxy";
  originalRequest?: RequestInput;
  kind?: "http" | "https-tunnel";
  tunnel?: {
    target: string;
    port: number;
    connected: boolean;
    startedAt: string;
    endedAt?: string;
    bytesSent?: number;
    bytesReceived?: number;
  };
  interceptionStatus?: "continued" | "dropped" | "timed_out" | "queue_full" | "proxy_stopped";
}
export interface AuditItem {
  id: string;
  createdAt: string;
  action: "allow" | "block";
  url: string;
  reason: string;
  mode: "safe" | "authorized";
}

export type ReconMode = "passive" | "active";
export type ReconRunStatus = "queued" | "running" | "completed" | "cancelled" | "failed";
export interface ReconFinding {
  kind: "url" | "metadata" | "header" | "profile";
  value: string;
  source?: string;
}
export interface ReconRun {
  id: string;
  createdAt: string;
  updatedAt: string;
  mode: ReconMode;
  status: ReconRunStatus;
  profile?: "http";
  urls: string[];
  findings: ReconFinding[];
  error?: string;
  authorized?: boolean;
}

export interface ProjectWorkspace {
  id: string;
  name: string;
  description?: string;
  target?: string;
  scope?: string;
  createdAt: string;
  updatedAt: string;
}

export type FindingStatus = "open" | "confirmed" | "resolved" | "false-positive";
export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";
export interface Finding {
  id: string;
  workspaceId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  status: FindingStatus;
  endpoint?: string;
  remediation?: string;
  evidenceIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface Evidence {
  id: string;
  workspaceId: string;
  findingId?: string;
  title: string;
  kind: "note" | "request" | "response" | "screenshot" | "file";
  content: string;
  createdAt: string;
}

export interface RequestCollection {
  id: string;
  workspaceId: string;
  name: string;
  description?: string;
  requests: RequestInput[];
  createdAt: string;
  updatedAt: string;
}

export type ScenarioRisk = "low" | "medium" | "high";
export interface ScenarioStep {
  id: string;
  action: "request" | "recon" | "metadata";
  label: string;
  target?: string;
  request?: RequestInput;
  risk: ScenarioRisk;
}
export interface ScenarioApproval {
  approved: boolean;
  note?: string;
  approvedAt: string;
  approvedBy: string;
}
export interface ScenarioManifest {
  id: string;
  workspaceId: string;
  name: string;
  description?: string;
  steps: ScenarioStep[];
  risk: ScenarioRisk;
  status: "draft" | "pending_approval" | "approved" | "rejected";
  approval?: ScenarioApproval;
  createdAt: string;
  updatedAt: string;
}

export type AutomationRunStatus = "queued" | "running" | "paused" | "completed" | "cancelled" | "failed";
export interface AutomationRunLimits {
  maxSteps: number;
  maxRequests: number;
  timeoutMs: number;
}
export interface AutomationStepResult {
  stepId: string;
  action: ScenarioStep["action"];
  status: "completed" | "skipped" | "failed" | "cancelled";
  startedAt: string;
  completedAt: string;
  response?: ResponseData;
  findings?: ReconFinding[];
  value?: string;
  error?: string;
}
export interface AutomationRun {
  id: string;
  scenarioId: string;
  workspaceId: string;
  createdAt: string;
  updatedAt: string;
  status: AutomationRunStatus;
  dryRun: boolean;
  limits: AutomationRunLimits;
  currentStep: number;
  requestsExecuted: number;
  results: AutomationStepResult[];
  error?: string;
}
