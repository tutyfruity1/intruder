import fs from "node:fs/promises";
import path from "node:path";
import { DEFAULT_SETTINGS, sanitizeSettings, type SecuritySettings } from "./security.js";
import type { AuditItem, HistoryItem, TrafficItem, ReconRun, ProjectWorkspace, Finding, Evidence, RequestCollection, ScenarioManifest, AutomationRun } from "./types.js";

export class JsonStore {
  readonly directory: string;
  constructor(directory = path.resolve("data")) { this.directory = directory; }
  private async read<T>(file: string, fallback: T): Promise<T> {
    try { return JSON.parse(await fs.readFile(path.join(this.directory, file), "utf8")) as T; } catch { return fallback; }
  }
  private async write(file: string, data: unknown) {
    await fs.mkdir(this.directory, { recursive: true });
    const target = path.join(this.directory, file);
    const temp = `${target}.next`;
    await fs.writeFile(temp, JSON.stringify(data, null, 2), "utf8");
    await fs.rename(temp, target);
  }
  async settings() {
    const envPort = Number(process.env.PROXY_PORT);
    const defaults = Number.isInteger(envPort) && envPort > 0 ? { ...DEFAULT_SETTINGS, proxyPort: envPort } : DEFAULT_SETTINGS;
    const saved = await this.read<Partial<SecuritySettings>>("settings.json", {});
    return sanitizeSettings({ ...defaults, ...saved, ...(Number.isInteger(envPort) && envPort > 0 ? { proxyPort: envPort } : {}) });
  }
  async saveSettings(input: Partial<SecuritySettings>) { const settings = sanitizeSettings(input); await this.write("settings.json", settings); return settings; }
  async history() { return this.read<HistoryItem[]>("history.json", []); }
  async addHistory(item: HistoryItem) { const current = await this.history(); await this.write("history.json", [item, ...current].slice(0, 200)); }
  async deleteHistory(id: string) { await this.write("history.json", (await this.history()).filter((item) => item.id !== id)); }
  async clearHistory() { await this.write("history.json", []); }
  private trafficWrite = Promise.resolve();
  async traffic() { return this.read<TrafficItem[]>("traffic.json", []); }
  async addTraffic(item: TrafficItem) {
    this.trafficWrite = this.trafficWrite.then(async () => {
      const current = await this.traffic();
      await this.write("traffic.json", [item, ...current].slice(0, 500));
    });
    return this.trafficWrite;
  }
  async deleteTraffic(id: string) {
    this.trafficWrite = this.trafficWrite.then(async () => {
      await this.write("traffic.json", (await this.traffic()).filter((item) => item.id !== id));
    });
    return this.trafficWrite;
  }
  async clearTraffic() {
    this.trafficWrite = this.trafficWrite.then(() => this.write("traffic.json", []));
    return this.trafficWrite;
  }
  async audit() { return this.read<AuditItem[]>("audit.json", []); }
  async addAudit(item: AuditItem) { await this.write("audit.json", [item, ...(await this.audit())].slice(0, 1000)); }
  async recons() { return this.read<ReconRun[]>("recon.json", []); }
  async recon(id: string) { return (await this.recons()).find((item) => item.id === id); }
  async addRecon(item: ReconRun) { await this.write("recon.json", [item, ...(await this.recons())].slice(0, 100)); }
  async updateRecon(item: ReconRun) {
    await this.write("recon.json", (await this.recons()).map((entry) => entry.id === item.id ? item : entry));
  }
  async cancelRecon(id: string) {
    const item = await this.recon(id);
    if (!item) return undefined;
    if (item.status === "queued" || item.status === "running") item.status = "cancelled";
    item.updatedAt = new Date().toISOString();
    await this.updateRecon(item);
    return item;
  }
  async workspaces() { return this.read<ProjectWorkspace[]>("workspaces.json", []); }
  async workspace(id: string) { return (await this.workspaces()).find((item) => item.id === id); }
  async saveWorkspace(item: ProjectWorkspace) {
    const items = (await this.workspaces()).filter((entry) => entry.id !== item.id);
    await this.write("workspaces.json", [item, ...items].slice(0, 100));
    return item;
  }
  async deleteWorkspace(id: string) {
    await this.write("workspaces.json", (await this.workspaces()).filter((item) => item.id !== id));
    await this.write("findings.json", (await this.findings()).filter((item) => item.workspaceId !== id));
    await this.write("evidence.json", (await this.evidence()).filter((item) => item.workspaceId !== id));
  }
  async findings(workspaceId?: string) {
    const items = await this.read<Finding[]>("findings.json", []);
    return workspaceId ? items.filter((item) => item.workspaceId === workspaceId) : items;
  }
  async saveFinding(item: Finding) {
    const items = (await this.findings()).filter((entry) => entry.id !== item.id);
    await this.write("findings.json", [item, ...items].slice(0, 1000));
    return item;
  }
  async deleteFinding(id: string) { await this.write("findings.json", (await this.findings()).filter((item) => item.id !== id)); }
  async evidence(workspaceId?: string) {
    const items = await this.read<Evidence[]>("evidence.json", []);
    return workspaceId ? items.filter((item) => item.workspaceId === workspaceId) : items;
  }
  async saveEvidence(item: Evidence) {
    const items = (await this.evidence()).filter((entry) => entry.id !== item.id);
    await this.write("evidence.json", [item, ...items].slice(0, 2000));
    return item;
  }
  async deleteEvidence(id: string) { await this.write("evidence.json", (await this.evidence()).filter((item) => item.id !== id)); }
  async collections(workspaceId?: string) {
    const items = await this.read<RequestCollection[]>("collections.json", []);
    return workspaceId ? items.filter((item) => item.workspaceId === workspaceId) : items;
  }
  async saveCollection(item: RequestCollection) {
    const items = (await this.collections()).filter((entry) => entry.id !== item.id);
    await this.write("collections.json", [item, ...items].slice(0, 500));
    return item;
  }
  async deleteCollection(id: string) { await this.write("collections.json", (await this.collections()).filter((item) => item.id !== id)); }
  async scenarios(workspaceId?: string) {
    const items = await this.read<ScenarioManifest[]>("scenarios.json", []);
    return workspaceId ? items.filter((item) => item.workspaceId === workspaceId) : items;
  }
  async scenario(id: string) { return (await this.scenarios()).find((item) => item.id === id); }
  async saveScenario(item: ScenarioManifest) {
    const items = (await this.scenarios()).filter((entry) => entry.id !== item.id);
    await this.write("scenarios.json", [item, ...items].slice(0, 500));
    return item;
  }
  async automationRuns(workspaceId?: string) {
    const items = await this.read<AutomationRun[]>("automation-runs.json", []);
    return workspaceId ? items.filter((item) => item.workspaceId === workspaceId) : items;
  }
  async automationRun(id: string) { return (await this.automationRuns()).find((item) => item.id === id); }
  async saveAutomationRun(item: AutomationRun) {
    const items = (await this.automationRuns()).filter((entry) => entry.id !== item.id);
    await this.write("automation-runs.json", [item, ...items].slice(0, 500));
    return item;
  }
}
