import http from "node:http";
import crypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import type { IncomingMessage, ServerResponse } from "node:http";
import { executeRequest, MAX_BODY } from "./request.js";
import { resolveAllowedHost, validateRequestUrl } from "./security.js";
import { JsonStore } from "./store.js";
import type { HttpMethod, RequestInput, TrafficItem } from "./types.js";
import { CaManager } from "./ca.js";

const methods = new Set<HttpMethod>(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const hopByHop = new Set(["connection", "content-length", "transfer-encoding", "proxy-connection", "proxy-authorization", "proxy-authenticate", "keep-alive", "te", "trailer", "upgrade", "host"]);

function headersFromRequest(req: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(req.headers)) {
    if (hopByHop.has(key.toLowerCase()) || value === undefined) continue;
    headers[key] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

async function readBody(req: IncomingMessage): Promise<string | undefined> {
  const sendBody = !["GET", "HEAD"].includes(req.method || "");
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const part = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += part.length;
    if (size > MAX_BODY) throw new Error("Request body exceeds 1 MB");
    chunks.push(part);
  }
  return sendBody ? Buffer.concat(chunks).toString("utf8") : undefined;
}

function requestFromProxy(req: IncomingMessage, body?: string): RequestInput {
  const method = req.method as HttpMethod;
  if (!methods.has(method)) throw new Error("Unsupported HTTP method");
  if (!req.url || !/^https?:\/\//i.test(req.url)) throw new Error("Proxy requests must use an absolute http:// or https:// URL");
  return { method, url: req.url, headers: headersFromRequest(req), ...(body !== undefined ? { body } : {}) };
}

function writeError(res: ServerResponse, status: number, message: string) {
  const body = `Local HTTP Lab proxy: ${message}\n`;
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "content-length": Buffer.byteLength(body), connection: "close" });
  res.end(body);
}

function writeSocketError(socket: net.Socket, status: number, message: string) {
  const body = `Local HTTP Lab proxy: ${message}\n`;
  socket.end(`HTTP/1.1 ${status} ${status === 429 ? "Too Many Requests" : status === 403 ? "Forbidden" : "Service Unavailable"}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`);
}

function responseHeaders(response: TrafficItem["response"]): Record<string, string> {
  const headers = { ...(response?.headers || {}) };
  for (const name of Object.keys(headers)) if (hopByHop.has(name.toLowerCase())) delete headers[name];
  delete headers["content-length"];
  return headers;
}

function parseConnectTarget(authority: string): { host: string; port: number } {
  if (!authority || authority.includes("@") || /[/?#]/.test(authority)) throw new Error("CONNECT target must be a host and port");
  let host = authority;
  let port = 443;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) throw new Error("Invalid CONNECT target");
    host = authority.slice(1, end);
    if (authority.slice(end + 1)) {
      if (!authority.startsWith(`[${host}]:`)) throw new Error("Invalid CONNECT target");
      port = Number(authority.slice(end + 2));
    }
  } else {
    const colon = authority.lastIndexOf(":");
    if (colon > 0 && /^\d+$/.test(authority.slice(colon + 1))) {
      host = authority.slice(0, colon);
      port = Number(authority.slice(colon + 1));
    }
  }
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid CONNECT target port");
  return { host: host.replace(/^\[|\]$/g, "").toLowerCase(), port };
}

export interface ProxyStatus {
  running: boolean;
  host: "127.0.0.1";
  port: number;
  active?: number;
}
export interface PendingInterceptedRequest {
  id: string;
  createdAt: string;
  expiresAt: string;
  request: RequestInput;
  originalRequest: RequestInput;
}

interface PendingEntry extends PendingInterceptedRequest {
  response: ServerResponse;
  timer: NodeJS.Timeout;
  release: () => void;
}

export class LocalProxy {
  private server?: http.Server;
  private mitmHttpServer: http.Server;
  private caManager: CaManager;
  private configuredPort = 3002;
  private activePort = 3002;
  private pending = new Map<string, PendingEntry>();
  private active = 0;
  private requestTimes: number[] = [];
  private sockets = new Set<net.Socket>();
  constructor(private readonly store: JsonStore) {
    this.caManager = new CaManager(this.store.directory);
    this.mitmHttpServer = http.createServer((req, res) => {
      void this.handleMitm(req, res);
    });
  }

  getCaCertPem(): string {
    return this.caManager.getCaCertPem();
  }

  async interceptionStatus() {
    const settings = await this.store.settings();
    return {
      enabled: settings.interceptEnabled === true,
      pending: this.pending.size,
      maxPending: settings.maxPendingIntercepted ?? 100,
      timeoutMs: settings.interceptionTimeout ?? 30000
    };
  }

  status(): ProxyStatus {
    return {
      running: Boolean(this.server?.listening),
      host: "127.0.0.1",
      port: this.server?.address() && typeof this.server.address() !== "string" ? (this.server.address() as { port: number }).port : this.activePort,
      active: this.active
    };
  }

  async start(port?: number): Promise<ProxyStatus> {
    if (this.server?.listening) return this.status();
    const settings = await this.store.settings();
    const selected = port ?? settings.proxyPort ?? this.configuredPort;
    if (!Number.isInteger(selected) || selected < 1 || selected > 65535) throw new Error("Proxy port must be between 1 and 65535");
    this.configuredPort = selected;
    this.activePort = selected;
    const server = http.createServer((req, res) => { void this.handle(req, res); });
    server.on("connect", (req, socket, head) => { const tcpSocket = socket as net.Socket; this.sockets.add(tcpSocket); tcpSocket.once("close", () => this.sockets.delete(tcpSocket)); void this.handleConnect(req, tcpSocket, head); });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => { server.off("listening", onListening); this.server = undefined; reject(error); };
      const onListening = () => { server.off("error", onError); resolve(); };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(selected, "127.0.0.1");
    });
    const address = server.address();
    if (address && typeof address !== "string") this.activePort = address.port;
    return this.status();
  }

  async stop(): Promise<ProxyStatus> {
    if (!this.server) return this.status();
    await Promise.all([...this.pending.keys()].map((id) => this.dropPending(id, "Proxy stopped", "proxy_stopped")));
    for (const socket of this.sockets) socket.destroy();
    const server = this.server;
    this.server = undefined;
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return this.status();
  }

  private async acquire(settings: Awaited<ReturnType<JsonStore["settings"]>>): Promise<() => void> {
    const now = Date.now();
    const windowStart = now - 60000;
    this.requestTimes = this.requestTimes.filter((time) => time >= windowStart);
    if (this.requestTimes.length >= (settings.proxyRateLimitPerMinute ?? 120)) throw new Error("Proxy request rate limit exceeded");
    this.requestTimes.push(now);
    if (this.active >= (settings.proxyMaxConcurrent ?? 20)) throw new Error("Proxy concurrency limit reached");
    this.active += 1;
    let released = false;
    return () => { if (!released) { released = true; this.active = Math.max(0, this.active - 1); } };
  }

  private requestForEdit(value: unknown, current: RequestInput): RequestInput {
    const source = value && typeof value === "object" && "request" in value ? (value as { request?: unknown }).request : value;
    const data = source && typeof source === "object" ? source as Partial<RequestInput> : {};
    const method = data.method === undefined ? current.method : data.method;
    const url = data.url === undefined ? current.url : data.url;
    if (typeof method !== "string" || !methods.has(method as HttpMethod)) throw new Error("Unsupported HTTP method");
    if (typeof url !== "string" || url.length > 4096) throw new Error("A valid URL is required");
    const headers: Record<string, string> = {};
    const suppliedHeaders = data.headers === undefined ? current.headers : data.headers;
    if (!suppliedHeaders || typeof suppliedHeaders !== "object") throw new Error("Invalid request headers");
    for (const [key, value] of Object.entries(suppliedHeaders)) {
      if (Object.keys(headers).length >= 50 || key.length > 256 || typeof value !== "string" || value.length > 8192) throw new Error("Invalid request headers");
      if (!hopByHop.has(key.toLowerCase())) headers[key] = value;
    }
    if (data.body !== undefined && (typeof data.body !== "string" || data.body.length > MAX_BODY)) throw new Error("Request body exceeds 1 MB");
    const request: RequestInput = { method: method as HttpMethod, url, headers };
    if (data.body !== undefined || current.body !== undefined) request.body = data.body === undefined ? current.body : data.body;
    return request;
  }

  async pendingInterceptions(): Promise<PendingInterceptedRequest[]> {
    return [...this.pending.values()].map(({ response: _response, timer: _timer, release: _release, ...entry }) => entry);
  }
  async getPending(id: string): Promise<PendingInterceptedRequest | undefined> {
    const entry = this.pending.get(id);
    if (!entry) return undefined;
    const { response: _response, timer: _timer, release: _release, ...result } = entry;
    return result;
  }
  async updatePending(id: string, value: unknown): Promise<PendingInterceptedRequest> {
    const entry = this.pending.get(id);
    if (!entry) throw new Error("Intercepted request not found");
    const request = this.requestForEdit(value, entry.request);
    const settings = await this.store.settings();
    await resolveAllowedHost(validateRequestUrl(request.url, settings), settings);
    if (this.pending.get(id) !== entry) throw new Error("Intercepted request not found");
    entry.request = request;
    return (await this.getPending(id))!;
  }

  private takePending(id: string): PendingEntry {
    const entry = this.pending.get(id);
    if (!entry) throw new Error("Intercepted request not found");
    this.pending.delete(id);
    clearTimeout(entry.timer);
    entry.release();
    return entry;
  }

  private async finishPending(entry: PendingEntry, request: RequestInput, status: TrafficItem["interceptionStatus"], error?: string) {
    const item: TrafficItem = { id: entry.id, createdAt: entry.createdAt, source: "proxy", kind: "http", request, originalRequest: entry.originalRequest, ...(status ? { interceptionStatus: status } : {}), ...(error ? { error } : {}) };
    await this.store.addTraffic(item);
    return item;
  }

  async continuePending(id: string, value?: unknown): Promise<TrafficItem> {
    const entry = this.pending.get(id);
    if (!entry) throw new Error("Intercepted request not found");
    const request = this.requestForEdit(value, entry.request);
    const settings = await this.store.settings();
    await resolveAllowedHost(validateRequestUrl(request.url, settings), settings);
    const taken = this.takePending(id);
    try {
      const response = await executeRequest(request, this.store);
      const item: TrafficItem = { id: taken.id, createdAt: taken.createdAt, source: "proxy", kind: "http", request, originalRequest: taken.originalRequest, response, interceptionStatus: "continued" };
      await this.store.addTraffic(item);
      taken.response.writeHead(response.status, response.statusText, responseHeaders(response));
      taken.response.end(response.body);
      return item;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Proxy request failed";
      const item = await this.finishPending(taken, request, "continued", message);
      writeError(taken.response, /allowed|private|unsafe|protocol|credentials|IP/i.test(message) ? 403 : 502, message);
      return item;
    }
  }

  async dropPending(id: string, reason = "Request dropped by user", status: TrafficItem["interceptionStatus"] = "dropped"): Promise<TrafficItem> {
    const entry = this.takePending(id);
    const item = await this.finishPending(entry, entry.request, status, reason);
    writeError(entry.response, status === "timed_out" ? 504 : 502, reason);
    return item;
  }

  private async enqueue(request: RequestInput, originalRequest: RequestInput, res: ServerResponse, settings: Awaited<ReturnType<JsonStore["settings"]>>, release: () => void) {
    const maxPending = settings.maxPendingIntercepted ?? 100;
    if (this.pending.size >= maxPending) {
      release();
      const message = "Interception queue is full";
      await this.store.addTraffic({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), source: "proxy", kind: "http", request, originalRequest, interceptionStatus: "queue_full", error: message });
      writeError(res, 503, message);
      return;
    }
    const id = crypto.randomUUID();
    const createdAt = new Date();
    const timeoutMs = settings.interceptionTimeout ?? 30000;
    const entry = {} as PendingEntry;
    Object.assign(entry, { id, createdAt: createdAt.toISOString(), expiresAt: new Date(createdAt.getTime() + timeoutMs).toISOString(), request, originalRequest, response: res, release });
    entry.timer = setTimeout(() => { if (this.pending.has(id)) void this.dropPending(id, "Intercepted request timed out", "timed_out").catch(() => undefined); }, timeoutMs);
    this.pending.set(id, entry);
    res.on("close", () => {
      if (this.pending.get(id)?.response === res && !res.writableEnded) {
        clearTimeout(entry.timer);
        this.pending.delete(id);
        release();
      }
    });
  }

  private async handleMitm(req: IncomingMessage, res: ServerResponse) {
    let request: RequestInput | undefined;
    let release: (() => void) | undefined;
    try {
      const settings = await this.store.settings();
      release = await this.acquire(settings);
      const hostHeader = req.headers.host || "";
      if (!hostHeader) throw new Error("Host header is required for HTTPS request");
      const rawUrl = req.url || "/";
      const fullUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${hostHeader}${rawUrl}`;
      const body = await readBody(req);
      request = {
        method: (req.method as HttpMethod) || "GET",
        url: fullUrl,
        headers: headersFromRequest(req),
        ...(body !== undefined ? { body } : {})
      };
      validateRequestUrl(request.url, settings);
      await resolveAllowedHost(new URL(request.url), settings);

      if (settings.interceptEnabled) {
        await this.enqueue(request, request, res, settings, release);
        release = undefined;
        return;
      }

      const response = await executeRequest(request, this.store);
      const item: TrafficItem = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), source: "proxy", kind: "http", request, response };
      await this.store.addTraffic(item);
      res.writeHead(response.status, response.statusText, responseHeaders(response));
      res.end(response.body);
    } catch (error) {
      const message = error instanceof Error ? error.message : "MITM proxy request failed";
      if (request) await this.store.addTraffic({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), source: "proxy", kind: "http", request, error: message });
      writeError(res, 502, message);
    } finally {
      release?.();
    }
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    if (req.url === "/ca.crt" || req.url === "http://http.lab/ca.crt" || req.url === "http://local-http-lab/ca.crt" || req.url?.endsWith("/ca.crt")) {
      const pem = this.caManager.getCaCertPem();
      res.writeHead(200, {
        "content-type": "application/x-x509-ca-cert",
        "content-disposition": "attachment; filename=\"local-http-lab-ca.crt\"",
        "content-length": Buffer.byteLength(pem)
      });
      res.end(pem);
      return;
    }

    let request: RequestInput | undefined;
    let release: (() => void) | undefined;
    try {
      const settings = await this.store.settings();
      release = await this.acquire(settings);
      request = requestFromProxy(req, await readBody(req));
      validateRequestUrl(request.url, settings);
      await resolveAllowedHost(new URL(request.url), settings);
      if (settings.interceptEnabled) {
        await this.enqueue(request, request, res, settings, release);
        release = undefined;
        return;
      }
      const response = await executeRequest(request, this.store);
      const item: TrafficItem = { id: crypto.randomUUID(), createdAt: new Date().toISOString(), source: "proxy", kind: "http", request, response };
      await this.store.addTraffic(item);
      res.writeHead(response.status, response.statusText, responseHeaders(response));
      res.end(response.body);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Proxy request failed";
      if (request) await this.store.addTraffic({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), source: "proxy", kind: "http", request, error: message });
      if (request && /allowed|private|unsafe|protocol|credentials|IP|DNS|port/i.test(message)) {
        const settings = await this.store.settings();
        await this.store.addAudit({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), action: "block", url: request.url, reason: message, mode: settings.authorizedTestingMode ? "authorized" : "safe" });
      }
      const status = /rate limit/i.test(message) ? 429 : /concurrency/i.test(message) ? 503 : /absolute|method|body exceeds/i.test(message) ? 400 : /allowed|private|unsafe|protocol|credentials|IP/i.test(message) ? 403 : 502;
      writeError(res, status, message);
    } finally {
      release?.();
    }
  }

  private async handleConnect(req: IncomingMessage, socket: net.Socket, head: Buffer) {
    let target: { host: string; port: number } | undefined;
    try {
      const settings = await this.store.settings();
      target = parseConnectTarget(req.url || "");
      const hostname = net.isIP(target.host) === 6 ? `[${target.host}]` : target.host;
      const targetUrl = new URL(`https://${hostname}:${target.port}/`);
      validateRequestUrl(targetUrl.toString(), settings);
      await resolveAllowedHost(targetUrl, settings);

      socket.write("HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n");

      const defaultHost = target.host;
      const tlsServer = tls.createServer({
        SNICallback: (servername, cb) => {
          try {
            const host = servername || defaultHost;
            const ctx = this.caManager.getSecureContext(host);
            cb(null, ctx);
          } catch (err) {
            cb(err as Error);
          }
        }
      }, (tlsSocket) => {
        this.sockets.add(tlsSocket);
        tlsSocket.once("close", () => this.sockets.delete(tlsSocket));
        this.mitmHttpServer.emit("connection", tlsSocket);
      });

      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));

      tlsServer.emit("connection", socket);
      if (head && head.length > 0) {
        socket.unshift(head);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "CONNECT request failed";
      writeSocketError(socket, 502, `CONNECT blocked: ${message}`);
    }
  }
}
