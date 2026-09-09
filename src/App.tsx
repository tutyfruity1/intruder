import { useEffect, useMemo, useState } from "react";
import { api, type ReconRun, type ProjectWorkspace, type Finding, type Evidence, type ScenarioManifest, type AutomationRun } from "./api";
import type { HeaderPair, HistoryItem, HttpMethod, IntruderMode, PayloadDictionaries, PayloadTransform, PendingInterceptedRequest, RequestInput, ResponseData, TrafficItem, ProxyStatus } from "./types";
import type { AppSettings } from "./api";

type Tab = "repeater" | "intruder" | "injection" | "traffic" | "history" | "recon" | "workspace" | "settings";
const methods: HttpMethod[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const blankPair = (): HeaderPair => ({ key: "", value: "" });
const pairsToHeaders = (pairs: HeaderPair[]) => Object.fromEntries(pairs.filter((p) => p.key.trim()).map((p) => [p.key.trim(), p.value]));
const pretty = (text: string) => { try { return JSON.stringify(JSON.parse(text), null, 2); } catch { return text; } };
const queryPairsFromUrl = (url: string): HeaderPair[] => {
  const queryStart = url.indexOf("?");
  if (queryStart < 0) return [blankPair()];
  const query = url.slice(queryStart + 1).split("#", 1)[0];
  const pairs = Array.from(new URLSearchParams(query).entries()).map(([key, value]) => ({ key, value }));
  return pairs.length ? pairs : [blankPair()];
};
const urlWithQueryPairs = (url: string, pairs: HeaderPair[]) => {
  const queryStart = url.indexOf("?");
  const hashStart = url.indexOf("#", queryStart >= 0 ? queryStart : 0);
  const base = (queryStart >= 0 ? url.slice(0, queryStart) : hashStart >= 0 ? url.slice(0, hashStart) : url);
  const hash = hashStart >= 0 ? url.slice(hashStart) : "";
  const query = new URLSearchParams();
  pairs.filter((pair) => pair.key.trim()).forEach((pair) => query.append(pair.key.trim(), pair.value));
  const serialized = query.toString();
  return `${base}${serialized ? `?${serialized}` : ""}${hash}`.replace(/%C2%A7/gi, "§");
};
const transformNames: Array<[PayloadTransform["operation"], string]> = [
  ["urlEncode", "URL encode"], ["urlDecode", "URL decode"], ["base64Encode", "Base64 encode"], ["base64Decode", "Base64 decode"],
  ["base64UrlEncode", "Base64 URL-safe encode"], ["base64UrlDecode", "Base64 URL-safe decode"], ["htmlEntityEncode", "HTML entity encode"],
  ["jsonEscape", "JSON escape"], ["unicodeEscape", "Unicode escape"], ["hexEncode", "Hex encode"], ["hexDecode", "Hex decode"],
  ["trim", "Trim"], ["lowercase", "Lowercase"], ["uppercase", "Uppercase"], ["prepend", "Prepend"], ["append", "Append"]
];
const previewTransform = (value: string, transform: PayloadTransform): string => {
  try {
    switch (transform.operation) {
      case "urlEncode": return encodeURIComponent(value);
      case "urlDecode": return decodeURIComponent(value);
      case "base64Encode": return btoa(Array.from(new TextEncoder().encode(value), (byte) => String.fromCharCode(byte)).join(""));
      case "base64Decode": return new TextDecoder().decode(Uint8Array.from(atob(value), (character) => character.charCodeAt(0)));
      case "base64UrlEncode": return previewTransform(value, { operation: "base64Encode" }).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      case "base64UrlDecode": return previewTransform(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="), { operation: "base64Decode" });
      case "htmlEntityEncode": return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character] || character));
      case "jsonEscape": return JSON.stringify(value).slice(1, -1);
      case "unicodeEscape": return Array.from(value).map((character) => { const codePoint = character.codePointAt(0)!; if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, "0")}`; const adjusted = codePoint - 0x10000; return `\\u${(0xd800 + (adjusted >> 10)).toString(16)}\\u${(0xdc00 + (adjusted & 0x3ff)).toString(16)}`; }).join("");
      case "hexEncode": return Array.from(new TextEncoder().encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
      case "hexDecode": return new TextDecoder().decode(Uint8Array.from(value.match(/.{1,2}/g) || [], (part) => parseInt(part, 16)));
      case "trim": return value.trim();
      case "lowercase": return value.toLowerCase();
      case "uppercase": return value.toUpperCase();
      case "prepend": return `${transform.value || ""}${value}`;
      case "append": return `${value}${transform.value || ""}`;
    }
  } catch { return "(invalid input)"; }
};
const cookiePairsFromHeaders = (headers: Record<string, string>): HeaderPair[] => {
  const cookie = Object.entries(headers).find(([key]) => key.toLowerCase() === "cookie")?.[1] || "";
  const pairs = cookie.split(";").map((part) => {
    const separator = part.indexOf("=");
    return separator < 0 ? { key: part.trim(), value: "" } : { key: part.slice(0, separator).trim(), value: part.slice(separator + 1).trim() };
  }).filter((pair) => pair.key);
  return pairs.length ? pairs : [blankPair()];
};
const headersWithCookies = (headers: Record<string, string>, pairs: HeaderPair[]) => {
  const next = Object.fromEntries(Object.entries(headers).filter(([key]) => key.toLowerCase() !== "cookie"));
  const cookie = pairs.filter((pair) => pair.key.trim()).map((pair) => `${pair.key.trim()}=${pair.value}`).join("; ");
  if (cookie) next.Cookie = cookie;
  return next;
};

const previewDocument = (body: string, requestUrl?: string) => {
  if (!requestUrl) return body;
  try {
    const base = document.createElement("base");
    base.href = new URL(requestUrl).href;
    const baseTag = base.outerHTML;
    if (/<head\b[^>]*>/i.test(body)) return body.replace(/<head\b[^>]*>/i, (tag) => `${tag}${baseTag}`);
    return `<!doctype html><html><head>${baseTag}</head><body>${body}</body></html>`;
  } catch {
    return body;
  }
};

function ResponsePanel({ response, error, requestUrl }: { response?: ResponseData; error?: string; requestUrl?: string }) {
  const [view, setView] = useState<"pretty" | "raw" | "hex" | "preview">("pretty");
  const [showHeaders, setShowHeaders] = useState(false);
  if (!response && !error) return <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">Response will appear here</div>;
  if (error) return <pre className="max-h-[28rem] overflow-auto rounded-lg border border-red-900/70 bg-red-950/40 p-4 text-sm text-red-200 whitespace-pre-wrap">{error}</pre>;
  const contentType = Object.entries(response!.headers).find(([key]) => key.toLowerCase() === "content-type")?.[1]?.toLowerCase() || "";
  const isHtml = contentType.includes("text/html") || /^\s*<!doctype html|^\s*<html[\s>]/i.test(response!.body);
  const looksLikeJson = /^\s*(?:\{[\s\S]*\}|\[[\s\S]*\])\s*$/.test(response!.body);
  const isJson = contentType.includes("application/json") || contentType.includes("+json") || looksLikeJson;
  const isXml = contentType.includes("xml") || /^\s*<\?xml[\s>]/i.test(response!.body);
  const previewKind = isHtml ? "HTML" : isJson ? "JSON" : isXml ? "XML" : "text";
  const body = view === "pretty" ? pretty(response!.body) : view === "hex" ? Array.from(new TextEncoder().encode(response!.body)).map((byte) => byte.toString(16).padStart(2, "0")).join(" ") : response!.body;
  return <div className="overflow-hidden rounded-lg border border-slate-800">
    <div className="flex items-center gap-3 border-b border-slate-800 bg-slate-950/60 px-3 py-2 text-xs"><span className={response!.status < 400 ? "text-teal-300" : "text-red-300"}>{response!.status} {response!.statusText}</span><span className="text-slate-500">{response!.durationMs} ms</span>{response!.truncated && <span className="text-warn">body truncated</span>}</div>
    <div className="flex gap-1 border-b border-slate-800 px-2 py-1">{(["pretty", "raw", "hex", "preview"] as const).map((item) => <button className={`rounded px-2 py-1 text-xs ${view === item ? "bg-slate-700 text-white" : "text-slate-500 hover:text-slate-200"}`} onClick={() => setView(item)} key={item}>{item[0].toUpperCase() + item.slice(1)}</button>)}</div>
    <button className="flex w-full items-center justify-between border-b border-slate-800 px-4 py-2 text-left text-xs text-slate-400 hover:text-slate-200" onClick={() => setShowHeaders((open) => !open)}><span>Response headers: {Object.keys(response!.headers).length}</span><span>{showHeaders ? "Hide" : "Show"}</span></button>
    {showHeaders && <pre className="max-h-56 overflow-auto border-b border-slate-800 bg-slate-950/40 p-4 text-xs text-slate-400 whitespace-pre-wrap">{Object.entries(response!.headers).map(([key, value]) => `${key}: ${value}`).join("\n") || "(no response headers)"}</pre>}
    {view === "preview" && isHtml ? <div className="bg-white p-2"><iframe title="HTML response preview" sandbox="allow-scripts" srcDoc={previewDocument(response!.body, requestUrl)} className="h-[70vh] min-h-[28rem] w-full rounded border border-slate-300 bg-white" /></div> : view === "preview" && isJson ? <pre className="max-h-[70vh] min-h-[28rem] overflow-auto bg-slate-950 p-4 text-xs text-slate-200 whitespace-pre-wrap">{pretty(response!.body)}</pre> : view === "preview" && isXml ? <pre className="max-h-[70vh] min-h-[28rem] overflow-auto bg-slate-950 p-4 text-xs text-slate-200 whitespace-pre-wrap">{response!.body}</pre> : view === "preview" ? <pre className="max-h-[70vh] min-h-[28rem] overflow-auto bg-slate-950 p-4 text-xs text-slate-200 whitespace-pre-wrap">{response!.body || "(empty response)"}</pre> : <pre className="max-h-[70vh] min-h-[28rem] overflow-auto p-4 text-xs text-slate-300 whitespace-pre-wrap">{body}</pre>}
  </div>;
}

function requestToRaw(value: RequestInput) {
  const headers = Object.entries(value.headers).map(([key, val]) => `${key}: ${val}`).join("\n");
  return `${value.method} ${value.url} HTTP/1.1\n${headers}${value.body ? `\n\n${value.body}` : "\n"}`;
}

function parseRawRequest(text: string): RequestInput | undefined {
  const [head, ...bodyParts] = text.replace(/\r\n/g, "\n").split("\n\n");
  const lines = head.split("\n");
  const [method, url] = (lines.shift() || "").trim().split(/\s+/);
  if (!method || !url || !methods.includes(method as HttpMethod)) return undefined;
  const headers: Record<string, string> = {};
  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator > 0) headers[line.slice(0, separator).trim()] = line.slice(separator + 1).trim();
  }
  return { method: method as HttpMethod, url, headers, body: bodyParts.join("\n\n") || undefined };
}

function SimpleRequestEditor({ value, onChange, onSend, loading }: { value: RequestInput; onChange: (v: RequestInput) => void; onSend: () => void; loading: boolean }) {
  const [rawText, setRawText] = useState(() => requestToRaw(value));
  useEffect(() => setRawText(requestToRaw(value)), [value.method, value.url, value.body, JSON.stringify(value.headers)]);
  const updateRaw = (text: string) => {
    setRawText(text);
    const parsed = parseRawRequest(text);
    if (parsed) onChange(parsed);
  };
  return <div className="space-y-3">
    <div className="flex items-center justify-between border-b border-slate-800 pb-2"><span className="text-xs text-slate-500">Complete HTTP request · edit method, URL, headers and body directly</span><button className="btn-primary px-4 py-1 text-xs" disabled={loading} onClick={onSend}>{loading ? "Sending…" : "Send"}</button></div>
    <textarea className="field min-h-[32rem] w-full resize-y font-mono text-xs leading-5" value={rawText} onChange={(event) => updateRaw(event.target.value)} spellCheck={false} />
    <p className="text-xs text-slate-500">Use <code>METHOD URL HTTP/1.1</code>, headers, an empty line, then the body.</p>
  </div>;
}

function RequestEditor({ value, onChange, onSend, loading }: { value: RequestInput; onChange: (v: RequestInput) => void; onSend: () => void; loading: boolean }) {
  const [view, setView] = useState<"structured" | "raw">("structured");
  const [rawText, setRawText] = useState("");
  const [pairs, setPairs] = useState<HeaderPair[]>(Object.entries(value.headers).map(([key, val]) => ({ key, value: val })) || [blankPair()]);
  const [queryPairs, setQueryPairs] = useState<HeaderPair[]>(queryPairsFromUrl(value.url));
  const [cookiePairs, setCookiePairs] = useState<HeaderPair[]>(cookiePairsFromHeaders(value.headers));
  useEffect(() => setPairs(Object.entries(value.headers).map(([key, val]) => ({ key, value: val })).concat(Object.keys(value.headers).length ? [] : [blankPair()])), [value.headers]);
  useEffect(() => setQueryPairs(queryPairsFromUrl(value.url)), [value.url]);
  useEffect(() => setCookiePairs(cookiePairsFromHeaders(value.headers)), [value.headers]);
  const update = (patch: Partial<RequestInput>) => onChange({ ...value, ...patch });
  const raw = `${value.method} ${value.url} HTTP/1.1\n${Object.entries(value.headers).map(([key, val]) => `${key}: ${val}`).join("\n")}${value.body ? `\n\n${value.body}` : ""}`;
  useEffect(() => { if (view === "structured") setRawText(raw); }, [raw, view]);
  const parseRaw = (text: string) => {
    const [head, ...bodyParts] = text.replace(/\r\n/g, "\n").split("\n\n");
    const lines = head.split("\n");
    const requestLine = lines.shift()?.trim().split(/\s+/) || [];
    const nextHeaders: Record<string, string> = {};
    for (const line of lines) { const separator = line.indexOf(":"); if (separator > 0) nextHeaders[line.slice(0, separator).trim()] = line.slice(separator + 1).trim(); }
    if (methods.includes(requestLine[0] as HttpMethod) && requestLine[1]) onChange({ method: requestLine[0] as HttpMethod, url: requestLine[1], headers: nextHeaders, body: bodyParts.join("\n\n") || undefined });
  };
  return <div className="space-y-4">
    <div className="flex items-center justify-between border-b border-slate-800 pb-2"><div className="flex gap-1"><button className={`rounded px-2 py-1 text-xs ${view === "structured" ? "bg-slate-700 text-white" : "text-slate-500"}`} onClick={() => setView("structured")}>Request</button><button className={`rounded px-2 py-1 text-xs ${view === "raw" ? "bg-slate-700 text-white" : "text-slate-500"}`} onClick={() => { setRawText(raw); setView("raw"); }}>Raw</button></div><div className="flex items-center gap-2"><span className="text-xs text-slate-500">HTTP request editor</span>{view === "raw" && <button className="btn-primary px-3 py-1 text-xs" disabled={loading} onClick={onSend}>{loading ? "Sending…" : "Send"}</button>}</div></div>
    {view === "raw" ? <textarea className="field min-h-[26rem] font-mono text-xs leading-5" value={rawText || raw} onChange={(event) => { setRawText(event.target.value); parseRaw(event.target.value); }} spellCheck={false} /> : <><div className="grid grid-cols-[110px_1fr_auto] gap-2">
      <select className="field method-select appearance-none border-emerald-400 bg-emerald-950/50 text-emerald-100 focus:border-emerald-300 focus:ring-emerald-300" value={value.method} onChange={(e) => update({ method: e.target.value as HttpMethod })}>{methods.map((m) => <option key={m}>{m}</option>)}</select>
      <input className="field" value={value.url} onChange={(e) => update({ url: e.target.value })} placeholder="http://localhost:3000/api/health" />
      <button className="btn-primary min-w-20" disabled={loading} onClick={onSend}>{loading ? "Sending…" : "Send"}</button>
    </div>
    <div>
      <div className="mb-1 flex items-center justify-between"><span className="label mb-0">Query parameters</span><button className="text-xs text-teal-300" onClick={() => setQueryPairs([...queryPairs, blankPair()])}>+ add</button></div>
      <div className="space-y-2">{queryPairs.map((pair, i) => <div className="grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><input className="field" placeholder="Parameter" value={pair.key} onChange={(e) => { const next = [...queryPairs]; next[i] = { ...pair, key: e.target.value }; setQueryPairs(next); update({ url: urlWithQueryPairs(value.url, next) }); }} /><input className="field" placeholder="Value" value={pair.value} onChange={(e) => { const next = [...queryPairs]; next[i] = { ...pair, value: e.target.value }; setQueryPairs(next); update({ url: urlWithQueryPairs(value.url, next) }); }} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => { const next = queryPairs.filter((_, j) => i !== j); setQueryPairs(next); update({ url: urlWithQueryPairs(value.url, next) }); }}>×</button></div>)}</div>
    </div>
    <div>
      <div className="mb-1 flex items-center justify-between"><span className="label mb-0">Headers</span><button className="text-xs text-teal-300" onClick={() => setPairs([...pairs, blankPair()])}>+ add</button></div>
      <div className="space-y-2">{pairs.map((pair, i) => <div className="grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><input className="field" placeholder="Header" value={pair.key} onChange={(e) => { const next = [...pairs]; next[i] = { ...pair, key: e.target.value }; setPairs(next); update({ headers: pairsToHeaders(next) }); }} /><input className="field" placeholder="Value" value={pair.value} onChange={(e) => { const next = [...pairs]; next[i] = { ...pair, value: e.target.value }; setPairs(next); update({ headers: pairsToHeaders(next) }); }} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => { const next = pairs.filter((_, j) => i !== j); setPairs(next); update({ headers: pairsToHeaders(next) }); }}>×</button></div>)}</div>
    </div>
    <div>
      <div className="mb-1 flex items-center justify-between"><span className="label mb-0">Cookies</span><button className="text-xs text-teal-300" onClick={() => setCookiePairs([...cookiePairs, blankPair()])}>+ add</button></div>
      <div className="space-y-2">{cookiePairs.map((pair, i) => <div className="grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><input className="field" placeholder="Cookie name" value={pair.key} onChange={(e) => { const next = [...cookiePairs]; next[i] = { ...pair, key: e.target.value }; setCookiePairs(next); update({ headers: headersWithCookies(value.headers, next) }); }} /><input className="field" placeholder="Cookie value" value={pair.value} onChange={(e) => { const next = [...cookiePairs]; next[i] = { ...pair, value: e.target.value }; setCookiePairs(next); update({ headers: headersWithCookies(value.headers, next) }); }} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => { const next = cookiePairs.filter((_, j) => i !== j); setCookiePairs(next); update({ headers: headersWithCookies(value.headers, next) }); }}>×</button></div>)}</div>
    </div>
    <div><label className="label">Body</label><textarea className="field min-h-32 font-mono text-xs" value={value.body || ""} onChange={(e) => update({ body: e.target.value })} placeholder='{"hello":"world"}' /></div></>}
  </div>;
}

function Repeater({ loadedRequest }: { loadedRequest?: RequestInput }) {
  const [request, setRequest] = useState<RequestInput>(loadedRequest || { method: "GET", url: "http://localhost:3001/api/health", headers: {} });
  const [response, setResponse] = useState<ResponseData>(); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  useEffect(() => { if (loadedRequest) { setRequest(loadedRequest); setResponse(undefined); setError(""); } }, [loadedRequest]);
  useEffect(() => { const handler = (event: KeyboardEvent) => { if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); void send(); } }; window.addEventListener("keydown", handler); return () => window.removeEventListener("keydown", handler); });
  const send = async () => { setLoading(true); setError(""); setResponse(undefined); try { setResponse((await api.request(request)).response); } catch (e) { setError((e as Error).message); } finally { setLoading(false); } };
  return <div className="grid gap-4 lg:grid-cols-2"><section className="card"><h2 className="mb-4 text-lg font-semibold">HTTP request</h2><SimpleRequestEditor value={request} onChange={setRequest} onSend={send} loading={loading} /></section><section className="card"><h2 className="mb-4 text-lg font-semibold">Response</h2><ResponsePanel response={response} error={error} requestUrl={request.url} /></section></div>;
}

function InterceptionPanel({ onLoad, onIntruder }: { onLoad: (request: RequestInput) => void; onIntruder: (request: RequestInput) => void }) {
  const [enabled, setEnabled] = useState(false); const [pending, setPending] = useState<PendingInterceptedRequest[]>([]); const [edits, setEdits] = useState<Record<string, RequestInput>>({}); const [error, setError] = useState("");
  const refresh = async () => { try { const [state, list] = await Promise.all([api.interceptionStatus(), api.pendingInterceptions()]); setEnabled(state.interception.enabled); setPending(list.items); setEdits((old) => Object.fromEntries(list.items.map((item) => [item.id, old[item.id] || item.request]))); setError(""); } catch (e) { setError((e as Error).message); } };
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 1000); return () => window.clearInterval(timer); }, []);
  const action = async (id: string, kind: "continue" | "drop") => { try { if (kind === "continue") await api.continueInterception(id, edits[id]); else await api.dropInterception(id); await refresh(); } catch (e) { setError((e as Error).message); } };
  return <section className="card"><div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-lg font-semibold">Intercept before forwarding</h2><p className="mt-1 text-xs text-slate-400">HTTP requests pause here until you continue or drop them. HTTPS CONNECT remains unsupported.</p></div><div className="flex items-center gap-2"><span className={`rounded-full px-3 py-1 text-xs ${enabled ? "bg-amber-950 text-amber-300" : "bg-slate-800 text-slate-400"}`}>{enabled ? `${pending.length} pending` : "Disabled"}</span><button className={enabled ? "btn-danger" : "btn-primary"} onClick={() => void api.toggleInterception(!enabled).then(refresh).catch((e) => setError((e as Error).message))}>{enabled ? "Disable intercept" : "Enable intercept"}</button></div></div>{error && <p className="mt-2 text-sm text-red-300">{error}</p>}{enabled && (pending.length ? <div className="mt-4 space-y-3">{pending.map((item) => <details className="rounded-lg border border-amber-900/60 p-3" key={item.id} open><summary className="cursor-pointer text-sm"><span className="mr-3 text-amber-300">{item.request.method}</span><span className="text-slate-300">{item.request.url}</span><span className="float-right text-xs text-slate-500">expires {new Date(item.expiresAt).toLocaleTimeString()}</span></summary><div className="mt-3"><SimpleRequestEditor value={edits[item.id] || item.request} onChange={(request) => setEdits((old) => ({ ...old, [item.id]: request }))} onSend={() => undefined} loading={false} /><div className="mt-3 flex flex-wrap gap-2"><button className="btn-primary" onClick={() => void action(item.id, "continue")}>Continue and forward</button><button className="btn-secondary" onClick={() => onLoad(edits[item.id] || item.request)}>Send to Repeater</button><button className="btn-secondary" onClick={() => onIntruder(edits[item.id] || item.request)}>Send to Intruder</button><button className="btn-danger" onClick={() => void action(item.id, "drop")}>Drop</button></div></div></details>)}</div> : <p className="mt-4 text-sm text-slate-500">No requests are waiting.</p>)}</section>;
}

function Traffic({ onLoad, onIntruder }: { onLoad: (request: RequestInput) => void; onIntruder: (request: RequestInput) => void }) {
  const [status, setStatus] = useState<ProxyStatus>(); const [port, setPort] = useState(3002);
  const [items, setItems] = useState<TrafficItem[]>([]); const [selected, setSelected] = useState<TrafficItem>(); const [edited, setEdited] = useState<RequestInput>(); const [query, setQuery] = useState(""); const [error, setError] = useState("");
  const refresh = async () => { try { const [state, traffic] = await Promise.all([api.proxyStatus(), api.traffic(query)]); setStatus(state.proxy); setPort(state.proxy.port); setItems(traffic.items); setError(""); } catch (e) { setError((e as Error).message); } };
  useEffect(() => { void refresh(); }, []);
  useEffect(() => { const timer = window.setInterval(() => void refresh(), 3000); return () => window.clearInterval(timer); }, [query]);
  const toggle = async () => { try { if (status?.running) await api.stopProxy(); else await api.startProxy(port); await refresh(); } catch (e) { setError((e as Error).message); } };
  return <div className="space-y-4">
    <InterceptionPanel onLoad={onLoad} onIntruder={onIntruder} />
    <section className="card"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">Restricted HTTP/HTTPS proxy</h2><p className="mt-1 text-xs text-slate-400">HTTP is captured. HTTPS CONNECT is a blind tunnel for allowlisted targets only; it is never decrypted or intercepted.</p></div><span className={`rounded-full px-3 py-1 text-xs ${status?.running ? "bg-teal-950 text-teal-300" : "bg-slate-800 text-slate-400"}`}>{status?.running ? `Running on ${status.host}:${status.port}` : "Stopped"}</span></div><div className="mt-4 flex flex-wrap items-end gap-2"><label className="label mb-0 w-40">Proxy port<input className="field mt-1" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} /></label><button className={status?.running ? "btn-danger" : "btn-primary"} onClick={() => void toggle()}>{status?.running ? "Stop proxy" : "Start proxy"}</button></div><p className="mt-3 text-xs text-slate-500">Configure your HTTP client/browser manually to use <code>127.0.0.1:{status?.port || port}</code>. HTTP URLs appear with captured responses; HTTPS URLs appear as tunnel metadata only.</p>{error && <p className="mt-2 text-sm text-red-300">{error}</p>}</section>
    <section className="card"><div className="mb-4 flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-lg font-semibold">Captured traffic</h2><p className="text-xs text-slate-400">HTTP entries include captured response data. HTTPS entries contain tunnel metadata only; plaintext is never captured.</p></div><div className="flex gap-2"><input className="field w-64" placeholder="Search method, URL, error…" value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn-danger" onClick={() => api.clearTraffic().then(refresh)}>Clear</button></div></div>{items.length === 0 ? <p className="py-12 text-center text-sm text-slate-500">No proxied requests yet.</p> : <div className="space-y-2">{items.map((item) => <details className="rounded-lg border border-slate-800 p-3" key={item.id} onClick={() => { setSelected(item); setEdited({ ...item.request, headers: { ...item.request.headers } }); }}><summary className="cursor-pointer text-sm"><span className={`mr-3 ${item.kind === "https-tunnel" ? "text-violet-300" : "text-teal-300"}`}>{item.kind === "https-tunnel" ? "HTTPS TUNNEL" : item.request.method}</span><span className="text-slate-300">{item.request.url}</span><span className={`float-right text-xs ${item.error ? "text-red-300" : "text-slate-500"}`}>{item.kind === "https-tunnel" ? `${item.tunnel?.connected ? "connected" : "blocked"} · ${item.tunnel?.bytesSent || 0}↑ ${item.tunnel?.bytesReceived || 0}↓` : item.interceptionStatus ? `${item.interceptionStatus}${item.error ? ` · ${item.error}` : ""}` : item.error || `${item.response?.status} · ${item.response?.durationMs} ms`}</span></summary><div className="mt-3 grid gap-3 lg:grid-cols-2"><div><h3 className="label">{item.kind === "https-tunnel" ? "Tunnel metadata (no plaintext)" : "Request"}</h3><pre className="max-h-56 overflow-auto rounded border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400 whitespace-pre-wrap">{item.kind === "https-tunnel" ? JSON.stringify(item.tunnel, null, 2) : requestToRaw(item.request)}</pre></div><div><h3 className="label">{item.kind === "https-tunnel" ? "Status" : "Response"}</h3><pre className="max-h-56 overflow-auto rounded border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400 whitespace-pre-wrap">{item.kind === "https-tunnel" ? "HTTPS CONNECT is not intercepted or decrypted." : item.error || pretty(item.response?.body || "")}</pre></div></div>{item.kind !== "https-tunnel" && <div className="mt-3 flex flex-wrap gap-2"><button className="btn-secondary text-xs" onClick={(event) => { event.preventDefault(); onLoad(item.request); }}>Send to Repeater</button><button className="btn-secondary text-xs" onClick={(event) => { event.preventDefault(); onIntruder(item.request); }}>Send to Intruder</button><button className="text-xs text-red-300" onClick={(event) => { event.preventDefault(); void api.deleteTraffic(item.id).then(refresh); }}>Delete</button></div>}</details>)}</div>}</section>
    {selected && edited && <section className="card"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-lg font-semibold">Request editor</h2><p className="text-xs text-slate-400">Modify the captured HTTP request, then load the edited version into Repeater.</p></div><button className="text-xs text-slate-400 hover:text-white" onClick={() => { setSelected(undefined); setEdited(undefined); }}>Close</button></div><SimpleRequestEditor value={edited} onChange={setEdited} onSend={() => onLoad(edited)} loading={false} /><div className="mt-4 flex gap-2"><button className="btn-primary" onClick={() => onLoad(edited)}>Load edited request into Repeater</button><button className="btn-secondary" onClick={() => setEdited({ ...selected.request, headers: { ...selected.request.headers } })}>Reset changes</button></div></section>}
  </div>;
}

function Intruder({ loadedRequest }: { loadedRequest?: RequestInput }) {
  const [base, setBase] = useState<RequestInput>({ method: "GET", url: "http://localhost:3001/api/health?value=§test§", headers: {} });
  const [mode, setMode] = useState<IntruderMode>("sniper"); const [payloads, setPayloads] = useState("one\ntwo\nthree"); const [dictionaryName, setDictionaryName] = useState(""); const [transforms, setTransforms] = useState<PayloadTransform[]>([]); const [dictionaryTexts, setDictionaryTexts] = useState<Record<string, string>>({}); const [concurrency, setConcurrency] = useState(3); const [delay, setDelay] = useState(100); const [generated, setGenerated] = useState<RequestInput[]>([]); const [results, setResults] = useState<Array<{ request: RequestInput; response?: ResponseData; error?: string }>>([]); const [resultFilter, setResultFilter] = useState<"all" | "success" | "error">("all"); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  const payloadList = useMemo(() => payloads.split(/\r?\n|,/).map((x) => x.trim()).filter(Boolean), [payloads]);
  useEffect(() => { if (loadedRequest) setBase({ ...loadedRequest, headers: { ...loadedRequest.headers } }); }, [loadedRequest]);
  const markerNames = useMemo(() => Array.from(new Set(Array.from(JSON.stringify(base).matchAll(/§([^§]+)§|\{\{([^{}]+)\}\}/g), (match) => (match[1] || match[2]).trim()))), [base]);
  const payloadDictionaries = useMemo<PayloadDictionaries>(() => Object.fromEntries(Object.entries(dictionaryTexts).map(([name, text]) => [name, text.split(/\r?\n|,/).map((x) => x.trim()).filter(Boolean)])), [dictionaryTexts]);
  const visibleResults = useMemo(() => results.filter((item) => resultFilter === "all" || (resultFilter === "error" ? Boolean(item.error) : Boolean(item.response))), [results, resultFilter]);
  const loadDictionary = async (file: File) => {
    try {
      const text = await file.text();
      const entries = text.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
      if (!entries.length) throw new Error("Dictionary file is empty");
      setPayloads(entries.join("\n"));
      setDictionaryName(`${file.name} · ${entries.length} values`);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not read dictionary file");
    }
  };
  const run = async (execute: boolean) => {
    setLoading(true); setError("");
    try {
      const payload = { request: base, mode, payloads: payloadList, payloadDictionaries, transformations: transforms };
      if (execute) setResults((await api.runIntruder({ ...payload, concurrency, delay })).results);
      else setGenerated((await api.generateIntruder(payload)).requests);
    } catch (e) { setError((e as Error).message); } finally { setLoading(false); }
  };
  return <div className="space-y-4"><div className="grid gap-4 lg:grid-cols-[1.1fr_.9fr]"><section className="card space-y-4"><div><h2 className="text-lg font-semibold">Restricted Intruder</h2><p className="mt-1 text-xs text-slate-400">Use §markers§ in the URL, headers, or body. The dictionary is available for every Intruder mode.</p></div><div><label className="label">Mode</label><select className="field tool-select" value={mode} onChange={(e) => { setMode(e.target.value as IntruderMode); setResults([]); setGenerated([]); }}><option value="sniper">Sniper — one position at a time</option><option value="batteringRam">Battering ram — same payload in every position</option><option value="pitchfork">Pitchfork — payload lists advance together</option><option value="clusterBomb">Cluster bomb — every combination</option></select></div><SimpleRequestEditor value={base} onChange={setBase} onSend={() => void run(true)} loading={loading} /><div><div className="mb-1 flex items-center justify-between"><label className="label mb-0">Payload dictionary</label><label className="btn-secondary cursor-pointer text-xs">Add .txt / .csv dictionary<input className="hidden" type="file" accept=".txt,.csv,text/plain,text/csv" onChange={(event) => { const file = event.target.files?.[0]; if (file) void loadDictionary(file); event.currentTarget.value = ""; }} /></label></div><textarea className="field min-h-24 font-mono text-xs" value={payloads} onChange={(e) => { setPayloads(e.target.value); setDictionaryName(""); }} />{dictionaryName && <p className="mt-1 text-xs text-teal-300">{dictionaryName}</p>}<p className="mt-1 text-xs text-slate-500">One value per line or comma-separated. Used by Sniper, Battering Ram, Pitchfork and Cluster Bomb.</p></div>{(mode === "pitchfork" || mode === "clusterBomb") && markerNames.length > 1 && <div><label className="label">Per-marker dictionaries</label><div className="space-y-2">{markerNames.map((name) => <textarea key={name} className="field min-h-16 font-mono text-xs" placeholder={`${name}: one value per line`} value={dictionaryTexts[name] || ""} onChange={(e) => setDictionaryTexts((old) => ({ ...old, [name]: e.target.value }))} />)}</div><p className="mt-1 text-xs text-slate-500">Named dictionaries override the shared list for Pitchfork and Cluster Bomb.</p></div>}<div><div className="mb-1 flex items-center justify-between"><label className="label mb-0">Payload transformations</label><button className="text-xs text-teal-300" onClick={() => setTransforms([...transforms, { operation: "urlEncode" }])}>+ add step</button></div>{transforms.map((transform, i) => <div className="mb-2 grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><select className="field" value={transform.operation} onChange={(e) => { const next = [...transforms]; next[i] = { ...transform, operation: e.target.value as PayloadTransform["operation"] }; setTransforms(next); }} >{transformNames.map(([operation, label]) => <option value={operation} key={operation}>{label}</option>)}</select><input className="field" placeholder="Prefix / suffix (optional)" value={transform.value || ""} onChange={(e) => { const next = [...transforms]; next[i] = { ...transform, value: e.target.value }; setTransforms(next); }} disabled={!["prepend", "append"].includes(transform.operation)} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => setTransforms(transforms.filter((_, j) => i !== j))}>×</button></div>)}<p className="text-xs text-slate-500">Steps run in order for every payload. An empty chain preserves existing behavior.</p>{transforms.length > 0 && <div className="mt-2 space-y-1 text-xs"><div className="text-slate-400">Payload preview</div>{payloadList.slice(0, 20).map((payload) => <div className="grid grid-cols-2 gap-2" key={payload}><code className="truncate text-slate-500">{payload}</code><code className="truncate text-teal-300">{transforms.reduce((current, transform) => previewTransform(current, transform), payload)}</code></div>)}</div>}</div><div className="grid grid-cols-2 gap-2"><label className="label">Concurrency<input className="field mt-1" type="number" min={1} max={10} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} /></label><label className="label">Delay (ms)<input className="field mt-1" type="number" min={0} max={10000} value={delay} onChange={(e) => setDelay(Number(e.target.value))} /></label></div>  <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-400">Request budget: <span className="text-slate-200">{generated.length || "preview required"}</span> candidates · {concurrency} concurrent · {delay} ms delay.</div><div className="flex gap-2"><button className="btn-secondary" disabled={loading} onClick={() => void run(false)}>Preview requests</button><button className="btn-primary" disabled={loading} onClick={() => void run(true)}>Run intruder</button></div>{error && <p className="text-sm text-red-300">{error}</p>}</section>  <section className="card"><div className="mb-4 flex items-center justify-between"><h2 className="text-lg font-semibold">{results.length ? `Results · ${visibleResults.length}/${results.length}` : "Preview"}</h2>{results.length > 0 && <select className="field w-32" value={resultFilter} onChange={(e) => setResultFilter(e.target.value as typeof resultFilter)}><option value="all">All results</option><option value="success">Responses</option><option value="error">Errors</option></select>}</div>{results.length ? <div className="max-h-[38rem] space-y-2 overflow-auto">{visibleResults.map((r, i) => <div className="rounded-lg border border-slate-800 p-3 text-xs" key={i}><div className="flex justify-between"><span className="truncate text-slate-400">{r.request.url}</span><span className={r.error ? "text-red-300" : "text-teal-300"}>{r.error || `${r.response?.status} · ${r.response?.durationMs} ms`}</span></div></div>)}</div> : generated.length ? <div className="max-h-[38rem] space-y-2 overflow-auto">{generated.map((r, i) => <pre className="overflow-auto rounded-lg border border-slate-800 p-3 text-xs text-slate-400" key={i}>{i + 1}. {r.method} {r.url}</pre>)}</div> : <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">Generate a safe preview before running</div>}</section></div></div>;
}

type InjectionCategory = "sql" | "xss" | "template" | "path" | "header";
const injectionProbes: Record<InjectionCategory, Array<{ name: string; value: string; purpose: string }>> = {
  sql: [
    { name: "Quote handling", value: "§'§", purpose: "Checks whether a quote causes an input-handling error." },
    { name: "Boolean comparison", value: "§' AND '1'='1§", purpose: "Non-destructive response comparison probe; never extracts data." },
    { name: "Comment parsing", value: "§test'--§", purpose: "Checks comment parsing and error handling." }
  ],
  xss: [
    { name: "HTML marker", value: "§<x-lab-marker>§", purpose: "Inert HTML element marker for reflection checks." },
    { name: "Attribute marker", value: "§\" data-lab-marker=\"1§", purpose: "Checks whether input is escaped inside an attribute." },
    { name: "Script-context marker", value: "§';/*lab*/§", purpose: "Text-only marker for context analysis; no executable script." }
  ],
  template: [
    { name: "Expression marker", value: "§{{lab_marker}}§", purpose: "Checks whether template delimiters are evaluated or rendered as text." },
    { name: "Alternate expression", value: "§${lab_marker}§", purpose: "Checks interpolation handling without executing code." }
  ],
  path: [
    { name: "Traversal marker", value: "§../lab-marker§", purpose: "Checks traversal normalization without targeting a real file." },
    { name: "Encoded traversal marker", value: "§%2e%2e%2flab-marker§", purpose: "Checks decoding and canonicalization." }
  ],
  header: [
    { name: "CRLF marker", value: "§lab-header-marker§", purpose: "Checks header value validation; CRLF characters are intentionally excluded." },
    { name: "Host variation", value: "§lab.invalid§", purpose: "Checks whether host-like input is validated consistently." }
  ]
};

function InjectionLab({ loadedRequest, onLoad, onIntruder }: { loadedRequest?: RequestInput; onLoad: (request: RequestInput) => void; onIntruder: (request: RequestInput) => void }) {
  const [request, setRequest] = useState<RequestInput>(loadedRequest || { method: "GET", url: "http://localhost:3001/api/health?probe=§lab-marker§", headers: {} });
  const [category, setCategory] = useState<InjectionCategory>("sql");
  const [probeIndex, setProbeIndex] = useState(0);
  const [result, setResult] = useState<ResponseData>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => { if (loadedRequest) setRequest({ ...loadedRequest, headers: { ...loadedRequest.headers } }); }, [loadedRequest]);
  const probe = injectionProbes[category][probeIndex] || injectionProbes[category][0];
  const applyProbe = () => setRequest((current) => ({ ...current, url: current.url.includes("§") ? current.url.replace(/§[^§]*§/, probe.value) : `${current.url}${current.url.includes("?") ? "&" : "?"}probe=${probe.value}` }));
  const send = async () => {
    setLoading(true); setError(""); setResult(undefined);
    try { setResult((await api.request(request)).response); } catch (e) { setError((e as Error).message); } finally { setLoading(false); }
  };
  return <div className="grid gap-4 lg:grid-cols-[1.1fr_.9fr]">
    <section className="card space-y-4"><div><h2 className="text-lg font-semibold">Injection Lab</h2><p className="mt-1 text-xs text-slate-400">Diagnostic probes for authorized local targets. Compare status, errors and reflection; probes do not extract data or bypass authentication.</p></div>
      <div className="grid gap-2 sm:grid-cols-2"><label className="label">Injection family<select className="field mt-1" value={category} onChange={(e) => { setCategory(e.target.value as InjectionCategory); setProbeIndex(0); }}><option value="sql">SQL injection</option><option value="xss">XSS / HTML context</option><option value="template">Template expression</option><option value="path">Path traversal</option><option value="header">Header validation</option></select></label><label className="label">Diagnostic probe<select className="field mt-1" value={probeIndex} onChange={(e) => setProbeIndex(Number(e.target.value))}>{injectionProbes[category].map((item, index) => <option value={index} key={item.name}>{item.name}</option>)}</select></label></div>
      <div className="rounded border border-slate-800 bg-slate-950/50 p-3 text-xs"><div className="text-slate-400">Probe</div><code className="mt-1 block break-all text-amber-300">{probe.value}</code><p className="mt-2 text-slate-500">{probe.purpose}</p><button className="btn-secondary mt-3 text-xs" onClick={applyProbe}>Insert probe into first marker</button></div>
      <SimpleRequestEditor value={request} onChange={setRequest} onSend={send} loading={loading} />
      <div className="flex flex-wrap gap-2"><button className="btn-secondary" onClick={() => onLoad(request)}>Send to Repeater</button><button className="btn-secondary" onClick={() => onIntruder(request)}>Send to Intruder</button></div>
    </section>
    <section className="card"><h2 className="mb-4 text-lg font-semibold">Diagnostic result</h2>{error ? <pre className="rounded border border-red-900/70 bg-red-950/40 p-4 text-sm text-red-200 whitespace-pre-wrap">{error}</pre> : result ? <ResponsePanel response={result} requestUrl={request.url} /> : <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">Send a probe to inspect the response</div>}</section>
  </div>;
}

function History() {
  const [items, setItems] = useState<HistoryItem[]>([]); const [error, setError] = useState("");
  const refresh = () => api.history().then((d) => setItems(d.items)).catch((e) => setError((e as Error).message));
  useEffect(() => { refresh(); }, []);
  return <section className="card"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-lg font-semibold">Request history</h2><p className="text-xs text-slate-400">Stored locally in data/history.json.</p></div><button className="btn-danger" onClick={() => api.clearHistory().then(refresh)}>Clear history</button></div>{error && <p className="text-red-300">{error}</p>}{items.length === 0 ? <p className="py-12 text-center text-sm text-slate-500">No requests yet.</p> : <div className="space-y-2">{items.map((item) => <details className="rounded-lg border border-slate-800 p-3" key={item.id}><summary className="cursor-pointer text-sm"><span className="mr-3 text-teal-300">{item.request.method}</span><span className="text-slate-300">{item.request.url}</span><span className="float-right text-xs text-slate-500">{new Date(item.createdAt).toLocaleString()}</span></summary><pre className="mt-3 max-h-48 overflow-auto text-xs text-slate-400">{item.error || pretty(item.response?.body || "")}</pre></details>)}</div>}</section>;
}

function SecurityCenter() {
  const [settings, setSettings] = useState<AppSettings>();
  const [externalHosts, setExternalHosts] = useState("");
  const [allowedHosts, setAllowedHosts] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [audit, setAudit] = useState<Array<{ id: string; createdAt: string; action: "allow" | "block"; url: string; reason: string; mode: "safe" | "authorized" }>>([]);

  useEffect(() => {
    api.settings()
      .then(({ settings: current }) => {
        setSettings(current);
        setAllowedHosts(current.allowedHosts.join("\n"));
        setExternalHosts(current.externalAllowedHosts.join("\n"));
      })
      .catch((e) => setError((e as Error).message));
    api.audit().then(({ items }) => setAudit(items.slice(0, 20))).catch((e) => setError((e as Error).message));
  }, []);

  if (!settings) return <section className="card"><p className="text-sm text-slate-400">Loading security policy…</p>{error && <p className="mt-2 text-sm text-red-300">{error}</p>}</section>;

  const update = (patch: Partial<AppSettings>) => setSettings((current) => current ? { ...current, ...patch } : current);
  const save = async () => {
    setSaving(true);
    setMessage("");
    setError("");
    try {
      const next = await api.saveSettings({
        ...settings,
        allowedHosts: allowedHosts.split(/\r?\n|,/).map((host) => host.trim()).filter(Boolean),
        externalAllowedHosts: externalHosts.split(/\r?\n|,/).map((host) => host.trim()).filter(Boolean)
      });
      const saved = (next as { settings: AppSettings }).settings;
      setSettings(saved);
      setAllowedHosts(saved.allowedHosts.join("\n"));
      setExternalHosts(saved.externalAllowedHosts.join("\n"));
      setMessage("Security policy saved locally.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }

    function Recon() {
      const [urls, setUrls] = useState("http://localhost:3001/api/health");
      const [runs, setRuns] = useState<ReconRun[]>([]);
      const [selected, setSelected] = useState<ReconRun>();
      const [error, setError] = useState("");
      const refresh = () => api.reconRuns().then(({ runs: current }) => { setRuns(current); if (selected) setSelected(current.find((run) => run.id === selected.id)); }).catch((e) => setError((e as Error).message));
      useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 2000); return () => window.clearInterval(timer); }, []);
      const targets = urls.split(/\r?\n|,/).map((url) => url.trim()).filter(Boolean);
      const create = async (mode: "passive" | "active") => {
        setError("");
        try {
          const result = mode === "passive" ? await api.createPassiveRecon(targets) : await api.createActiveRecon(targets, true);
          setSelected(result.run);
          await refresh();
        } catch (e) { setError((e as Error).message); }
      };
      return <div className="space-y-4">
        <section className="card space-y-4"><div><h2 className="text-lg font-semibold">Recon Workspace</h2><p className="mt-1 text-xs text-slate-400">Passive collection accepts only explicitly supplied URLs. Active checks require Authorized Testing Mode and are bounded server-side.</p></div><label className="label">Target URLs<textarea className="field mt-1 min-h-28 font-mono text-xs" value={urls} onChange={(e) => setUrls(e.target.value)} /></label><div className="flex flex-wrap gap-2"><button className="btn-secondary" disabled={!targets.length} onClick={() => void create("passive")}>Start passive recon</button><button className="btn-primary" disabled={!targets.length} onClick={() => void create("active")}>Start authorized active check</button></div>{error && <p className="text-sm text-red-300">{error}</p>}</section>
        <section className="card"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-lg font-semibold">Runs</h2><p className="text-xs text-slate-400">Run metadata and findings are stored locally.</p></div><button className="btn-secondary text-xs" onClick={refresh}>Refresh</button></div>{runs.length === 0 ? <p className="py-8 text-center text-sm text-slate-500">No recon runs yet.</p> : <div className="space-y-2">{runs.map((run) => <button className={`w-full rounded-lg border p-3 text-left ${selected?.id === run.id ? "border-teal-700 bg-teal-950/20" : "border-slate-800"}`} key={run.id} onClick={() => setSelected(run)}><div className="flex flex-wrap items-center justify-between gap-2 text-sm"><span className="text-teal-300">{run.mode}</span><span className="text-slate-300">{run.status}</span><span className="text-xs text-slate-500">{run.findings.length} findings · {new Date(run.createdAt).toLocaleString()}</span></div><div className="mt-1 truncate text-xs text-slate-400">{run.urls.join(", ")}</div></button>)}</div>}</section>
        {selected && <section className="card"><div className="flex items-center justify-between"><h2 className="text-lg font-semibold">Run findings</h2>{["queued", "running"].includes(selected.status) && <button className="btn-danger text-xs" onClick={() => void api.cancelRecon(selected.id).then(refresh).catch((e) => setError((e as Error).message))}>Cancel run</button>}</div><div className="mt-3 space-y-2">{selected.findings.length ? selected.findings.map((finding, index) => <div className="rounded border border-slate-800 p-2 text-xs" key={`${finding.kind}-${index}`}><span className="mr-2 text-violet-300">{finding.kind}</span><span className="break-all text-slate-300">{finding.value}</span></div>) : <p className="text-sm text-slate-500">Findings will appear as the run progresses.</p>}</div>{selected.error && <p className="mt-3 text-sm text-red-300">{selected.error}</p>}</section>}
      </div>;
    }
  };

  return <div className="space-y-4">
    <section className="card">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="text-lg font-semibold">Security Center</h2><p className="mt-1 text-xs text-slate-400">Effective policy for Repeater, Intruder and the local proxy.</p></div>
        <span className={`rounded-full border px-3 py-1 text-xs ${settings.allowExternalHosts ? "border-amber-800 bg-amber-950/60 text-amber-300" : "border-teal-900 bg-teal-950/60 text-teal-300"}`}>{settings.allowExternalHosts ? "External allowlist enabled" : "Local/private targets only"}</span>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3"><div className="label">Proxy mode</div><div className="text-sm text-slate-200">{settings.proxyMode}</div></div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3"><div className="label">Intruder cap</div><div className="text-sm text-slate-200">{settings.maxIntruderRequests.toLocaleString()} requests</div></div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3"><div className="label">Request timeout</div><div className="text-sm text-slate-200">{settings.requestTimeout} ms</div></div>
        <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3"><div className="label">Response limit</div><div className="text-sm text-slate-200">{Math.round(settings.maxResponseSize / 1024 / 1024)} MB</div></div>
      </div>
    </section>
    <section className="card space-y-4">
      <div><h2 className="text-lg font-semibold">Target policy</h2><p className="mt-1 text-xs text-slate-400">One host per line. Local/private targets remain available independently from the external allowlist.</p></div>
      <div className="grid gap-4 lg:grid-cols-2">
        <label className="label">Local and private allowlist<textarea className="field mt-1 min-h-32 font-mono text-xs" value={allowedHosts} onChange={(e) => setAllowedHosts(e.target.value)} /></label>
        <label className="label">External allowlist<textarea className="field mt-1 min-h-32 font-mono text-xs" value={externalHosts} onChange={(e) => setExternalHosts(e.target.value)} placeholder="api.example.test" /></label>
      </div>
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-900/60 bg-amber-950/20 p-3">
        <input id="external-hosts" type="checkbox" checked={settings.allowExternalHosts} onChange={(e) => update({ allowExternalHosts: e.target.checked })} />
        <label htmlFor="external-hosts" className="text-sm text-amber-100">Allow external targets only when they are explicitly listed above</label>
      </div>
      <div className="rounded-lg border border-violet-900/60 bg-violet-950/20 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="font-semibold text-violet-100">Authorized Testing Mode</h3><p className="mt-1 text-xs text-violet-200/70">Every target must still match an explicit rule and every DNS answer is checked before connection.</p></div><label className="flex items-center gap-2 text-sm text-violet-100"><input type="checkbox" checked={settings.authorizedTestingMode} onChange={(e) => update({ authorizedTestingMode: e.target.checked })} /> Enable</label></div>
        <label className="label mt-4">Authorized target rules<textarea className="field mt-1 min-h-24 font-mono text-xs" value={settings.authorizedTargets.join("\n")} onChange={(e) => update({ authorizedTargets: e.target.value.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean) })} placeholder={"127.0.0.1\n10.0.0.0/8\nhttp://lab.example.test:8080"} /></label>
        <div className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {([
            ["authorizedAllowLocalhost", "localhost"],
            ["authorizedAllowLoopback", "loopback"],
            ["authorizedAllowPrivateRanges", "RFC1918 private"],
            ["authorizedAllowLinkLocal", "link-local"],
            ["authorizedAllowInternalDns", "internal DNS"],
            ["authorizedAllowIpv4", "IPv4"],
            ["authorizedAllowIpv6", "IPv6"],
            ["authorizedAllowRedirects", "HTTP/HTTPS redirects"],
            ["authorizedAllowNonStandardPorts", "non-standard ports"]
          ] as const).map(([key, label]) => <label className="flex items-center gap-2 text-xs text-slate-300" key={key}><input type="checkbox" checked={settings[key]} onChange={(e) => update({ [key]: e.target.checked })} /> {label}</label>)}
        </div>
        <label className="label mt-3 max-w-xs">Max redirects<input className="field mt-1" type="number" min={0} max={10} value={settings.maxRedirects} onChange={(e) => update({ maxRedirects: Number(e.target.value) })} /></label>
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <label className="label">Max Intruder requests<input className="field mt-1" type="number" min={1} max={1000} value={settings.maxIntruderRequests} onChange={(e) => update({ maxIntruderRequests: Number(e.target.value) })} /></label>
        <label className="label">Timeout (ms)<input className="field mt-1" type="number" min={1000} max={60000} value={settings.requestTimeout} onChange={(e) => update({ requestTimeout: Number(e.target.value) })} /></label>
        <label className="label">Proxy rate / min<input className="field mt-1" type="number" min={1} max={10000} value={settings.proxyRateLimitPerMinute} onChange={(e) => update({ proxyRateLimitPerMinute: Number(e.target.value) })} /></label>
        <label className="label">Proxy concurrency<input className="field mt-1" type="number" min={1} max={100} value={settings.proxyMaxConcurrent} onChange={(e) => update({ proxyMaxConcurrent: Number(e.target.value) })} /></label>
      </div>
      <div className="flex flex-wrap items-center gap-3"><button className="btn-primary" disabled={saving} onClick={() => void save()}>{saving ? "Saving…" : "Save policy"}</button>{message && <span className="text-sm text-teal-300">{message}</span>}{error && <span className="text-sm text-red-300">{error}</span>}</div>
    </section>
    <section className="card">
      <h2 className="text-lg font-semibold">Safety notes</h2>
      <ul className="mt-3 space-y-2 text-sm text-slate-400">
        <li>DNS answers are checked immediately before connection; mixed public/private answers are rejected.</li>
        <li>HTTPS CONNECT is a blind tunnel and is never decrypted or intercepted.</li>
        <li>External targets require explicit authorization. Do not expose the API or proxy to untrusted networks.</li>
      </ul>
    </section>
    <section className="card">
      <div className="mb-3 flex items-center justify-between"><div><h2 className="text-lg font-semibold">Policy decision log</h2><p className="text-xs text-slate-400">Recent allow/block decisions, including redirect destinations.</p></div><button className="btn-secondary text-xs" onClick={() => void api.audit().then(({ items }) => setAudit(items.slice(0, 20)))}>Refresh</button></div>
      {audit.length === 0 ? <p className="text-sm text-slate-500">No policy decisions recorded yet.</p> : <div className="space-y-2">{audit.map((item) => <div className="rounded border border-slate-800 p-2 text-xs" key={item.id}><div className="flex flex-wrap gap-2"><span className={item.action === "allow" ? "text-teal-300" : "text-red-300"}>{item.action.toUpperCase()}</span><span className="text-slate-500">{item.mode}</span><span className="text-slate-500">{new Date(item.createdAt).toLocaleString()}</span></div><div className="mt-1 break-all text-slate-300">{item.url}</div><div className="mt-1 text-slate-500">{item.reason}</div></div>)}</div>}
    </section>
  </div>;
}

function ReconWorkspace() {
  const [urls, setUrls] = useState("http://localhost:3001/api/health");
  const [runs, setRuns] = useState<ReconRun[]>([]);
  const [error, setError] = useState("");
  const refresh = () => api.reconRuns().then(({ runs: next }) => setRuns(next)).catch((e) => setError((e as Error).message));
  useEffect(() => { void refresh(); }, []);
  const create = async (mode: "passive" | "active") => {
    try {
      const targets = urls.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean);
      const result = mode === "passive" ? await api.createPassiveRecon(targets) : await api.createActiveRecon(targets, true);
      setRuns((current) => [result.run, ...current]);
    } catch (e) { setError((e as Error).message); }
  };
  return <div className="space-y-4"><section className="card space-y-4"><h2 className="text-lg font-semibold">Recon Workspace</h2><p className="text-xs text-slate-400">Passive recon uses only supplied URLs. Active checks require Authorized Testing Mode and server-side limits.</p><textarea className="field min-h-28 font-mono text-xs" value={urls} onChange={(e) => setUrls(e.target.value)} /><div className="flex gap-2"><button className="btn-secondary" onClick={() => void create("passive")}>Start passive recon</button><button className="btn-primary" onClick={() => void create("active")}>Start authorized active check</button><button className="btn-secondary" onClick={refresh}>Refresh</button></div>{error && <p className="text-sm text-red-300">{error}</p>}</section><section className="card"><h2 className="mb-3 text-lg font-semibold">Runs</h2>{runs.map((run) => <div className="mb-2 rounded border border-slate-800 p-3 text-xs" key={run.id}><div className="flex justify-between"><span className="text-teal-300">{run.mode}</span><span>{run.status}</span></div>{run.findings.map((finding, index) => <div className="mt-2 text-slate-400" key={index}>{finding.kind}: {finding.value}</div>)}{(run.status === "queued" || run.status === "running") && <button className="mt-2 text-red-300" onClick={() => void api.cancelRecon(run.id).then(refresh)}>Cancel</button>}</div>)}</section></div>;
}

function Workspace() {
  const [workspaces, setWorkspaces] = useState<ProjectWorkspace[]>([]);
  const [selected, setSelected] = useState<ProjectWorkspace>();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioManifest[]>([]);
  const [automationRuns, setAutomationRuns] = useState<AutomationRun[]>([]);
  const [name, setName] = useState(""); const [description, setDescription] = useState(""); const [error, setError] = useState("");
  const [findingTitle, setFindingTitle] = useState(""); const [findingDescription, setFindingDescription] = useState(""); const [severity, setSeverity] = useState<Finding["severity"]>("info");
  const [evidenceTitle, setEvidenceTitle] = useState(""); const [evidenceContent, setEvidenceContent] = useState("");
  const refresh = async (workspace = selected) => { const { workspaces: next } = await api.workspaces(); setWorkspaces(next); const current = workspace || next[0]; if (current) { setSelected(current); const [f, e, s, r] = await Promise.all([api.findings(current.id), api.evidence(current.id), api.scenarios(current.id), api.automationRuns(current.id)]); setFindings(f.findings); setEvidence(e.evidence); setScenarios(s.scenarios); setAutomationRuns(r.runs); } };
  useEffect(() => { void refresh().catch((e) => setError((e as Error).message)); }, []);
  const createWorkspace = async () => { try { const result = await api.createWorkspace({ name, description }); setName(""); setDescription(""); await refresh(result.workspace); } catch (e) { setError((e as Error).message); } };
  const createFinding = async () => { if (!selected) return; try { const result = await api.createFinding(selected.id, { title: findingTitle, description: findingDescription, severity }); setFindings((items) => [result.finding, ...items]); setFindingTitle(""); setFindingDescription(""); } catch (e) { setError((e as Error).message); } };
  const createEvidence = async () => { if (!selected) return; try { const result = await api.createEvidence(selected.id, { title: evidenceTitle, content: evidenceContent }); setEvidence((items) => [result.evidence, ...items]); setEvidenceTitle(""); setEvidenceContent(""); } catch (e) { setError((e as Error).message); } };
  const exportReport = async (format: "markdown" | "json" | "sarif") => { if (!selected) return; const report = await api.report(selected.id, format); const content = format === "markdown" ? report.markdown : JSON.stringify(report.report, null, 2); const blob = new Blob([content], { type: format === "markdown" ? "text/markdown" : "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `${selected.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase() || "report"}.${format === "markdown" ? "md" : format === "sarif" ? "sarif.json" : "json"}`; link.click(); URL.revokeObjectURL(link.href); };
  const createScenario = async () => { if (!selected) return; try { const result = await api.createScenario(selected.id, { name: "Metadata review (dry-run)", description: "Safe manifest; no network execution", steps: [{ action: "metadata", label: "Review workspace metadata", risk: "low" }] }); setScenarios((items) => [result.scenario, ...items]); } catch (e) { setError((e as Error).message); } };
  const runAction = async (action: (id: string) => Promise<unknown>, id: string) => { try { await action(id); await refresh(); } catch (e) { setError((e as Error).message); } };
  return <div className="space-y-4"><section className="card space-y-3"><div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">Project Workspace</h2><p className="text-xs text-slate-400">Local project context, findings, and evidence. Data is persisted as JSON on the server.</p></div>{selected && <div className="flex flex-wrap gap-2"><button className="btn-secondary" onClick={() => void exportReport("markdown")}>Markdown</button><button className="btn-secondary" onClick={() => void exportReport("json")}>JSON</button><button className="btn-secondary" onClick={() => void exportReport("sarif")}>SARIF</button></div>}</div><div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]"><input className="field" placeholder="New workspace name" value={name} onChange={(e) => setName(e.target.value)} /><input className="field" placeholder="Description (optional)" value={description} onChange={(e) => setDescription(e.target.value)} /><button className="btn-primary" onClick={() => void createWorkspace()}>Create</button></div>{workspaces.length > 0 && <select className="field" value={selected?.id || ""} onChange={(e) => void refresh(workspaces.find((item) => item.id === e.target.value))}>{workspaces.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select>}{error && <p className="text-sm text-red-300">{error}</p>}</section>{selected && <><section className="card space-y-3"><h3 className="font-semibold">New finding</h3><div className="grid gap-2 md:grid-cols-2"><input className="field" placeholder="Title" value={findingTitle} onChange={(e) => setFindingTitle(e.target.value)} /><select className="field" value={severity} onChange={(e) => setSeverity(e.target.value as Finding["severity"])}>{["info", "low", "medium", "high", "critical"].map((item) => <option key={item}>{item}</option>)}</select></div><textarea className="field min-h-20" placeholder="What did you observe?" value={findingDescription} onChange={(e) => setFindingDescription(e.target.value)} /><button className="btn-primary" onClick={() => void createFinding()}>Add finding</button><div className="space-y-2">{findings.map((item) => <article className="rounded border border-slate-800 p-3" key={item.id}><div className="flex justify-between"><strong>{item.title}</strong><span className="text-xs text-amber-300">{item.severity}</span></div><p className="mt-1 text-sm text-slate-400">{item.description}</p></article>)}</div></section><section className="card space-y-3"><h3 className="font-semibold">Evidence Vault</h3><input className="field" placeholder="Evidence title" value={evidenceTitle} onChange={(e) => setEvidenceTitle(e.target.value)} /><textarea className="field min-h-20 font-mono text-xs" placeholder="Paste notes, requests, or responses" value={evidenceContent} onChange={(e) => setEvidenceContent(e.target.value)} /><button className="btn-primary" onClick={() => void createEvidence()}>Add evidence</button><div className="space-y-2">{evidence.map((item) => <article className="rounded border border-slate-800 p-3" key={item.id}><strong>{item.title}</strong><pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap text-xs text-slate-400">{item.content}</pre></article>)}</div>  </section><section className="card space-y-3"><div className="flex items-center justify-between"><div><h3 className="font-semibold">Scenario manifests</h3><p className="text-xs text-slate-400">Approved runs execute only request/recon/metadata steps within configured bounds.</p></div><button className="btn-secondary" onClick={() => void createScenario()}>Add safe scenario</button></div>{scenarios.map((scenario) => <div className="rounded border border-slate-800 p-3 text-sm" key={scenario.id}><div className="flex justify-between"><strong>{scenario.name}</strong><span className="text-xs text-teal-300">{scenario.status}</span></div><p className="text-xs text-slate-400">{scenario.steps.length} step(s) · {scenario.risk} risk</p><div className="mt-2 flex flex-wrap gap-3"><button className="text-xs text-teal-300" onClick={() => void api.dryRunScenario(scenario.id)}>Dry-run</button>{scenario.status !== "approved" && <button className="text-xs text-amber-300" onClick={() => void api.approveScenario(scenario.id, true).then(() => refresh())}>Approve</button>}<button className="text-xs text-teal-300" onClick={async () => { try { const result = await api.createAutomationRun(scenario.id, { dryRun: true }); setAutomationRuns((runs) => [result.run, ...runs]); } catch (e) { setError((e as Error).message); } }}>Create run</button></div></div>)}<div className="mt-3 space-y-2"><h4 className="text-sm font-semibold">Automation runs</h4>{automationRuns.map((run) => <div className="rounded border border-slate-800 p-2 text-xs" key={run.id}><span className="mr-2 text-teal-300">{run.status}</span><span>steps {run.currentStep}/{run.limits.maxSteps}, requests {run.requestsExecuted}/{run.limits.maxRequests}</span><div className="mt-2 flex gap-3">{run.status === "queued" && <button className="text-teal-300" onClick={() => void runAction(api.startAutomationRun, run.id)}>Start</button>}{run.status === "running" && <button className="text-amber-300" onClick={() => void runAction(api.pauseAutomationRun, run.id)}>Pause</button>}{run.status === "paused" && <button className="text-teal-300" onClick={() => void runAction(api.resumeAutomationRun, run.id)}>Resume</button>}{["queued", "running", "paused"].includes(run.status) && <button className="text-red-300" onClick={() => void runAction(api.cancelAutomationRun, run.id)}>Cancel</button>}</div></div>)}</div></section></>}</div>;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("repeater"); const [loadedRequest, setLoadedRequest] = useState<RequestInput>();
  const [authorizedMode, setAuthorizedMode] = useState(false);
  useEffect(() => { api.settings().then(({ settings }) => setAuthorizedMode(settings.authorizedTestingMode)).catch(() => undefined); }, [tab]);
  const tabs: Array<[Tab, string]> = [["repeater", "Repeater"], ["intruder", "Intruder"], ["injection", "Injection Lab"], ["traffic", "Traffic"], ["history", "History"], ["recon", "Recon"], ["workspace", "Workspace"], ["settings", "Security Center"]];
  const loadRepeater = (request: RequestInput) => { setLoadedRequest({ ...request, headers: { ...request.headers } }); setTab("repeater"); };
  const loadIntruder = (request: RequestInput) => { setLoadedRequest({ ...request, headers: { ...request.headers } }); setTab("intruder"); };
  return <div className="min-h-screen bg-[radial-gradient(circle_at_top,#182846_0,#0a1020_48%)]"><header className="border-b border-slate-800/80 bg-slate-950/40"><div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-5"><div><div className="flex items-center gap-2"><span className="h-3 w-3 rounded-full bg-teal-300 shadow-[0_0_14px_#5eead4]" /><h1 className="text-xl font-bold tracking-tight">Local HTTP Lab</h1></div><p className="mt-1 text-xs text-slate-400">A safety-first local Repeater, Intruder, and HTTP proxy</p></div><span className={`whitespace-nowrap rounded-full border px-3 py-1 text-xs ${authorizedMode ? "border-amber-800 bg-amber-950/60 text-amber-300" : "border-teal-900 bg-teal-950/50 text-teal-300"}`}>{authorizedMode ? "Authorized Testing Mode" : "Safe Mode"}</span></div></header><main className="mx-auto max-w-7xl px-4 py-6"><nav className="mb-6 flex flex-wrap gap-1 rounded-lg border border-slate-800 bg-slate-950/40 p-1">{tabs.map(([key, label]) => <button className={`rounded-md px-4 py-2 text-sm ${tab === key ? "bg-slate-700 text-white" : "text-slate-400 hover:text-white"}`} onClick={() => setTab(key)} key={key}>{label}</button>)}</nav>{tab === "repeater" && <Repeater loadedRequest={loadedRequest} />}{tab === "intruder" && <Intruder loadedRequest={loadedRequest} />}{tab === "injection" && <InjectionLab loadedRequest={loadedRequest} onLoad={loadRepeater} onIntruder={loadIntruder} />}{tab === "traffic" && <Traffic onLoad={loadRepeater} onIntruder={loadIntruder} />}{tab === "history" && <History />}{tab === "recon" && <ReconWorkspace />}{tab === "workspace" && <Workspace />}{tab === "settings" && <SecurityCenter />}</main><footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-slate-600">Local HTTP Lab · requests are never executed through a shell</footer></div>;
}
