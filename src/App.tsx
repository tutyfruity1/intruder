import { useEffect, useMemo, useState } from "react";
import { api, type ReconRun, type ProjectWorkspace, type Finding, type Evidence, type ScenarioManifest, type AutomationRun } from "./api";
import type { HeaderPair, HistoryItem, HttpMethod, IntruderMode, PayloadDictionaries, PayloadTransform, PendingInterceptedRequest, RequestInput, ResponseData, TrafficItem, ProxyStatus } from "./types";
import { translations, type Language } from "./i18n";

type Tab = "repeater" | "intruder" | "injection" | "traffic" | "history" | "recon" | "workspace";
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

function ResponsePanel({ response, error, requestUrl, lang }: { response?: ResponseData; error?: string; requestUrl?: string; lang: Language }) {
  const t = translations[lang].repeater;
  const [view, setView] = useState<"pretty" | "raw" | "hex" | "preview">("pretty");
  const [showHeaders, setShowHeaders] = useState(false);
  if (!response && !error) return <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">{t.noResponse}</div>;
  if (error) return <pre className="max-h-[28rem] overflow-auto rounded-lg border border-red-900/70 bg-red-950/40 p-4 text-sm text-red-200 whitespace-pre-wrap">{error}</pre>;
  const contentType = Object.entries(response!.headers).find(([key]) => key.toLowerCase() === "content-type")?.[1]?.toLowerCase() || "";
  const isHtml = contentType.includes("text/html") || /^\s*<!doctype html|^\s*<html[\s>]/i.test(response!.body);
  const looksLikeJson = /^\s*(?:\{[\s\S]*\}|\[[\s\S]*\])\s*$/.test(response!.body);
  const isJson = contentType.includes("application/json") || contentType.includes("+json") || looksLikeJson;
  const isXml = contentType.includes("xml") || /^\s*<\?xml[\s>]/i.test(response!.body);
  const body = view === "pretty" ? pretty(response!.body) : view === "hex" ? Array.from(new TextEncoder().encode(response!.body)).map((byte) => byte.toString(16).padStart(2, "0")).join(" ") : response!.body;

  const viewLabels: Record<string, string> = {
    pretty: t.pretty,
    raw: t.raw,
    hex: t.hex,
    preview: t.preview
  };

  return <div className="overflow-hidden rounded-lg border border-slate-800">
    <div className="flex items-center gap-3 border-b border-slate-800 bg-slate-950/60 px-3 py-2 text-xs"><span className={response!.status < 400 ? "text-teal-300" : "text-red-300"}>{response!.status} {response!.statusText}</span><span className="text-slate-500">{response!.durationMs} ms</span>{response!.truncated && <span className="text-warn">body truncated</span>}</div>
    <div className="flex gap-1 border-b border-slate-800 px-2 py-1">{(["pretty", "raw", "hex", "preview"] as const).map((item) => <button className={`rounded px-2 py-1 text-xs ${view === item ? "bg-slate-700 text-white" : "text-slate-500 hover:text-slate-200"}`} onClick={() => setView(item)} key={item}>{viewLabels[item]}</button>)}</div>
    <button className="flex w-full items-center justify-between border-b border-slate-800 px-4 py-2 text-left text-xs text-slate-400 hover:text-slate-200" onClick={() => setShowHeaders((open) => !open)}><span>{t.responseHeaders}: {Object.keys(response!.headers).length}</span><span>{showHeaders ? t.hide : t.show}</span></button>
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

function SimpleRequestEditor({ value, onChange, onSend, loading, lang }: { value: RequestInput; onChange: (v: RequestInput) => void; onSend: () => void; loading: boolean; lang: Language }) {
  const t = translations[lang].repeater;
  const [rawText, setRawText] = useState(() => requestToRaw(value));
  useEffect(() => setRawText(requestToRaw(value)), [value.method, value.url, value.body, JSON.stringify(value.headers)]);
  const updateRaw = (text: string) => {
    setRawText(text);
    const parsed = parseRawRequest(text);
    if (parsed) onChange(parsed);
  };
  return <div className="space-y-3">
    <div className="flex items-center justify-between border-b border-slate-800 pb-2"><span className="text-xs text-slate-500">{t.hint}</span><button className="btn-primary px-4 py-1 text-xs" disabled={loading} onClick={onSend}>{loading ? t.sending : t.send}</button></div>
    <textarea className="field min-h-[32rem] w-full resize-y font-mono text-xs leading-5" value={rawText} onChange={(event) => updateRaw(event.target.value)} spellCheck={false} />
    <p className="text-xs text-slate-500">Use <code>METHOD URL HTTP/1.1</code>, headers, an empty line, then the body.</p>
  </div>;
}

function RequestEditor({ value, onChange, onSend, loading, lang }: { value: RequestInput; onChange: (v: RequestInput) => void; onSend: () => void; loading: boolean; lang: Language }) {
  const t = translations[lang].repeater;
  const [view, setView] = useState<"structured" | "raw">("structured");
  const [rawText, setRawText] = useState("");
  const [pairs, setPairs] = useState<HeaderPair[]>(Object.entries(value.headers).map(([key, val]) => ({ key, value: val })) || [blankPair()]);
  const [queryPairs, setQueryPairs] = useState<HeaderPair[]>(queryPairsFromUrl(value.url));
  const [cookiePairs, setCookiePairs] = useState<HeaderPair[]>(cookiePairsFromHeaders(value.headers));
  useEffect(() => setPairs(Object.entries(value.headers).map(([key, val]) => ({ key, value: val })).concat(Object.keys(value.headers).length ? [] : [blankPair()])), [value.headers]);
  useEffect(() => setQueryPairs(queryPairsFromUrl(value.url)), [value.url]);
  useEffect(() => setCookiePairs(cookiePairsFromHeaders(value.headers)), [value.headers]);
  const update = (patch: Partial<RequestInput>) => onChange({ ...value, ...patch });
  const raw = requestToRaw(value);
  useEffect(() => { if (view === "structured") setRawText(raw); }, [raw, view]);
  const parseRaw = (text: string) => {
    const parsed = parseRawRequest(text);
    if (parsed) onChange(parsed);
  };
  return <div className="space-y-4">
    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
      <div className="flex gap-1">
        <button className={`rounded px-2 py-1 text-xs ${view === "structured" ? "bg-slate-700 text-white" : "text-slate-500"}`} onClick={() => setView("structured")}>Structured</button>
        <button className={`rounded px-2 py-1 text-xs ${view === "raw" ? "bg-slate-700 text-white" : "text-slate-500"}`} onClick={() => { setRawText(raw); setView("raw"); }}>Raw</button>
      </div>
      <div className="flex items-center gap-2">
        <button className="btn-primary px-3 py-1 text-xs" disabled={loading} onClick={onSend}>{loading ? t.sending : t.send}</button>
      </div>
    </div>
    {view === "raw" ? (
      <textarea className="field min-h-[26rem] w-full font-mono text-xs leading-5" value={rawText || raw} onChange={(event) => { setRawText(event.target.value); parseRaw(event.target.value); }} spellCheck={false} />
    ) : (
      <>
        <div className="grid grid-cols-[110px_1fr_auto] gap-2">
          <select className="field method-select appearance-none border-emerald-400 bg-emerald-950/50 text-emerald-100 focus:border-emerald-300 focus:ring-emerald-300" value={value.method} onChange={(e) => update({ method: e.target.value as HttpMethod })}>{methods.map((m) => <option key={m}>{m}</option>)}</select>
          <input className="field" value={value.url} onChange={(e) => update({ url: e.target.value })} placeholder="https://example.com/api/data" />
          <button className="btn-primary min-w-20" disabled={loading} onClick={onSend}>{loading ? t.sending : t.send}</button>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between"><span className="label mb-0">{t.queryParameters}</span><button className="text-xs text-teal-300" onClick={() => setQueryPairs([...queryPairs, blankPair()])}>{t.add}</button></div>
          <div className="space-y-2">{queryPairs.map((pair, i) => <div className="grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><input className="field" placeholder={t.paramName} value={pair.key} onChange={(e) => { const next = [...queryPairs]; next[i] = { ...pair, key: e.target.value }; setQueryPairs(next); update({ url: urlWithQueryPairs(value.url, next) }); }} /><input className="field" placeholder={t.paramValue} value={pair.value} onChange={(e) => { const next = [...queryPairs]; next[i] = { ...pair, value: e.target.value }; setQueryPairs(next); update({ url: urlWithQueryPairs(value.url, next) }); }} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => { const next = queryPairs.filter((_, j) => i !== j); setQueryPairs(next); update({ url: urlWithQueryPairs(value.url, next) }); }}>×</button></div>)}</div>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between"><span className="label mb-0">{t.headers}</span><button className="text-xs text-teal-300" onClick={() => setPairs([...pairs, blankPair()])}>{t.add}</button></div>
          <div className="space-y-2">{pairs.map((pair, i) => <div className="grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><input className="field" placeholder={t.headerName} value={pair.key} onChange={(e) => { const next = [...pairs]; next[i] = { ...pair, key: e.target.value }; setPairs(next); update({ headers: pairsToHeaders(next) }); }} /><input className="field" placeholder={t.headerValue} value={pair.value} onChange={(e) => { const next = [...pairs]; next[i] = { ...pair, value: e.target.value }; setPairs(next); update({ headers: pairsToHeaders(next) }); }} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => { const next = pairs.filter((_, j) => i !== j); setPairs(next); update({ headers: pairsToHeaders(next) }); }}>×</button></div>)}</div>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between"><span className="label mb-0">{t.cookies}</span><button className="text-xs text-teal-300" onClick={() => setCookiePairs([...cookiePairs, blankPair()])}>{t.add}</button></div>
          <div className="space-y-2">{cookiePairs.map((pair, i) => <div className="grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><input className="field" placeholder={t.cookieName} value={pair.key} onChange={(e) => { const next = [...cookiePairs]; next[i] = { ...pair, key: e.target.value }; setCookiePairs(next); update({ headers: headersWithCookies(value.headers, next) }); }} /><input className="field" placeholder={t.cookieValue} value={pair.value} onChange={(e) => { const next = [...cookiePairs]; next[i] = { ...pair, value: e.target.value }; setCookiePairs(next); update({ headers: headersWithCookies(value.headers, next) }); }} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => { const next = cookiePairs.filter((_, j) => i !== j); setCookiePairs(next); update({ headers: headersWithCookies(value.headers, next) }); }}>×</button></div>)}</div>
        </div>
        <div>
          <div className="mb-1 flex items-center justify-between">
            <label className="label mb-0">{t.body}</label>
            <button className="text-xs text-teal-300" onClick={() => { try { if (value.body) update({ body: JSON.stringify(JSON.parse(value.body), null, 2) }); } catch {} }}>Format JSON</button>
          </div>
          <textarea className="field min-h-32 font-mono text-xs" value={value.body || ""} onChange={(e) => update({ body: e.target.value })} placeholder='{"hello":"world"}' />
        </div>
      </>
    )}
  </div>;
}

function Repeater({ loadedRequest, lang }: { loadedRequest?: RequestInput; lang: Language }) {
  const t = translations[lang].repeater;
  const [request, setRequest] = useState<RequestInput>(loadedRequest || { method: "GET", url: "http://localhost:3001/api/health", headers: {} });
  const [response, setResponse] = useState<ResponseData>(); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  useEffect(() => { if (loadedRequest) { setRequest(loadedRequest); setResponse(undefined); setError(""); } }, [loadedRequest]);
  useEffect(() => { const handler = (event: KeyboardEvent) => { if ((event.ctrlKey || event.metaKey) && event.key === "Enter") { event.preventDefault(); void send(); } }; window.addEventListener("keydown", handler); return () => window.removeEventListener("keydown", handler); });
  const send = async () => { setLoading(true); setError(""); setResponse(undefined); try { setResponse((await api.request(request)).response); } catch (e) { setError((e as Error).message); } finally { setLoading(false); } };
  return <div className="grid gap-4 lg:grid-cols-2"><section className="card"><h2 className="mb-4 text-lg font-semibold">{t.httpRequest}</h2><RequestEditor value={request} onChange={setRequest} onSend={send} loading={loading} lang={lang} /></section><section className="card"><h2 className="mb-4 text-lg font-semibold">{t.response}</h2><ResponsePanel response={response} error={error} requestUrl={request.url} lang={lang} /></section></div>;
}

function InterceptionPanel({ onLoad, onIntruder, lang }: { onLoad: (request: RequestInput) => void; onIntruder: (request: RequestInput) => void; lang: Language }) {
  const t = translations[lang].traffic;
  const [enabled, setEnabled] = useState(false); const [pending, setPending] = useState<PendingInterceptedRequest[]>([]); const [edits, setEdits] = useState<Record<string, RequestInput>>({}); const [error, setError] = useState("");
  const refresh = async () => { try { const [state, list] = await Promise.all([api.interceptionStatus(), api.pendingInterceptions()]); setEnabled(state.interception.enabled); setPending(list.items); setEdits((old) => Object.fromEntries(list.items.map((item) => [item.id, old[item.id] || item.request]))); setError(""); } catch (e) { setError((e as Error).message); } };
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 1000); return () => window.clearInterval(timer); }, []);
  const action = async (id: string, kind: "continue" | "drop") => { try { if (kind === "continue") await api.continueInterception(id, edits[id]); else await api.dropInterception(id); await refresh(); } catch (e) { setError((e as Error).message); } };
  return <section className="card"><div className="flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-lg font-semibold">{t.interceptTitle}</h2><p className="mt-1 text-xs text-slate-400">{t.interceptSubtitle}</p></div><div className="flex items-center gap-2"><span className={`rounded-full px-3 py-1 text-xs ${enabled ? "bg-amber-950 text-amber-300" : "bg-slate-800 text-slate-400"}`}>{enabled ? `${pending.length} ${t.pending}` : t.disabled}</span><button className={enabled ? "btn-danger" : "btn-primary"} onClick={() => void api.toggleInterception(!enabled).then(refresh).catch((e) => setError((e as Error).message))}>{enabled ? t.disableIntercept : t.enableIntercept}</button></div></div>{error && <p className="mt-2 text-sm text-red-300">{error}</p>}{enabled && (pending.length ? <div className="mt-4 space-y-3">{pending.map((item) => <details className="rounded-lg border border-amber-900/60 p-3" key={item.id} open><summary className="cursor-pointer text-sm"><span className="mr-3 text-amber-300">{item.request.method}</span><span className="text-slate-300">{item.request.url}</span><span className="float-right text-xs text-slate-500">{t.expires} {new Date(item.expiresAt).toLocaleTimeString()}</span></summary><div className="mt-3"><SimpleRequestEditor value={edits[item.id] || item.request} onChange={(request) => setEdits((old) => ({ ...old, [item.id]: request }))} onSend={() => undefined} loading={false} lang={lang} /><div className="mt-3 flex flex-wrap gap-2"><button className="btn-primary" onClick={() => void action(item.id, "continue")}>{t.continueAndForward}</button><button className="btn-secondary" onClick={() => onLoad(edits[item.id] || item.request)}>{t.sendToRepeater}</button><button className="btn-secondary" onClick={() => onIntruder(edits[item.id] || item.request)}>{t.sendToIntruder}</button><button className="btn-danger" onClick={() => void action(item.id, "drop")}>{t.drop}</button></div></div></details>)}</div> : <p className="mt-4 text-sm text-slate-500">{t.noPendingRequests}</p>)}</section>;
}

function Traffic({ onLoad, onIntruder, lang }: { onLoad: (request: RequestInput) => void; onIntruder: (request: RequestInput) => void; lang: Language }) {
  const t = translations[lang].traffic;
  const [status, setStatus] = useState<ProxyStatus>(); const [port, setPort] = useState(3002);
  const [items, setItems] = useState<TrafficItem[]>([]); const [selected, setSelected] = useState<TrafficItem>(); const [edited, setEdited] = useState<RequestInput>(); const [query, setQuery] = useState(""); const [error, setError] = useState("");
  const refresh = async () => { try { const [state, traffic] = await Promise.all([api.proxyStatus(), api.traffic(query)]); setStatus(state.proxy); setPort(state.proxy.port); setItems(traffic.items); setError(""); } catch (e) { setError((e as Error).message); } };
  useEffect(() => { void refresh(); }, []);
  useEffect(() => { const timer = window.setInterval(() => void refresh(), 3000); return () => window.clearInterval(timer); }, [query]);
  const toggle = async () => { try { if (status?.running) await api.stopProxy(); else await api.startProxy(port); await refresh(); } catch (e) { setError((e as Error).message); } };
  return <div className="space-y-4">
    <InterceptionPanel onLoad={onLoad} onIntruder={onIntruder} lang={lang} />
    <section className="card"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">{t.proxyTitle}</h2><p className="mt-1 text-xs text-slate-400">{t.proxySubtitle}</p></div><span className={`rounded-full px-3 py-1 text-xs ${status?.running ? "bg-teal-950 text-teal-300" : "bg-slate-800 text-slate-400"}`}>{status?.running ? `${t.runningOn} ${status.host}:${status.port}` : t.stopped}</span></div><div className="mt-4 flex flex-wrap items-end gap-2"><label className="label mb-0 w-40">{t.proxyPort}<input className="field mt-1" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(Number(e.target.value))} /></label><button className={status?.running ? "btn-danger" : "btn-primary"} onClick={() => void toggle()}>{status?.running ? t.stopProxy : t.startProxy}</button><a href="/api/proxy/ca.crt" download="local-http-lab-ca.crt" className="btn-secondary text-xs inline-flex items-center gap-1 py-2 px-3">📥 {t.downloadCaCert}</a></div><p className="mt-3 text-xs text-slate-500">{t.proxyHint} <code>127.0.0.1:{status?.port || port}</code>. {t.downloadCaCertSubtitle}</p>{error && <p className="mt-2 text-sm text-red-300">{error}</p>}</section>
    <section className="card"><div className="mb-4 flex flex-wrap items-center justify-between gap-2"><div><h2 className="text-lg font-semibold">{t.capturedTraffic}</h2><p className="text-xs text-slate-400">{t.capturedSubtitle}</p></div><div className="flex gap-2"><input className="field w-64" placeholder={t.searchPlaceholder} value={query} onChange={(e) => setQuery(e.target.value)} /><button className="btn-danger" onClick={() => api.clearTraffic().then(refresh)}>{t.clear}</button></div></div>{items.length === 0 ? <p className="py-12 text-center text-sm text-slate-500">{t.noProxiedRequests}</p> : <div className="space-y-2">{items.map((item) => <details className="rounded-lg border border-slate-800 p-3" key={item.id} onClick={() => { setSelected(item); setEdited({ ...item.request, headers: { ...item.request.headers } }); }}><summary className="cursor-pointer text-sm"><span className={`mr-3 ${item.kind === "https-tunnel" ? "text-violet-300" : "text-teal-300"}`}>{item.kind === "https-tunnel" ? "HTTPS TUNNEL" : item.request.method}</span><span className="text-slate-300">{item.request.url}</span><span className={`float-right text-xs ${item.error ? "text-red-300" : "text-slate-500"}`}>{item.kind === "https-tunnel" ? `${item.tunnel?.connected ? "connected" : "blocked"} · ${item.tunnel?.bytesSent || 0}↑ ${item.tunnel?.bytesReceived || 0}↓` : item.interceptionStatus ? `${item.interceptionStatus}${item.error ? ` · ${item.error}` : ""}` : item.error || `${item.response?.status} · ${item.response?.durationMs} ms`}</span></summary><div className="mt-3 grid gap-3 lg:grid-cols-2"><div><h3 className="label">{item.kind === "https-tunnel" ? t.tunnelMetadata : t.requestLabel}</h3><pre className="max-h-56 overflow-auto rounded border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400 whitespace-pre-wrap">{item.kind === "https-tunnel" ? JSON.stringify(item.tunnel, null, 2) : requestToRaw(item.request)}</pre></div><div><h3 className="label">{item.kind === "https-tunnel" ? t.statusLabel : t.responseLabel}</h3><pre className="max-h-56 overflow-auto rounded border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400 whitespace-pre-wrap">{item.kind === "https-tunnel" ? "HTTPS CONNECT is not intercepted or decrypted." : item.error || pretty(item.response?.body || "")}</pre></div></div>{item.kind !== "https-tunnel" && <div className="mt-3 flex flex-wrap gap-2"><button className="btn-secondary text-xs" onClick={(event) => { event.preventDefault(); onLoad(item.request); }}>{t.sendToRepeater}</button><button className="btn-secondary text-xs" onClick={(event) => { event.preventDefault(); onIntruder(item.request); }}>{t.sendToIntruder}</button><button className="text-xs text-red-300" onClick={(event) => { event.preventDefault(); void api.deleteTraffic(item.id).then(refresh); }}>{t.deleteLabel}</button></div>}</details>)}</div>}</section>
    {selected && edited && <section className="card"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-lg font-semibold">{t.requestEditor}</h2><p className="text-xs text-slate-400">{t.requestEditorSubtitle}</p></div><button className="text-xs text-slate-400 hover:text-white" onClick={() => { setSelected(undefined); setEdited(undefined); }}>{t.close}</button></div><SimpleRequestEditor value={edited} onChange={setEdited} onSend={() => onLoad(edited)} loading={false} lang={lang} /><div className="mt-4 flex gap-2"><button className="btn-primary" onClick={() => onLoad(edited)}>{t.loadEditedIntoRepeater}</button><button className="btn-secondary" onClick={() => setEdited({ ...selected.request, headers: { ...selected.request.headers } })}>{t.resetChanges}</button></div></section>}
  </div>;
}

function Intruder({ loadedRequest, lang }: { loadedRequest?: RequestInput; lang: Language }) {
  const t = translations[lang].intruder;
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
  return <div className="space-y-4"><div className="grid gap-4 lg:grid-cols-[1.1fr_.9fr]"><section className="card space-y-4"><div><h2 className="text-lg font-semibold">{t.title}</h2><p className="mt-1 text-xs text-slate-400">{t.subtitle}</p></div><div><label className="label">{t.modeLabel}</label><select className="field tool-select" value={mode} onChange={(e) => { setMode(e.target.value as IntruderMode); setResults([]); setGenerated([]); }}><option value="sniper">{t.modes.sniper}</option><option value="batteringRam">{t.modes.batteringRam}</option><option value="pitchfork">{t.modes.pitchfork}</option><option value="clusterBomb">{t.modes.clusterBomb}</option></select></div><SimpleRequestEditor value={base} onChange={setBase} onSend={() => void run(true)} loading={loading} lang={lang} /><div><div className="mb-1 flex items-center justify-between"><label className="label mb-0">{t.payloadDictionary}</label><label className="btn-secondary cursor-pointer text-xs">{t.addDictionaryFile}<input className="hidden" type="file" accept=".txt,.csv,text/plain,text/csv" onChange={(event) => { const file = event.target.files?.[0]; if (file) void loadDictionary(file); event.currentTarget.value = ""; }} /></label></div><textarea className="field min-h-24 font-mono text-xs" value={payloads} onChange={(e) => { setPayloads(e.target.value); setDictionaryName(""); }} />{dictionaryName && <p className="mt-1 text-xs text-teal-300">{dictionaryName}</p>}<p className="mt-1 text-xs text-slate-500">{t.dictionaryHint}</p></div>{(mode === "pitchfork" || mode === "clusterBomb") && markerNames.length > 1 && <div><label className="label">{t.perMarkerDictionaries}</label><div className="space-y-2">{markerNames.map((name) => <textarea key={name} className="field min-h-16 font-mono text-xs" placeholder={`${name}: one value per line`} value={dictionaryTexts[name] || ""} onChange={(e) => setDictionaryTexts((old) => ({ ...old, [name]: e.target.value }))} />)}</div><p className="mt-1 text-xs text-slate-500">{t.perMarkerHint}</p></div>}<div><div className="mb-1 flex items-center justify-between"><label className="label mb-0">{t.payloadTransformations}</label><button className="text-xs text-teal-300" onClick={() => setTransforms([...transforms, { operation: "urlEncode" }])}>{t.addStep}</button></div>{transforms.map((transform, i) => <div className="mb-2 grid grid-cols-[1fr_1fr_auto] gap-2" key={i}><select className="field" value={transform.operation} onChange={(e) => { const next = [...transforms]; next[i] = { ...transform, operation: e.target.value as PayloadTransform["operation"] }; setTransforms(next); }} >{transformNames.map(([operation, label]) => <option value={operation} key={operation}>{label}</option>)}</select><input className="field" placeholder={t.prefixSuffix} value={transform.value || ""} onChange={(e) => { const next = [...transforms]; next[i] = { ...transform, value: e.target.value }; setTransforms(next); }} disabled={!["prepend", "append"].includes(transform.operation)} /><button className="px-2 text-slate-500 hover:text-red-300" onClick={() => setTransforms(transforms.filter((_, j) => i !== j))}>×</button></div>)}<p className="text-xs text-slate-500">{t.transformHint}</p>{transforms.length > 0 && <div className="mt-2 space-y-1 text-xs"><div className="text-slate-400">{t.previewTitle}</div>{payloadList.slice(0, 20).map((payload) => <div className="grid grid-cols-2 gap-2" key={payload}><code className="truncate text-slate-500">{payload}</code><code className="truncate text-teal-300">{transforms.reduce((current, transform) => previewTransform(current, transform), payload)}</code></div>)}</div>}</div><div className="grid grid-cols-2 gap-2"><label className="label">{t.concurrency}<input className="field mt-1" type="number" min={1} max={10} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} /></label><label className="label">{t.delayMs}<input className="field mt-1" type="number" min={0} max={10000} value={delay} onChange={(e) => setDelay(Number(e.target.value))} /></label></div>  <div className="rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-400">{t.budgetLabel} <span className="text-slate-200">{generated.length || t.previewRequired}</span> {t.candidates} · {concurrency} {t.concurrent} · {delay} ms.</div><div className="flex gap-2"><button className="btn-secondary" disabled={loading} onClick={() => void run(false)}>{t.previewRequests}</button><button className="btn-primary" disabled={loading} onClick={() => void run(true)}>{t.runIntruder}</button></div>{error && <p className="text-sm text-red-300">{error}</p>}</section>  <section className="card"><div className="mb-4 flex items-center justify-between"><h2 className="text-lg font-semibold">{results.length ? `${t.resultsTitle} · ${visibleResults.length}/${results.length}` : t.previewOnlyTitle}</h2>{results.length > 0 && <select className="field w-32" value={resultFilter} onChange={(e) => setResultFilter(e.target.value as typeof resultFilter)}><option value="all">{t.allResults}</option><option value="success">{t.responses}</option><option value="error">{t.errors}</option></select>}</div>{results.length ? <div className="max-h-[38rem] space-y-2 overflow-auto">{visibleResults.map((r, i) => <div className="rounded-lg border border-slate-800 p-3 text-xs" key={i}><div className="flex justify-between"><span className="truncate text-slate-400">{r.request.url}</span><span className={r.error ? "text-red-300" : "text-teal-300"}>{r.error || `${r.response?.status} · ${r.response?.durationMs} ms`}</span></div></div>)}</div> : generated.length ? <div className="max-h-[38rem] space-y-2 overflow-auto">{generated.map((r, i) => <pre className="overflow-auto rounded-lg border border-slate-800 p-3 text-xs text-slate-400" key={i}>{i + 1}. {r.method} {r.url}</pre>)}</div> : <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">{t.safePreviewHint}</div>}</section></div></div>;
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

function InjectionLab({ loadedRequest, onLoad, onIntruder, lang }: { loadedRequest?: RequestInput; onLoad: (request: RequestInput) => void; onIntruder: (request: RequestInput) => void; lang: Language }) {
  const t = translations[lang].injection;
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
    <section className="card space-y-4"><div><h2 className="text-lg font-semibold">{t.title}</h2><p className="mt-1 text-xs text-slate-400">{t.subtitle}</p></div>
      <div className="grid gap-2 sm:grid-cols-2"><label className="label">{t.familyLabel}<select className="field mt-1" value={category} onChange={(e) => { setCategory(e.target.value as InjectionCategory); setProbeIndex(0); }}><option value="sql">{t.families.sql}</option><option value="xss">{t.families.xss}</option><option value="template">{t.families.template}</option><option value="path">{t.families.path}</option><option value="header">{t.families.header}</option></select></label><label className="label">{t.probeLabel}<select className="field mt-1" value={probeIndex} onChange={(e) => setProbeIndex(Number(e.target.value))}>{injectionProbes[category].map((item, index) => <option value={index} key={item.name}>{item.name}</option>)}</select></label></div>
      <div className="rounded border border-slate-800 bg-slate-950/50 p-3 text-xs"><div className="text-slate-400">{t.probeText}</div><code className="mt-1 block break-all text-amber-300">{probe.value}</code><p className="mt-2 text-slate-500">{probe.purpose}</p><button className="btn-secondary mt-3 text-xs" onClick={applyProbe}>{t.insertProbe}</button></div>
      <SimpleRequestEditor value={request} onChange={setRequest} onSend={send} loading={loading} lang={lang} />
      <div className="flex flex-wrap gap-2"><button className="btn-secondary" onClick={() => onLoad(request)}>{t.sendToRepeater}</button><button className="btn-secondary" onClick={() => onIntruder(request)}>{t.sendToIntruder}</button></div>
    </section>
    <section className="card"><h2 className="mb-4 text-lg font-semibold">{t.resultTitle}</h2>{error ? <pre className="rounded border border-red-900/70 bg-red-950/40 p-4 text-sm text-red-200 whitespace-pre-wrap">{error}</pre> : result ? <ResponsePanel response={result} requestUrl={request.url} lang={lang} /> : <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-sm text-slate-500">{t.noProbeSent}</div>}</section>
  </div>;
}

function History({ lang }: { lang: Language }) {
  const t = translations[lang].history;
  const [items, setItems] = useState<HistoryItem[]>([]); const [error, setError] = useState("");
  const refresh = () => api.history().then((d) => setItems(d.items)).catch((e) => setError((e as Error).message));
  useEffect(() => { refresh(); }, []);
  return <section className="card"><div className="mb-4 flex items-center justify-between"><div><h2 className="text-lg font-semibold">{t.title}</h2><p className="text-xs text-slate-400">{t.subtitle}</p></div><button className="btn-danger" onClick={() => api.clearHistory().then(refresh)}>{t.clearHistory}</button></div>{error && <p className="text-red-300">{error}</p>}{items.length === 0 ? <p className="py-12 text-center text-sm text-slate-500">{t.noRequests}</p> : <div className="space-y-2">{items.map((item) => <details className="rounded-lg border border-slate-800 p-3" key={item.id}><summary className="cursor-pointer text-sm"><span className="mr-3 text-teal-300">{item.request.method}</span><span className="text-slate-300">{item.request.url}</span><span className="float-right text-xs text-slate-500">{new Date(item.createdAt).toLocaleString()}</span></summary><pre className="mt-3 max-h-48 overflow-auto text-xs text-slate-400">{item.error || pretty(item.response?.body || "")}</pre></details>)}</div>}</section>;
}

function ReconWorkspace({ lang }: { lang: Language }) {
  const t = translations[lang].recon;
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
  return <div className="space-y-4"><section className="card space-y-4"><h2 className="text-lg font-semibold">{t.title}</h2><p className="text-xs text-slate-400">{t.subtitle}</p><textarea className="field min-h-28 font-mono text-xs" value={urls} onChange={(e) => setUrls(e.target.value)} /><div className="flex gap-2"><button className="btn-secondary" onClick={() => void create("passive")}>{t.startPassive}</button><button className="btn-primary" onClick={() => void create("active")}>{t.startActive}</button><button className="btn-secondary" onClick={refresh}>{t.refresh}</button></div>{error && <p className="text-sm text-red-300">{error}</p>}</section><section className="card"><h2 className="mb-3 text-lg font-semibold">{t.runsTitle}</h2>{runs.length === 0 ? <p className="py-8 text-center text-sm text-slate-500">{t.noRuns}</p> : runs.map((run) => <div className="mb-2 rounded border border-slate-800 p-3 text-xs" key={run.id}><div className="flex justify-between"><span className="text-teal-300">{run.mode}</span><span>{run.status}</span></div>{run.findings.map((finding, index) => <div className="mt-2 text-slate-400" key={index}>{finding.kind}: {finding.value}</div>)}{(run.status === "queued" || run.status === "running") && <button className="mt-2 text-red-300" onClick={() => void api.cancelRecon(run.id).then(refresh)}>{t.cancelRun}</button>}</div>)}</section></div>;
}

function Workspace({ lang }: { lang: Language }) {
  const t = translations[lang].workspace;
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
  return <div className="space-y-4"><section className="card space-y-3"><div className="flex items-center justify-between"><div><h2 className="text-lg font-semibold">{t.title}</h2><p className="text-xs text-slate-400">{t.subtitle}</p></div>{selected && <div className="flex flex-wrap gap-2"><button className="btn-secondary" onClick={() => void exportReport("markdown")}>{t.markdown}</button><button className="btn-secondary" onClick={() => void exportReport("json")}>{t.json}</button><button className="btn-secondary" onClick={() => void exportReport("sarif")}>{t.sarif}</button></div>}</div><div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]"><input className="field" placeholder={t.newWorkspaceName} value={name} onChange={(e) => setName(e.target.value)} /><input className="field" placeholder={t.descriptionOptional} value={description} onChange={(e) => setDescription(e.target.value)} /><button className="btn-primary" onClick={() => void createWorkspace()}>{t.create}</button></div>{workspaces.length > 0 && <select className="field" value={selected?.id || ""} onChange={(e) => void refresh(workspaces.find((item) => item.id === e.target.value))}>{workspaces.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select>}{error && <p className="text-sm text-red-300">{error}</p>}</section>{selected && <><section className="card space-y-3"><h3 className="font-semibold">{t.newFinding}</h3><div className="grid gap-2 md:grid-cols-2"><input className="field" placeholder={t.titleLabel} value={findingTitle} onChange={(e) => setFindingTitle(e.target.value)} /><select className="field" value={severity} onChange={(e) => setSeverity(e.target.value as Finding["severity"])}>{["info", "low", "medium", "high", "critical"].map((item) => <option key={item}>{item}</option>)}</select></div><textarea className="field min-h-20" placeholder={t.whatObserved} value={findingDescription} onChange={(e) => setFindingDescription(e.target.value)} /><button className="btn-primary" onClick={() => void createFinding()}>{t.addFinding}</button><div className="space-y-2">{findings.map((item) => <article className="rounded border border-slate-800 p-3" key={item.id}><div className="flex justify-between"><strong>{item.title}</strong><span className="text-xs text-amber-300">{item.severity}</span></div><p className="mt-1 text-sm text-slate-400">{item.description}</p></article>)}</div></section><section className="card space-y-3"><h3 className="font-semibold">{t.evidenceVault}</h3><input className="field" placeholder={t.evidenceTitle} value={evidenceTitle} onChange={(e) => setEvidenceTitle(e.target.value)} /><textarea className="field min-h-20 font-mono text-xs" placeholder={t.evidenceContent} value={evidenceContent} onChange={(e) => setEvidenceContent(e.target.value)} /><button className="btn-primary" onClick={() => void createEvidence()}>{t.addEvidence}</button><div className="space-y-2">{evidence.map((item) => <article className="rounded border border-slate-800 p-3" key={item.id}><strong>{item.title}</strong><pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap text-xs text-slate-400">{item.content}</pre></article>)}</div>  </section><section className="card space-y-3"><div className="flex items-center justify-between"><div><h3 className="font-semibold">{t.scenarioManifests}</h3><p className="text-xs text-slate-400">Approved runs execute only request/recon/metadata steps within configured bounds.</p></div><button className="btn-secondary" onClick={() => void createScenario()}>{t.addSafeScenario}</button></div>{scenarios.map((scenario) => <div className="rounded border border-slate-800 p-3 text-sm" key={scenario.id}><div className="flex justify-between"><strong>{scenario.name}</strong><span className="text-xs text-teal-300">{scenario.status}</span></div><p className="text-xs text-slate-400">{scenario.steps.length} {t.stepCount} · {scenario.risk} risk</p><div className="mt-2 flex flex-wrap gap-3"><button className="text-xs text-teal-300" onClick={() => void api.dryRunScenario(scenario.id)}>{t.dryRun}</button>{scenario.status !== "approved" && <button className="text-xs text-amber-300" onClick={() => void api.approveScenario(scenario.id, true).then(() => refresh())}>{t.approve}</button>}<button className="text-xs text-teal-300" onClick={async () => { try { const result = await api.createAutomationRun(scenario.id, { dryRun: true }); setAutomationRuns((runs) => [result.run, ...runs]); } catch (e) { setError((e as Error).message); } }}>{t.createRun}</button></div></div>)}<div className="mt-3 space-y-2"><h4 className="text-sm font-semibold">{t.automationRuns}</h4>{automationRuns.map((run) => <div className="rounded border border-slate-800 p-2 text-xs" key={run.id}><span className="mr-2 text-teal-300">{run.status}</span><span>steps {run.currentStep}/{run.limits.maxSteps}, requests {run.requestsExecuted}/{run.limits.maxRequests}</span><div className="mt-2 flex gap-3">{run.status === "queued" && <button className="text-teal-300" onClick={() => void runAction(api.startAutomationRun, run.id)}>{t.start}</button>}{run.status === "running" && <button className="text-amber-300" onClick={() => void runAction(api.pauseAutomationRun, run.id)}>{t.pause}</button>}{run.status === "paused" && <button className="text-teal-300" onClick={() => void runAction(api.resumeAutomationRun, run.id)}>{t.resume}</button>}{["queued", "running", "paused"].includes(run.status) && <button className="text-red-300" onClick={() => void runAction(api.cancelAutomationRun, run.id)}>{t.cancel}</button>}</div></div>)}</div></section></>}</div>;
}

export default function App() {
  const [lang, setLang] = useState<Language>(() => {
    const saved = localStorage.getItem("lang");
    return (saved === "uk" || saved === "en") ? saved : "en";
  });
  const [tab, setTab] = useState<Tab>("repeater"); const [loadedRequest, setLoadedRequest] = useState<RequestInput>();

  const handleSetLang = (newLang: Language) => {
    setLang(newLang);
    localStorage.setItem("lang", newLang);
  };

  const currentTrans = translations[lang];

  const tabs: Array<[Tab, string]> = [
    ["repeater", currentTrans.tabs.repeater],
    ["intruder", currentTrans.tabs.intruder],
    ["injection", currentTrans.tabs.injection],
    ["traffic", currentTrans.tabs.traffic],
    ["history", currentTrans.tabs.history],
    ["recon", currentTrans.tabs.recon],
    ["workspace", currentTrans.tabs.workspace]
  ];

  const loadRepeater = (request: RequestInput) => { setLoadedRequest({ ...request, headers: { ...request.headers } }); setTab("repeater"); };
  const loadIntruder = (request: RequestInput) => { setLoadedRequest({ ...request, headers: { ...request.headers } }); setTab("intruder"); };

  return <div className="min-h-screen bg-[radial-gradient(circle_at_top,#182846_0,#0a1020_48%)]">
    <header className="border-b border-slate-800/80 bg-slate-950/40">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-5">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-3 w-3 rounded-full bg-teal-300 shadow-[0_0_14px_#5eead4]" />
            <h1 className="text-xl font-bold tracking-tight">{currentTrans.appTitle}</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">{currentTrans.appSubtitle}</p>
        </div>
        <div className="flex items-center gap-2 border border-slate-800 rounded-lg p-1 bg-slate-900/60">
          <button className={`px-2 py-1 text-xs rounded font-medium ${lang === "en" ? "bg-teal-600 text-white" : "text-slate-400 hover:text-slate-200"}`} onClick={() => handleSetLang("en")}>EN</button>
          <button className={`px-2 py-1 text-xs rounded font-medium ${lang === "uk" ? "bg-teal-600 text-white" : "text-slate-400 hover:text-slate-200"}`} onClick={() => handleSetLang("uk")}>UA</button>
        </div>
      </div>
    </header>
    <main className="mx-auto max-w-7xl px-4 py-6">
      <nav className="mb-6 flex flex-wrap gap-1 rounded-lg border border-slate-800 bg-slate-950/40 p-1">
        {tabs.map(([key, label]) => <button className={`rounded-md px-4 py-2 text-sm ${tab === key ? "bg-slate-700 text-white" : "text-slate-400 hover:text-white"}`} onClick={() => setTab(key)} key={key}>{label}</button>)}
      </nav>
      {tab === "repeater" && <Repeater loadedRequest={loadedRequest} lang={lang} />}
      {tab === "intruder" && <Intruder loadedRequest={loadedRequest} lang={lang} />}
      {tab === "injection" && <InjectionLab loadedRequest={loadedRequest} onLoad={loadRepeater} onIntruder={loadIntruder} lang={lang} />}
      {tab === "traffic" && <Traffic onLoad={loadRepeater} onIntruder={loadIntruder} lang={lang} />}
      {tab === "history" && <History lang={lang} />}
      {tab === "recon" && <ReconWorkspace lang={lang} />}
      {tab === "workspace" && <Workspace lang={lang} />}
    </main>
    <footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-slate-600">{currentTrans.footer}</footer>
  </div>;
}
