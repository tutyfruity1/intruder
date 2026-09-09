import dns from "node:dns/promises";
import net from "node:net";

export interface SecuritySettings {
  allowedHosts: string[];
  externalAllowedHosts?: string[];
  authorizedTestingMode?: boolean;
  authorizedTargets?: string[];
  authorizedAllowLocalhost?: boolean;
  authorizedAllowLoopback?: boolean;
  authorizedAllowPrivateRanges?: boolean;
  authorizedAllowLinkLocal?: boolean;
  authorizedAllowInternalDns?: boolean;
  authorizedAllowIpv4?: boolean;
  authorizedAllowIpv6?: boolean;
  authorizedAllowRedirects?: boolean;
  authorizedAllowNonStandardPorts?: boolean;
  maxRedirects?: number;
  allowExternalHosts?: boolean;
  proxyMode?: "local" | "allowlist";
  allowPrivateHosts: boolean;
  maxIntruderRequests: number;
  requestTimeout?: number;
  maxResponseSize?: number;
  defaultConcurrency?: number;
  defaultDelay?: number;
  proxyPort?: number;
  interceptEnabled?: boolean;
  maxPendingIntercepted?: number;
  interceptionTimeout?: number;
  proxyMaxConcurrent?: number;
  proxyRateLimitPerMinute?: number;
  proxyConnectionTimeout?: number;
  proxyAllowedConnectPorts?: number[];
}

export const DEFAULT_SETTINGS: SecuritySettings = {
  allowedHosts: ["localhost", "127.0.0.1", "::1"],
  externalAllowedHosts: [],
  authorizedTestingMode: true,
  authorizedTargets: [],
  authorizedAllowLocalhost: true,
  authorizedAllowLoopback: true,
  authorizedAllowPrivateRanges: true,
  authorizedAllowLinkLocal: true,
  authorizedAllowInternalDns: true,
  authorizedAllowIpv4: true,
  authorizedAllowIpv6: true,
  authorizedAllowRedirects: true,
  authorizedAllowNonStandardPorts: true,
  maxRedirects: 10,
  allowExternalHosts: true,
  proxyMode: "allowlist",
  allowPrivateHosts: true,
  maxIntruderRequests: 10000,
  requestTimeout: 10000,
  maxResponseSize: 50 * 1024 * 1024,
  defaultConcurrency: 3,
  defaultDelay: 100,
  proxyPort: 3002,
  interceptEnabled: false,
  maxPendingIntercepted: 100,
  interceptionTimeout: 30000,
  proxyMaxConcurrent: 20,
  proxyRateLimitPerMinute: 12000,
  proxyConnectionTimeout: 10000,
  proxyAllowedConnectPorts: [443]
};

const ipv4 = (value: string) => value.split(".").reduce((n, octet) => (n * 256) + Number(octet), 0);
const mappedIpv4 = (value: string) => value.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)?.[1];

function specialIpv4(address: string) {
  const n = ipv4(address);
  const first = n >>> 24;
  const second = (n >>> 16) & 255;
  return first === 0 || (first === 100 && second >= 64 && second <= 127) ||
    (first === 192 && second === 0) || (first === 192 && second === 88) ||
    (first === 198 && (second === 18 || second === 19 || second === 51)) ||
    (first === 203 && second === 0) || first >= 224;
}

type AddressKind = "loopback" | "private" | "linkLocal" | "public" | "unsafe";
function addressKind(address: string): AddressKind {
  const value = mappedIpv4(address) || address;
  const version = net.isIP(value);
  if (version === 4) {
    const n = ipv4(value);
    const first = n >>> 24;
    const second = (n >>> 16) & 255;
    if (first === 127) return "loopback";
    if (first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168)) return "private";
    if (first === 169 && second === 254) return "linkLocal";
    return specialIpv4(value) ? "unsafe" : "public";
  }
  if (version === 6) {
    const lower = value.toLowerCase();
    if (lower === "::1") return "loopback";
    if (lower.startsWith("fc") || lower.startsWith("fd")) return "private";
    if (/^fe[89ab]/.test(lower)) return "linkLocal";
    if (lower === "::" || lower.startsWith("2001:db8:")) return "unsafe";
    return "public";
  }
  return "unsafe";
}

export function isSafeIp(address: string): boolean {
  return ["loopback", "private", "linkLocal"].includes(addressKind(address));
}

export function isPublicIp(address: string): boolean {
  return addressKind(address) === "public";
}

function hostMatches(host: string, allowed: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  const a = allowed.toLowerCase().trim().replace(/^\[|\]$/g, "");
  return a.startsWith("*.") ? h.endsWith(a.slice(1)) : h === a;
}
const hostnameOf = (url: URL) => url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
const isLocalHost = (host: string) => host === "localhost" || host.endsWith(".localhost");
const matchesAny = (host: string, entries: string[]) => entries.some((allowed) => hostMatches(host, allowed));

function parseIpv6(value: string): bigint | undefined {
  const parts = value.toLowerCase().split("::");
  if (parts.length > 2) return undefined;
  const left = parts[0] ? parts[0].split(":") : [];
  const right = parts[1] ? parts[1].split(":") : [];
  const expanded = [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
  if (expanded.length !== 8 || expanded.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return undefined;
  return expanded.reduce((result, part) => (result << 16n) | BigInt(parseInt(part, 16)), 0n);
}

function cidrContains(address: string, rule: string): boolean {
  const [network, prefixText] = rule.split("/");
  const normalized = mappedIpv4(address) || address;
  const version = net.isIP(normalized);
  const prefix = Number(prefixText);
  if (!version || !Number.isInteger(prefix) || (version === 4 && (prefix < 0 || prefix > 32)) || (version === 6 && (prefix < 0 || prefix > 128)) || net.isIP(network) !== version) return false;
  if (version === 4) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return ((ipv4(normalized) >>> 0) & mask) === ((ipv4(network) >>> 0) & mask);
  }
  const current = parseIpv6(normalized);
  const wanted = parseIpv6(network);
  if (current === undefined || wanted === undefined) return false;
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(128 - prefix);
  return (current & mask) === (wanted & mask);
}

function targetRuleMatches(url: URL, address: string, rule: string): boolean {
  const value = rule.trim().toLowerCase();
  if (!value) return false;
  if (value.includes("://")) {
    try {
      const candidate = new URL(value);
      return candidate.protocol === url.protocol && candidate.hostname === url.hostname &&
        (!candidate.port || Number(candidate.port) === Number(url.port || (url.protocol === "https:" ? 443 : 80))) &&
        (!candidate.pathname || candidate.pathname === "/" || candidate.pathname === url.pathname);
    } catch { return false; }
  }
  let host = value;
  let port: string | undefined;
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end < 0) return false;
    host = value.slice(1, end);
    port = value.slice(end + 2) || undefined;
  } else if (net.isIP(value) !== 6 && value.split(":").length === 2) {
    [host, port] = value.split(":");
  }
  const actualPort = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  return (!port || Number(port) === actualPort) && (hostMatches(url.hostname, host) || cidrContains(address, host));
}

function explicitTargetMatch(url: URL, addresses: string[], settings: SecuritySettings) {
  return (settings.authorizedTargets ?? []).some((rule) => addresses.some((address) => targetRuleMatches(url, address, rule)));
}

function assertPortAllowed(url: URL, settings: SecuritySettings) {
  const standard = !url.port || (url.protocol === "http:" && url.port === "80") || (url.protocol === "https:" && url.port === "443");
  if (settings.authorizedTestingMode && !standard && !settings.authorizedAllowNonStandardPorts) throw new Error("Non-standard port is not allowed by Authorized Testing Mode");
}

function assertAuthorizedAddress(address: string, settings: SecuritySettings) {
  const kind = addressKind(address);
  const normalized = mappedIpv4(address) || address;
  if (net.isIP(normalized) === 4 && !settings.authorizedAllowIpv4) throw new Error("IPv4 destinations are not allowed by Authorized Testing Mode");
  if (net.isIP(normalized) === 6 && !settings.authorizedAllowIpv6) throw new Error("IPv6 destinations are not allowed by Authorized Testing Mode");
  if (kind === "loopback" && !(settings.authorizedAllowLoopback || settings.authorizedAllowLocalhost)) throw new Error("Loopback is not allowed by Authorized Testing Mode");
  if (kind === "private" && !settings.authorizedAllowPrivateRanges) throw new Error("Private ranges are not allowed by Authorized Testing Mode");
  if (kind === "linkLocal" && !settings.authorizedAllowLinkLocal) throw new Error("Link-local addresses are not allowed by Authorized Testing Mode");
}

export function validateRequestUrl(raw: string, _settings?: Partial<SecuritySettings>): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("URL must be valid and include a protocol"); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only http:// and https:// URLs are supported");
  return url;
}

export async function resolveAllowedHost(url: URL, _settings?: Partial<SecuritySettings>): Promise<string[]> {
  const host = hostnameOf(url);
  const resolved = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true, verbatim: true })).map(({ address }) => address);
  if (!resolved.length) throw new Error("Hostname did not resolve");
  return resolved;
}

export async function validateResolvedHost(url: URL, settings?: Partial<SecuritySettings>): Promise<void> {
  await resolveAllowedHost(url, settings);
}

export function sanitizeSettings(input: Partial<SecuritySettings>): SecuritySettings {
  const list = (value: unknown, fallback: string[], max: number) => Array.isArray(value) ? [...new Set(value.filter((item): item is string => typeof item === "string").map((item) => item.trim().toLowerCase()).filter(Boolean).slice(0, max))] : fallback;
  const numberList = Array.isArray(input.proxyAllowedConnectPorts)
    ? input.proxyAllowedConnectPorts.filter((port): port is number => Number.isFinite(port)).map((port) => Math.floor(port)).filter((port) => port >= 1 && port <= 65535).slice(0, 20)
    : (DEFAULT_SETTINGS.proxyAllowedConnectPorts ?? [443]);
  return {
    allowedHosts: [...new Set([...DEFAULT_SETTINGS.allowedHosts, ...list(input.allowedHosts, DEFAULT_SETTINGS.allowedHosts, 100)])],
    externalAllowedHosts: list(input.externalAllowedHosts, DEFAULT_SETTINGS.externalAllowedHosts ?? [], 100),
    authorizedTestingMode: input.authorizedTestingMode === true,
    authorizedTargets: list(input.authorizedTargets, DEFAULT_SETTINGS.authorizedTargets ?? [], 200),
    authorizedAllowLocalhost: input.authorizedAllowLocalhost === true,
    authorizedAllowLoopback: input.authorizedAllowLoopback === true,
    authorizedAllowPrivateRanges: input.authorizedAllowPrivateRanges === true,
    authorizedAllowLinkLocal: input.authorizedAllowLinkLocal === true,
    authorizedAllowInternalDns: input.authorizedAllowInternalDns === true,
    authorizedAllowIpv4: input.authorizedAllowIpv4 === true,
    authorizedAllowIpv6: input.authorizedAllowIpv6 === true,
    authorizedAllowRedirects: input.authorizedAllowRedirects === true,
    authorizedAllowNonStandardPorts: input.authorizedAllowNonStandardPorts === true,
    maxRedirects: Math.min(10, Math.max(0, Number.isFinite(input.maxRedirects) ? Math.floor(input.maxRedirects as number) : 5)),
    allowExternalHosts: input.allowExternalHosts === true,
    proxyMode: input.proxyMode === "local" ? "local" : "allowlist",
    allowPrivateHosts: input.allowPrivateHosts !== false,
    maxIntruderRequests: Math.min(100000, Math.max(1, Number.isFinite(input.maxIntruderRequests) ? Math.floor(input.maxIntruderRequests as number) : 10000)),
    requestTimeout: Math.min(60000, Math.max(1000, Number.isFinite(input.requestTimeout) ? Math.floor(input.requestTimeout as number) : 10000)),
    maxResponseSize: Math.min(50 * 1024 * 1024, Math.max(1024, Number.isFinite(input.maxResponseSize) ? Math.floor(input.maxResponseSize as number) : 5 * 1024 * 1024)),
    defaultConcurrency: Math.min(10, Math.max(1, Number.isFinite(input.defaultConcurrency) ? Math.floor(input.defaultConcurrency as number) : 3)),
    defaultDelay: Math.min(10000, Math.max(0, Number.isFinite(input.defaultDelay) ? Math.floor(input.defaultDelay as number) : 100)),
    proxyPort: Math.min(65535, Math.max(1, Number.isFinite(input.proxyPort) ? Math.floor(input.proxyPort as number) : 3002)),
    interceptEnabled: input.interceptEnabled === true,
    maxPendingIntercepted: Math.min(1000, Math.max(1, Number.isFinite(input.maxPendingIntercepted) ? Math.floor(input.maxPendingIntercepted as number) : 100)),
    interceptionTimeout: Math.min(600000, Math.max(1000, Number.isFinite(input.interceptionTimeout) ? Math.floor(input.interceptionTimeout as number) : 30000)),
    proxyMaxConcurrent: Math.min(100, Math.max(1, Number.isFinite(input.proxyMaxConcurrent) ? Math.floor(input.proxyMaxConcurrent as number) : 20)),
    proxyRateLimitPerMinute: Math.min(10000, Math.max(1, Number.isFinite(input.proxyRateLimitPerMinute) ? Math.floor(input.proxyRateLimitPerMinute as number) : 120)),
    proxyConnectionTimeout: Math.min(60000, Math.max(1000, Number.isFinite(input.proxyConnectionTimeout) ? Math.floor(input.proxyConnectionTimeout as number) : 10000)),
    proxyAllowedConnectPorts: numberList.length ? [...new Set(numberList)] : [443]
  };
}
