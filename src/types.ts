export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "CONNECT";
export type IntruderMode = "sniper" | "batteringRam" | "pitchfork" | "clusterBomb";
export type PayloadTransformOperation = "urlEncode" | "urlDecode" | "base64Encode" | "base64Decode" | "base64UrlEncode" | "base64UrlDecode" | "htmlEntityEncode" | "jsonEscape" | "unicodeEscape" | "hexEncode" | "hexDecode" | "trim" | "lowercase" | "uppercase" | "prepend" | "append";
export interface PayloadTransform { operation: PayloadTransformOperation; value?: string; }

export interface HeaderPair { key: string; value: string; }
export interface RequestInput {
  method: HttpMethod;
  url: string;
  headers: Record<string, string>;
  body?: string;
}
export type PayloadDictionaries = Record<string, string[]>;
export interface ResponseData {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  durationMs: number;
  truncated?: boolean;
}
export interface HistoryItem {
  id: string;
  createdAt: string;
  request: RequestInput;
  response?: ResponseData;
  error?: string;
}
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
export interface ProxyStatus {
  running: boolean;
  host: "127.0.0.1";
  port: number;
  enabled?: boolean;
  pending?: number;
  maxPending?: number;
  timeoutMs?: number;
  mode?: "local" | "allowlist";
  allowExternalHosts?: boolean;
  maxConcurrent?: number;
}
export interface PendingInterceptedRequest {
  id: string;
  createdAt: string;
  expiresAt: string;
  request: RequestInput;
  originalRequest: RequestInput;
}
