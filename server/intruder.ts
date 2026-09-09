import type { RequestInput, PayloadDictionaries, PayloadTransform } from "./types.js";
import { transformPayload } from "./transformations.js";

export type IntruderMode = "sniper" | "batteringRam" | "pitchfork" | "clusterBomb";
export interface IntruderOptions {
  transformations?: PayloadTransform[];
  payloadDictionaries?: PayloadDictionaries;
  payloadsByPosition?: PayloadDictionaries;
}

interface Position { start: number; end: number; name: string; }
const markerPattern = /§([^§]+)§|\{\{([^{}]+)\}\}/g;

function positions(request: RequestInput): Position[] {
  const text = JSON.stringify(request);
  const found: Position[] = [];
  let match: RegExpExecArray | null;
  while ((match = markerPattern.exec(text))) found.push({ start: match.index, end: match.index + match[0].length, name: (match[1] || match[2]).trim() });
  markerPattern.lastIndex = 0;
  return found;
}

function applyPayload(request: RequestInput, replacements: string[]): RequestInput {
  let index = 0;
  const replace = (value: string) => value.replace(markerPattern, () => replacements[index++] ?? "");
  return {
    ...request,
    url: replace(request.url),
    headers: Object.fromEntries(Object.entries(request.headers).map(([key, value]) => [replace(key), replace(value)])),
    body: request.body === undefined ? undefined : replace(request.body)
  };
}

function dictionaryFor(position: Position, index: number, payloads: string[], dictionaries: PayloadDictionaries): string[] {
  return dictionaries[position.name] || dictionaries[String(index)] || payloads;
}

export function generateIntruderRequests(
  request: RequestInput,
  mode: IntruderMode,
  payloads: string[],
  maxRequests = 100,
  transformationsOrOptions: PayloadTransform[] | IntruderOptions | PayloadDictionaries = [],
  payloadDictionaries: PayloadDictionaries = {}
): RequestInput[] {
  const optionObject = !Array.isArray(transformationsOrOptions) ? transformationsOrOptions as IntruderOptions : undefined;
  const transformations = Array.isArray(transformationsOrOptions) ? transformationsOrOptions : optionObject?.transformations || [];
  if (optionObject) {
    payloadDictionaries = optionObject.payloadDictionaries || optionObject.payloadsByPosition ||
      (!("transformations" in optionObject) && !("payloadDictionaries" in optionObject) && !("payloadsByPosition" in optionObject)
        ? optionObject as PayloadDictionaries : payloadDictionaries);
  }
  if (!payloads.length && !Object.values(payloadDictionaries).some((values) => values.length)) throw new Error("At least one payload is required");
  const found = positions(request);
  if (!found.length) throw new Error("Add at least one §marker§ or {{marker}} to the request");
  const dictionaries = found.map((position, index) => dictionaryFor(position, index, payloads, payloadDictionaries).map((payload) => transformPayload(payload, transformations)));
  if (dictionaries.some((values) => values.some((payload) => payload.length > 4096))) throw new Error("Payloads must be 4096 characters or less after transformation");
  if (payloads.some((p) => p.length > 4096) || Object.values(payloadDictionaries).some((values) => values.some((p) => p.length > 4096))) {
    throw new Error("Payloads must be 4096 characters or less");
  }

  const planned = mode === "sniper"
    ? dictionaries.reduce((total, values) => total + values.length, 0)
    : mode === "batteringRam"
      ? dictionaries[0].length
      : mode === "pitchfork"
        ? Math.min(...dictionaries.map((values) => values.length))
        : dictionaries.reduce((total, values) => total * values.length, 1);
  if (!planned) throw new Error("Each marker needs at least one payload");
  if (planned > maxRequests) throw new Error(`Intruder plan creates ${planned} requests; maximum is ${maxRequests}`);

  const combos: string[][] = [];
  if (mode === "sniper") {
    for (let position = 0; position < found.length; position++) {
      for (const payload of dictionaries[position]) {
        const values = Array(found.length).fill("");
        values[position] = payload;
        combos.push(values);
      }
    }
  } else if (mode === "batteringRam") {
    for (const payload of dictionaries[0]) combos.push(Array(found.length).fill(payload));
  } else if (mode === "pitchfork") {
    for (let i = 0; i < planned; i++) combos.push(dictionaries.map((values) => values[i]));
  } else {
    const build = (prefix: string[], depth: number) => {
      if (depth === found.length) { combos.push(prefix); return; }
      for (const payload of dictionaries[depth]) build([...prefix, payload], depth + 1);
    };
    build([], 0);
  }
  return combos.map((values) => applyPayload(request, values));
}
