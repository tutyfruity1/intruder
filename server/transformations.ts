export type PayloadTransformOperation =
  | "urlEncode"
  | "urlDecode"
  | "base64Encode"
  | "base64Decode"
  | "base64UrlEncode"
  | "base64UrlDecode"
  | "htmlEntityEncode"
  | "jsonEscape"
  | "unicodeEscape"
  | "hexEncode"
  | "hexDecode"
  | "trim"
  | "lowercase"
  | "uppercase"
  | "prepend"
  | "append";

export interface PayloadTransform {
  operation: PayloadTransformOperation;
  value?: string;
}

const htmlEntities: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};

function decodeBase64(value: string, urlSafe: boolean): string {
  const normalized = urlSafe
    ? value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")
    : value;
  return Buffer.from(normalized, "base64").toString("utf8");
}

export function applyPayloadTransform(value: string, transform: PayloadTransform): string {
  switch (transform.operation) {
    case "urlEncode": return encodeURIComponent(value);
    case "urlDecode": return decodeURIComponent(value);
    case "base64Encode": return Buffer.from(value, "utf8").toString("base64");
    case "base64Decode": return decodeBase64(value, false);
    case "base64UrlEncode": return Buffer.from(value, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    case "base64UrlDecode": return decodeBase64(value, true);
    case "htmlEntityEncode": return value.replace(/[&<>"']/g, (character) => htmlEntities[character]);
    case "jsonEscape": return JSON.stringify(value).slice(1, -1);
    case "unicodeEscape": return Array.from(value).map((character) => {
      const codePoint = character.codePointAt(0)!;
      if (codePoint <= 0xffff) return `\\u${codePoint.toString(16).padStart(4, "0")}`;
      const adjusted = codePoint - 0x10000;
      return `\\u${(0xd800 + (adjusted >> 10)).toString(16)}\\u${(0xdc00 + (adjusted & 0x3ff)).toString(16)}`;
    }).join("");
    case "hexEncode": return Buffer.from(value, "utf8").toString("hex");
    case "hexDecode": {
      if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) throw new Error("Hex decode requires an even number of hexadecimal characters");
      return Buffer.from(value, "hex").toString("utf8");
    }
    case "trim": return value.trim();
    case "lowercase": return value.toLowerCase();
    case "uppercase": return value.toUpperCase();
    case "prepend": return `${transform.value ?? ""}${value}`;
    case "append": return `${value}${transform.value ?? ""}`;
    default: throw new Error(`Unsupported payload transformation: ${String(transform.operation)}`);
  }
}

export function transformPayload(value: string, transforms: PayloadTransform[] = []): string {
  return transforms.reduce((current, transform) => applyPayloadTransform(current, transform), value);
}

export const PAYLOAD_TRANSFORM_OPERATIONS: PayloadTransformOperation[] = [
  "urlEncode", "urlDecode", "base64Encode", "base64Decode", "base64UrlEncode", "base64UrlDecode",
  "htmlEntityEncode", "jsonEscape", "unicodeEscape", "hexEncode", "hexDecode", "trim", "lowercase",
  "uppercase", "prepend", "append"
];

export function validatePayloadTransforms(value: unknown): PayloadTransform[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 20) throw new Error("Transformations must be an array of 20 items or fewer");
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || !PAYLOAD_TRANSFORM_OPERATIONS.includes((entry as PayloadTransform).operation)) {
      throw new Error("Unsupported payload transformation");
    }
    const transform = entry as PayloadTransform;
    if (transform.value !== undefined && (typeof transform.value !== "string" || transform.value.length > 1024)) {
      throw new Error("Transformation values must be 1024 characters or less");
    }
    return { operation: transform.operation, ...(transform.value === undefined ? {} : { value: transform.value }) };
  });
}
