import { describe, expect, it } from "vitest";
import { transformPayload } from "./transformations.js";

describe("payload transformations", () => {
  it("runs transformations in order", () => {
    expect(transformPayload("  Hello world  ", [
      { operation: "trim" },
      { operation: "lowercase" },
      { operation: "urlEncode" },
      { operation: "prepend", value: "x=" }
    ])).toBe("x=hello%20world");
  });
  it("supports standard and URL-safe base64", () => {
    expect(transformPayload("✓", [{ operation: "base64Encode" }])).toBe("4pyT");
    expect(transformPayload("foo?bar", [{ operation: "base64UrlEncode" }, { operation: "base64UrlDecode" }])).toBe("foo?bar");
  });
  it("supports escaping, hex, and entity encoding", () => {
    expect(transformPayload("\"<&", [{ operation: "jsonEscape" }])).toBe('\\"<&');
    expect(transformPayload("<&", [{ operation: "htmlEntityEncode" }])).toBe("&lt;&amp;");
    expect(transformPayload("😀", [{ operation: "unicodeEscape" }])).toBe("\\ud83d\\ude00");
    expect(transformPayload("hello", [{ operation: "hexEncode" }, { operation: "hexDecode" }])).toBe("hello");
  });
});
