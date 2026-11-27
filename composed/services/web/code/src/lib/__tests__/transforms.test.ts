import { describe, it, expect } from "vitest";
import { formatDate, formatNumber, truncate } from "../transforms";

describe("formatDate", () => {
  it("formats a date string", () => {
    const result = formatDate("2024-01-15T10:30:00Z");
    expect(result).toContain("Jan");
    expect(result).toContain("15");
    expect(result).toContain("2024");
  });

  it("returns dash for null", () => {
    expect(formatDate(null)).toBe("-");
  });
});

describe("formatNumber", () => {
  it("formats a number", () => {
    expect(formatNumber(1234)).toBe("1,234");
  });

  it("returns dash for null", () => {
    expect(formatNumber(null)).toBe("-");
  });
});

describe("truncate", () => {
  it("truncates long strings", () => {
    expect(truncate("a".repeat(100), 10)).toBe("aaaaaaaaaa...");
  });

  it("returns short strings as-is", () => {
    expect(truncate("hello")).toBe("hello");
  });

  it("returns dash for null", () => {
    expect(truncate(null)).toBe("-");
  });
});
