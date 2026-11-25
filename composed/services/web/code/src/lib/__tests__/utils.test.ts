import { describe, it, expect } from "vitest";
import { cn } from "../utils";

describe("cn", () => {
  it("merges class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar");
  });

  it("handles conditionals", () => {
    expect(cn("foo", false && "bar", "baz")).toBe("foo baz");
  });

  it("resolves tailwind conflicts", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
  });
});
