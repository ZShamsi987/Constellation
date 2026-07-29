import { describe, expect, it } from "vitest";
import { displayOs, formatBytes } from "./format";

describe("formatBytes", () => {
  it("formats binary capacity without overstating it", () => {
    expect(formatBytes(48 * 1024 ** 3)).toBe("48 GiB");
    expect(formatBytes(1536 * 1024 ** 2)).toBe("1.5 GiB");
  });
});

describe("displayOs", () => {
  it("uses user-facing platform names", () => {
    expect(displayOs("mac_os")).toBe("macOS");
    expect(displayOs("linux")).toBe("Linux");
  });
});
