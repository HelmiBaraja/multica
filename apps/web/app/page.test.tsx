import { describe, it, expect, vi } from "vitest";

const mockRedirect = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({ redirect: mockRedirect }));

import RootPage from "./page";

describe("root route", () => {
  it("redirects to the login page", () => {
    RootPage();
    expect(mockRedirect).toHaveBeenCalledWith("/login");
  });
});
