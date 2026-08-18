import { describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import type { StorageAdapter, User } from "../types";
import { createAuthStore } from "./store";

const fakeUser: User = {
  id: "u1",
  name: "Alice",
  email: "alice@example.com",
  avatar_url: null,
} as User;

function makeStorage(initial: Record<string, string> = {}): StorageAdapter & {
  snapshot: () => Record<string, string>;
} {
  const data = { ...initial };
  return {
    getItem: (k) => data[k] ?? null,
    setItem: (k, v) => {
      data[k] = v;
    },
    removeItem: (k) => {
      delete data[k];
    },
    snapshot: () => ({ ...data }),
  };
}

function makeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    setToken: vi.fn(),
    signupWithPassword: vi.fn().mockResolvedValue({ token: "t-1", user: fakeUser }),
    loginWithPassword: vi.fn().mockResolvedValue({ token: "t-1", user: fakeUser }),
    ...overrides,
  } as unknown as ApiClient;
}

describe("authStore", () => {
  it("publishes a retry request instead of silently ignoring it", () => {
    const storage = makeStorage({ multica_token: "t" });
    const api = makeApi();
    const store = createAuthStore({ api, storage });

    store.setState({ isLoading: true, status: "recovering" });
    store.getState().retryAuthentication();

    expect(store.getState().status).toBe("authenticating");
    expect(store.getState().retryGeneration).toBe(1);
  });

  it("explicit logout still clears credentials and publishes unauthenticated state", () => {
    const storage = makeStorage({ multica_token: "t" });
    const api = makeApi();
    const onLogout = vi.fn();
    const store = createAuthStore({ api, storage, onLogout });

    store.setState({ user: fakeUser, status: "authenticated", isLoading: false });
    store.getState().logout();

    expect(storage.snapshot().multica_token).toBeUndefined();
    expect(api.setToken).toHaveBeenCalledWith(null);
    expect(onLogout).toHaveBeenCalledOnce();
    expect(store.getState().user).toBeNull();
    expect(store.getState().status).toBe("unauthenticated");
  });
});

describe("authStore credentials", () => {
  it("logs in with a password and marks the session authenticated", async () => {
    const storage = makeStorage();
    const api = makeApi();
    const store = createAuthStore({ api, storage });

    const result = await store.getState().loginWithPassword("alice@example.com", "correct-horse");

    expect(api.loginWithPassword).toHaveBeenCalledWith("alice@example.com", "correct-horse");
    expect(result).toEqual(fakeUser);
    expect(store.getState().status).toBe("authenticated");
    expect(store.getState().user).toEqual(fakeUser);
  });

  it("persists the token in token mode but not in cookie mode", async () => {
    const tokenStorage = makeStorage();
    const tokenStore = createAuthStore({ api: makeApi(), storage: tokenStorage });
    await tokenStore.getState().loginWithPassword("alice@example.com", "correct-horse");
    expect(tokenStorage.snapshot().multica_token).toBe("t-1");

    const cookieStorage = makeStorage();
    const cookieStore = createAuthStore({ api: makeApi(), storage: cookieStorage, cookieAuth: true });
    await cookieStore.getState().loginWithPassword("alice@example.com", "correct-horse");
    expect(cookieStorage.snapshot().multica_token).toBeUndefined();
  });

  it("signs up and authenticates in one call", async () => {
    const api = makeApi();
    const store = createAuthStore({ api, storage: makeStorage() });

    await store.getState().signupWithPassword("alice@example.com", "correct-horse");

    expect(api.signupWithPassword).toHaveBeenCalledWith("alice@example.com", "correct-horse", undefined);
    expect(store.getState().status).toBe("authenticated");
  });

  it("leaves the session unauthenticated when login rejects", async () => {
    const store = createAuthStore({
      api: makeApi({
        loginWithPassword: vi.fn().mockRejectedValue(new Error("invalid email or password")),
      }),
      storage: makeStorage(),
    });

    await expect(
      store.getState().loginWithPassword("alice@example.com", "nope"),
    ).rejects.toThrow("invalid email or password");
    expect(store.getState().user).toBeNull();
  });
});
