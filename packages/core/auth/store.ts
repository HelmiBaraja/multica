import { create } from "zustand";
import type { User, StorageAdapter } from "../types";
import { identify as identifyAnalytics, resetAnalytics } from "../analytics";
import type { ApiClient } from "../api/client";
import { setCurrentWorkspace } from "../platform/workspace-storage";

export interface AuthStoreOptions {
  api: ApiClient;
  storage: StorageAdapter;
  onLogin?: () => void;
  onLogout?: () => void;
  /** When true, rely on HttpOnly cookies instead of localStorage for auth tokens. */
  cookieAuth?: boolean;
}

export type AuthStatus =
  | "authenticating"
  | "authenticated"
  | "unauthenticated"
  | "recovering";

export interface AuthState {
  user: User | null;
  isLoading: boolean;
  status: AuthStatus;
  retryGeneration: number;

  retryAuthentication: () => void;
  signupWithPassword: (email: string, password: string, name?: string) => Promise<User>;
  loginWithPassword: (email: string, password: string) => Promise<User>;
  loginWithToken: (token: string) => Promise<User>;
  logout: () => void;
  setUser: (user: User) => void;
  refreshMe: () => Promise<void>;
}

export function createAuthStore(options: AuthStoreOptions) {
  const { api, storage, onLogin, onLogout, cookieAuth } = options;

  return create<AuthState>((set) => ({
    user: null,
    isLoading: true,
    status: "authenticating",
    retryGeneration: 0,

    retryAuthentication: () => {
      set((state) => ({
        isLoading: true,
        status: "authenticating",
        retryGeneration: state.retryGeneration + 1,
      }));
    },

    signupWithPassword: async (email: string, password: string, name?: string) => {
      const { token, user } = await api.signupWithPassword(email, password, name);
      if (!cookieAuth) {
        storage.setItem("multica_token", token);
        api.setToken(token);
      }
      onLogin?.();
      identifyAnalytics(user.id, { email: user.email, name: user.name });
      set({ user, isLoading: false, status: "authenticated" });
      return user;
    },

    loginWithPassword: async (email: string, password: string) => {
      const { token, user } = await api.loginWithPassword(email, password);
      if (!cookieAuth) {
        storage.setItem("multica_token", token);
        api.setToken(token);
      }
      onLogin?.();
      identifyAnalytics(user.id, { email: user.email, name: user.name });
      set({ user, isLoading: false, status: "authenticated" });
      return user;
    },

    loginWithToken: async (token: string) => {
      storage.setItem("multica_token", token);
      api.setToken(token);
      const user = await api.getMe();
      onLogin?.();
      identifyAnalytics(user.id, { email: user.email, name: user.name });
      set({ user, isLoading: false, status: "authenticated" });
      return user;
    },

    logout: () => {
      if (cookieAuth) {
        // Clear server-side HttpOnly cookie.
        api.logout().catch(() => {});
      }
      storage.removeItem("multica_token");
      api.setToken(null);
      setCurrentWorkspace(null, null);
      resetAnalytics();
      onLogout?.();
      set({ user: null, isLoading: false, status: "unauthenticated" });
    },

    setUser: (user: User) => {
      set({ user, isLoading: false, status: "authenticated" });
    },

    refreshMe: async () => {
      const user = await api.getMe();
      set({ user, isLoading: false, status: "authenticated" });
    },
  }));
}
