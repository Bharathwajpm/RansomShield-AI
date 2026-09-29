/**
 * RansomShield AI — Authentication Context & Session Management
 * Phase 3C: Full Backend Integration
 *
 * Manages JWT access token storage in localStorage, active user session,
 * login/logout flows, and RBAC roles (ADMIN, ANALYST, VIEWER).
 */

import React, { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { API_BASE_URL } from "@/services/api";

export type UserRole = "ADMIN" | "ANALYST" | "VIEWER";

export interface AuthUser {
  user_id: string;
  username: string;
  email?: string | null;
  role: UserRole;
  full_name?: string | null;
  is_active: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  authModalOpen: boolean;
  setAuthModalOpen: (open: boolean) => void;
}

const TOKEN_KEY = "ransomshield_jwt_token";
const USER_KEY = "ransomshield_user_profile";

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(() => {
    if (typeof window !== "undefined") {
      return localStorage.getItem(TOKEN_KEY);
    }
    return null;
  });

  const [user, setUser] = useState<AuthUser | null>(() => {
    if (typeof window !== "undefined") {
      const stored = localStorage.getItem(USER_KEY);
      if (stored) {
        try {
          return JSON.parse(stored);
        } catch {
          return null;
        }
      }
    }
    return null;
  });

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [authModalOpen, setAuthModalOpen] = useState<boolean>(false);

  // Initialize or validate session on mount
  useEffect(() => {
    // If we have token but no user, default to admin prototype or fetch /me
    if (token && !user) {
      const fallbackUser: AuthUser = {
        user_id: "usr_admin",
        username: "admin",
        role: "ADMIN",
        full_name: "SOC Administrator",
        is_active: true,
      };
      setUser(fallbackUser);
      localStorage.setItem(USER_KEY, JSON.stringify(fallbackUser));
    }
  }, [token, user]);

  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    setIsLoading(true);
    setError(null);
    try {
      const resp = await fetch(`${API_BASE_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ detail: "Login failed" }));
        const msg = errData.detail || errData.error?.message || `Login error (${resp.status})`;
        setError(msg);
        setIsLoading(false);
        return false;
      }

      const data = await resp.json();
      const accessToken = data.access_token || data.data?.access_token;
      const loggedUser = data.user || data.data?.user;

      if (!accessToken) {
        setError("Login failed: no access token returned");
        setIsLoading(false);
        return false;
      }

      setToken(accessToken);
      setUser(loggedUser);
      localStorage.setItem(TOKEN_KEY, accessToken);
      if (loggedUser) {
        localStorage.setItem(USER_KEY, JSON.stringify(loggedUser));
      }
      if (typeof window !== "undefined") {
        window.dispatchEvent(new Event("auth:token_updated"));
      }
      setAuthModalOpen(false);
      setIsLoading(false);
      return true;
    } catch (e: any) {
      setError(e.message || "Unable to reach backend authentication service");
      setIsLoading(false);
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    if (typeof window !== "undefined") {
      window.dispatchEvent(new Event("auth:token_updated"));
    }
  }, []);

  const value: AuthContextValue = {
    user,
    token,
    isAuthenticated: !!token && !!user,
    isLoading,
    error,
    login,
    logout,
    authModalOpen,
    setAuthModalOpen,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return ctx;
}
