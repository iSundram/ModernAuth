import { createContext } from 'react';
import type { User, LoginRequest, LoginMfaRequiredResponse, LoginResponse } from '../types';

export interface AuthContextType {
  user: User | null;
  token: string | null;
  settings: Record<string, any>;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<LoginMfaRequiredResponse | void>;
  loginMfa: (userId: string, code: string) => Promise<void>;
  /** Store tokens and user from a login response (e.g. after email/backup/passkey MFA). */
  completeLogin: (response: LoginResponse) => void;
  logout: () => Promise<void>;
  setUser: (user: User | null) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
