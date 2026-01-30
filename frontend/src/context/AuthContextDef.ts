import { createContext } from 'react';
import type { User, LoginRequest } from '../types';

export interface AuthContextType {
  user: User | null;
  token: string | null;
  settings: Record<string, any>;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: LoginRequest) => Promise<{ mfa_required: boolean; user_id: string } | void>;
  loginMfa: (userId: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  setUser: (user: User | null) => void;
  setTokens: (accessToken: string, refreshToken: string) => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);
