import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import type { User, LoginRequest, LoginResponse, LoginMfaRequiredResponse } from '../types';
import { AuthContext } from './AuthContextDef';
import { authService } from '../api/services';
export type { AuthContextType } from './AuthContextDef';

// Type guard to check if a response is an MFA required response
function isMfaRequiredResponse(response: unknown): response is LoginMfaRequiredResponse {
  return (
    typeof response === 'object' &&
    response !== null &&
    'mfa_required' in response &&
    (response as LoginMfaRequiredResponse).mfa_required === true
  );
}

// Type guard to check if a response is a login response with tokens
interface LoginResponseWithTokens {
  user?: User;
  tokens?: {
    access_token: string;
    refresh_token: string;
  };
  access_token?: string;
  refresh_token?: string;
}

function isLoginResponseWithTokens(response: unknown): response is LoginResponseWithTokens {
  if (typeof response !== 'object' || response === null) {
    return false;
  }
  const r = response as LoginResponseWithTokens;
  // Check for tokens either at top level or nested
  return (
    (r.tokens?.access_token !== undefined && r.tokens?.refresh_token !== undefined) ||
    (r.access_token !== undefined && r.refresh_token !== undefined)
  );
}

// Helper to extract user from response
function extractUser(response: LoginResponseWithTokens): User | null {
  if (response.user) {
    return response.user;
  }
  return null;
}

// Helper to extract tokens from response
function extractTokens(response: LoginResponseWithTokens): { access_token: string; refresh_token: string } | null {
  if (response.tokens?.access_token && response.tokens?.refresh_token) {
    return response.tokens;
  }
  if (response.access_token && response.refresh_token) {
    return { access_token: response.access_token, refresh_token: response.refresh_token };
  }
  return null;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('access_token'));
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const bootstrapAuth = async () => {
      // Always fetch public settings first
      try {
        const publicSettings = await authService.getPublicSettings();
        setSettings(publicSettings);
      } catch (err) {
        console.error('Failed to fetch public settings:', err);
      }

      const storedAccess = localStorage.getItem('access_token');
      const storedRefresh = localStorage.getItem('refresh_token');

      if (!storedAccess || !storedRefresh) {
        setIsLoading(false);
        return;
      }

      setToken(storedAccess);

      try {
        const userData = await authService.me();
        setUser(userData);
        return;
      } catch {
        // Attempt a token refresh if the access token is no longer valid
        try {
          const refreshed = await authService.refresh(storedRefresh);
          // Refresh endpoint returns tokens directly, not wrapped
          localStorage.setItem('access_token', refreshed.access_token);
          localStorage.setItem('refresh_token', refreshed.refresh_token);
          setToken(refreshed.access_token);
          const userData = await authService.me();
          setUser(userData);
          return;
        } catch (refreshError) {
          console.error('Token refresh failed:', refreshError);
        }
      } finally {
        setIsLoading(false);
      }

      // If we reach here the refresh failed – clear stored auth
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      setToken(null);
      setUser(null);
      setIsLoading(false);
    };

    bootstrapAuth();
  }, []);

  const login = async (credentials: LoginRequest): Promise<LoginMfaRequiredResponse | void> => {
    setIsLoading(true);
    try {
      const response = await authService.login(credentials);
      
      if (isMfaRequiredResponse(response)) {
        return response;
      }

      if (!isLoginResponseWithTokens(response)) {
        throw new Error('Invalid response: missing tokens');
      }

      const tokens = extractTokens(response);
      if (!tokens) {
        throw new Error('Invalid response: missing access token');
      }
      
      localStorage.setItem('access_token', tokens.access_token);
      localStorage.setItem('refresh_token', tokens.refresh_token);
      
      setToken(tokens.access_token);
      
      // If the login response includes the user object, use it instead of fetching /me
      const userData = extractUser(response);
      if (userData) {
        setUser(userData);
      } else {
        const meData = await authService.me();
        setUser(meData);
      }
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const loginMfa = async (userId: string, code: string): Promise<void> => {
    setIsLoading(true);
    try {
      const response = await authService.loginMfa({ user_id: userId, code });
      
      if (!isLoginResponseWithTokens(response)) {
        throw new Error('Invalid response: missing tokens');
      }

      const tokens = extractTokens(response);
      if (!tokens) {
        throw new Error('Invalid response: missing access token');
      }
      
      localStorage.setItem('access_token', tokens.access_token);
      localStorage.setItem('refresh_token', tokens.refresh_token);
      
      setToken(tokens.access_token);
      
      // If the login response includes the user object, use it instead of fetching /me
      const userData = extractUser(response);
      if (userData) {
        setUser(userData);
      } else {
        const meData = await authService.me();
        setUser(meData);
      }
    } catch (error) {
      console.error('MFA Login error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
  };

  const completeLogin = (response: LoginResponse): void => {
    const tokens = response.tokens;
    if (!tokens?.access_token || !tokens?.refresh_token) {
      throw new Error('Invalid response: missing tokens');
    }
    localStorage.setItem('access_token', tokens.access_token);
    localStorage.setItem('refresh_token', tokens.refresh_token);
    setToken(tokens.access_token);
    setUser(response.user);
  };

  const logout = async () => {
    try {
      await authService.logout();
    } catch (error) {
      console.warn('Logout request failed, clearing local session instead.', error);
    }

    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    setToken(null);
    setUser(null);
  };

  const setTokensExternal = (accessToken: string, refreshToken: string) => {
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
    setToken(accessToken);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        settings,
        isAuthenticated: !!token,
        isLoading,
        login,
        loginMfa,
        completeLogin,
        logout,
        setUser,
        setTokens: setTokensExternal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
