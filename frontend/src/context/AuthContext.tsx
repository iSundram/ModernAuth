import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import type { User, LoginRequest } from '../types';
import { AuthContext } from './AuthContextDef';
import { authService } from '../api/services';
export type { AuthContextType } from './AuthContextDef';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('access_token'));
  const [settings, setSettings] = useState<Record<string, any>>({});
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
        setUser((userData as any)?.user || userData);
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
          setUser((userData as any)?.user || userData);
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

  const login = async (credentials: LoginRequest): Promise<{ mfa_required: boolean; user_id: string } | void> => {
    setIsLoading(true);
    try {
      const response = await authService.login(credentials);
      
      if ('mfa_required' in response && response.mfa_required) {
        return response;
      }

      // Type guard or check for access_token
      const loginResponse = response as any;
      // Backend returns { tokens: { access_token: ... }, user: ... }
      // Check if tokens object exists
      const tokens = loginResponse.tokens || loginResponse;
      
      if (!tokens.access_token) {
        throw new Error('Invalid response: missing access token');
      }
      
      localStorage.setItem('access_token', tokens.access_token);
      localStorage.setItem('refresh_token', tokens.refresh_token);
      
      setToken(tokens.access_token);
      
      // If the login response includes the user object, use it instead of fetching /me
      const userData = loginResponse.user || (loginResponse.tokens ? null : loginResponse);
      if (userData) {
        setUser(userData);
      } else {
        const meData = await authService.me();
        setUser((meData as any)?.user || meData);
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
      
      const loginResponse = response as any;
      const tokens = loginResponse.tokens || loginResponse;

      if (!tokens.access_token) {
        throw new Error('Invalid response: missing access token');
      }
      
      localStorage.setItem('access_token', tokens.access_token);
      localStorage.setItem('refresh_token', tokens.refresh_token);
      
      setToken(tokens.access_token);
      
      // If the login response includes the user object, use it instead of fetching /me
      const userData = loginResponse.user || (loginResponse.tokens ? null : loginResponse);
      if (userData) {
        setUser(userData);
      } else {
        const meData = await authService.me();
        setUser((meData as any)?.user || meData);
      }
    } catch (error) {
      console.error('MFA Login error:', error);
      throw error;
    } finally {
      setIsLoading(false);
    }
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
        logout,
        setUser,
        setTokens: setTokensExternal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
