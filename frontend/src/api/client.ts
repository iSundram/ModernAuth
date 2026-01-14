// Use proxy in development (empty string uses vite proxy), or explicit URL
const API_BASE_URL = import.meta.env.VITE_API_URL || '';

class ApiClient {
  private baseUrl: string;
  private isRefreshing: boolean = false;
  private refreshPromise: Promise<string> | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private getHeaders(): HeadersInit {
    const token = localStorage.getItem('access_token');
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
    };
    
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    return headers;
  }

  private async refreshAccessToken(): Promise<string> {
    // If already refreshing, return the existing promise
    if (this.isRefreshing && this.refreshPromise) {
      return this.refreshPromise;
    }

    this.isRefreshing = true;
    this.refreshPromise = (async () => {
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (!refreshToken) {
          throw new Error('No refresh token available');
        }

        // Don't use apiClient here to avoid infinite loop - make direct fetch
        const response = await fetch(`${this.baseUrl}/v1/auth/refresh`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ refresh_token: refreshToken }),
        });

        if (!response.ok) {
          // Refresh failed, clear tokens and throw
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          throw new Error('Token refresh failed');
        }

        const data = await response.json();
        // Backend returns: { access_token, refresh_token, token_type, expires_in }
        // Not wrapped in tokens object for refresh endpoint
        if (!data.access_token || !data.refresh_token) {
          throw new Error('Invalid refresh response');
        }

        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('refresh_token', data.refresh_token);

        return data.access_token;
      } finally {
        this.isRefreshing = false;
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  private async handleResponse<T>(response: Response, retryRequest?: () => Promise<Response>): Promise<T> {
    // Handle 401 Unauthorized - try to refresh token
    // Skip refresh for auth endpoints to avoid infinite loops
    const url = response.url || '';
    const isAuthEndpoint = url.includes('/auth/refresh') || url.includes('/auth/login') || url.includes('/auth/logout');
    
    if (response.status === 401 && retryRequest && !isAuthEndpoint) {
      try {
        await this.refreshAccessToken();
        // Retry the original request with new token
        const retryResponse = await retryRequest();
        return this.handleResponse<T>(retryResponse);
      } catch (refreshError) {
        // Refresh failed, redirect to login
        if (typeof window !== 'undefined') {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/login';
        }
        throw new Error('Session expired. Please login again.');
      }
    }

    if (!response.ok) {
      let errorMessage = 'Request failed';
      try {
        const errorData = await response.json();
        // Handle backend error format: { success: false, error: { code, message } }
        if (errorData?.error?.message) {
          errorMessage = errorData.error.message;
        } else if (errorData?.message) {
          errorMessage = errorData.message;
        } else if (typeof errorData === 'string') {
          errorMessage = errorData;
        }
      } catch {
        // If JSON parsing fails, use status text
        errorMessage = response.statusText || 'Request failed';
      }
      throw new Error(errorMessage);
    }
    
    if (response.status === 204) {
      return {} as T;
    }
    
    const data = await response.json();
    
    // Handle backend response format
    if (data && typeof data === 'object') {
      // 1. Array unwrapping (for list endpoints)
      if (Array.isArray(data.users)) {
        return data.users as T;
      }
      if (Array.isArray(data.tenants)) {
        return data.tenants as T;
      }
      if (Array.isArray(data.logs)) {
        return data.logs as T;
      }
      if (Array.isArray(data.data)) {
        return data.data as T;
      }
      if (Array.isArray(data.devices)) {
        return data.devices as T;
      }
      if (Array.isArray(data.invitations)) {
        return data.invitations as T;
      }
      if (Array.isArray(data.webhooks)) {
        return data.webhooks as T;
      }
      if (Array.isArray(data.providers)) {
        return data.providers as T;
      }

      // 2. Object unwrapping (for settings or other complex objects)
      if ('settings' in data && data.settings && typeof data.settings === 'object') {
        return data.settings as T;
      }

      // 3. Explicit 'data' property unwrapping
      if ('data' in data && data.data && typeof data.data === 'object' && !Array.isArray(data.data)) {
        return data.data as T;
      }

      // 3. User unwrapping (only if NOT a login response)
      if ('user' in data && !('tokens' in data)) {
        return data.user as T;
      }

      // 4. Return as-is for everything else (including complex responses like login, system stats)
      return data as T;
    }
    
    return (data ?? []) as T;
  }

  async get<T>(path: string): Promise<T> {
    const makeRequest = () => fetch(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: this.getHeaders(),
    });
    
    const response = await makeRequest();
    return this.handleResponse<T>(response, makeRequest);
  }

  async post<T>(path: string, data?: unknown): Promise<T> {
    const makeRequest = () => fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    });
    
    const response = await makeRequest();
    return this.handleResponse<T>(response, makeRequest);
  }

  async put<T>(path: string, data?: unknown): Promise<T> {
    const makeRequest = () => fetch(`${this.baseUrl}${path}`, {
      method: 'PUT',
      headers: this.getHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    });
    
    const response = await makeRequest();
    return this.handleResponse<T>(response, makeRequest);
  }

  async patch<T>(path: string, data?: unknown): Promise<T> {
    const makeRequest = () => fetch(`${this.baseUrl}${path}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: data ? JSON.stringify(data) : undefined,
    });
    
    const response = await makeRequest();
    return this.handleResponse<T>(response, makeRequest);
  }

  async delete<T>(path: string): Promise<T> {
    const makeRequest = () => fetch(`${this.baseUrl}${path}`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    
    const response = await makeRequest();
    return this.handleResponse<T>(response, makeRequest);
  }
}

export const apiClient = new ApiClient(API_BASE_URL);
