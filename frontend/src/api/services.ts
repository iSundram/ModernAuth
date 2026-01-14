import { apiClient } from './client';
import type { 
  User, LoginRequest, LoginResponse, AuditLog, AuditLogQuery,
  RegisterRequest, LoginMFARequest, SetupMFAResponse, EnableMFARequest, 
  ResetPasswordRequest, ChangePasswordRequest, UpdateUserRequest,
  Role,
  UserDevice, LoginHistory, Session,
  APIKey, CreateAPIKeyRequest,
  Webhook, CreateWebhookRequest, WebhookDelivery,
  UserInvitation, CreateInvitationRequest,
  Tenant, CreateTenantRequest, UpdateTenantRequest,
  SystemStats, ServiceStatus, SystemSetting,
  TokensResponse
} from '../types';

// ============================================================================
// Authentication Service
// ============================================================================

export const authService = {
  register: (data: RegisterRequest) =>
    apiClient.post<LoginResponse>('/v1/auth/register', data),

  login: (credentials: LoginRequest) =>
    apiClient.post<LoginResponse | { mfa_required: boolean; user_id: string }>('/v1/auth/login', credentials),

  loginMfa: (data: LoginMFARequest) =>
    apiClient.post<LoginResponse>('/v1/auth/login/mfa', data),

  refresh: (refreshToken: string) =>
    apiClient.post<TokensResponse>('/v1/auth/refresh', { refresh_token: refreshToken }),

  logout: () =>
    apiClient.post<void>('/v1/auth/logout'),

  me: () =>
    apiClient.get<User>('/v1/auth/me'),

  getPublicSettings: () =>
    apiClient.get<Record<string, any>>('/v1/auth/settings'),

  // Email Verification
  verifyEmail: (token: string) =>
    apiClient.post<{ message: string }>('/v1/auth/verify-email', { token }),

  sendVerification: () =>
    apiClient.post<{ message: string }>('/v1/auth/send-verification'),

  // Password Reset
  forgotPassword: (email: string) =>
    apiClient.post<{ message: string }>('/v1/auth/forgot-password', { email }),

  resetPassword: (data: ResetPasswordRequest) =>
    apiClient.post<{ message: string }>('/v1/auth/reset-password', data),

  changePassword: (data: ChangePasswordRequest) =>
    apiClient.post<{ message: string }>('/v1/auth/change-password', data),

  // Session Management
  revokeAllSessions: () =>
    apiClient.post<{ message: string }>('/v1/auth/revoke-all-sessions'),

  // MFA Management
  setupMfa: () =>
    apiClient.post<SetupMFAResponse>('/v1/auth/mfa/setup'),

  enableMfa: (data: EnableMFARequest) =>
    apiClient.post<{ message: string }>('/v1/auth/mfa/enable', data),

  disableMfa: (data: { code: string }) =>
    apiClient.post<{ message: string }>('/v1/auth/mfa/disable', data),

  generateBackupCodes: () =>
    apiClient.post<{ backup_codes: string[]; message: string }>('/v1/auth/mfa/backup-codes'),

  getBackupCodeCount: () =>
    apiClient.get<{ remaining_codes: number }>('/v1/auth/mfa/backup-codes/count'),

  getOAuthProviders: () =>
    apiClient.get<{ providers: string[] }>('/v1/oauth/providers'),

  getOAuthAuthorizationURL: (provider: string) =>
    apiClient.get<{ authorization_url: string; state: string }>(`/v1/oauth/${provider}/authorize`),
};

// ============================================================================
// User Service
// ============================================================================

export const userService = {
  list: () => 
    apiClient.get<User[]>('/v1/users'),
  
  get: (id: string) => 
    apiClient.get<User>(`/v1/users/${id}`),
  
  create: (data: RegisterRequest) => 
    apiClient.post<User>('/v1/users', data),
  
  update: (id: string, data: UpdateUserRequest) => 
    apiClient.put<User>(`/v1/users/${id}`, data),
  
  delete: (id: string) => 
    apiClient.delete<void>(`/v1/users/${id}`),
};

// ============================================================================
// Device Service
// ============================================================================

export const deviceService = {
  list: () =>
    apiClient.get<UserDevice[]>('/v1/devices'),

  get: (id: string) =>
    apiClient.get<UserDevice>(`/v1/devices/${id}`),

  trust: (id: string) =>
    apiClient.post<void>(`/v1/devices/${id}/trust`),

  untrust: (id: string) =>
    apiClient.delete<void>(`/v1/devices/${id}/trust`),

  remove: (id: string) =>
    apiClient.delete<void>(`/v1/devices/${id}`),

  getLoginHistory: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<LoginHistory[]>(`/v1/sessions/history?${searchParams.toString()}`);
  },
};

// ============================================================================
// Session Service
// ============================================================================

export const sessionService = {
  list: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<Session[]>(`/v1/sessions?${searchParams.toString()}`);
  },
  revokeAll: () =>
    apiClient.post<void>('/v1/auth/revoke-all-sessions'),
};

// ============================================================================
// API Key Service
// ============================================================================

export const apiKeyService = {
  list: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<APIKey[]>(`/v1/api-keys?${searchParams.toString()}`);
  },

  get: (id: string) =>
    apiClient.get<APIKey>(`/v1/api-keys/${id}`),

  create: (data: CreateAPIKeyRequest) =>
    apiClient.post<{ api_key: APIKey; key: string }>('/v1/api-keys', data).then(res => ({
      id: res.api_key.id,
      key: res.key,
      key_prefix: res.api_key.key_prefix,
      name: res.api_key.name,
      created_at: res.api_key.created_at,
    })),

  update: (id: string, data: Partial<CreateAPIKeyRequest>) =>
    apiClient.put<APIKey>(`/v1/api-keys/${id}`, data),

  revoke: (id: string) =>
    apiClient.delete<void>(`/v1/api-keys/${id}`),
};

// ============================================================================
// Webhook Service
// ============================================================================

export const webhookService = {
  list: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<Webhook[]>(`/v1/webhooks?${searchParams.toString()}`);
  },

  get: (id: string) =>
    apiClient.get<Webhook>(`/v1/webhooks/${id}`),

  create: (data: CreateWebhookRequest) =>
    apiClient.post<Webhook>('/v1/webhooks', data),

  update: (id: string, data: Partial<CreateWebhookRequest>) =>
    apiClient.put<Webhook>(`/v1/webhooks/${id}`, data),

  delete: (id: string) =>
    apiClient.delete<void>(`/v1/webhooks/${id}`),

  getDeliveries: (id: string, params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<WebhookDelivery[]>(`/v1/webhooks/${id}/deliveries?${searchParams.toString()}`);
  },
};

// ============================================================================
// Invitation Service
// ============================================================================

export const invitationService = {
  list: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<UserInvitation[]>(`/v1/invitations?${searchParams.toString()}`);
  },

  get: (id: string) =>
    apiClient.get<UserInvitation>(`/v1/invitations/${id}`),

  create: (data: CreateInvitationRequest) =>
    apiClient.post<UserInvitation>('/v1/invitations', data),

  delete: (id: string) =>
    apiClient.delete<void>(`/v1/invitations/${id}`),

  // Public invitation acceptance (no auth required)
  getByToken: (token: string) =>
    apiClient.get<UserInvitation>(`/v1/invitations/public/${token}`),

  accept: (token: string, data: { password: string; username?: string }) =>
    apiClient.post<LoginResponse>(`/v1/invitations/public/${token}/accept`, data),
};

// ============================================================================
// Tenant Service
// ============================================================================

export const tenantService = {
  list: (params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<Tenant[]>(`/v1/tenants?${searchParams.toString()}`);
  },

  get: (id: string) =>
    apiClient.get<Tenant>(`/v1/tenants/${id}`),

  create: (data: CreateTenantRequest) =>
    apiClient.post<Tenant>('/v1/tenants', data),

  update: (id: string, data: UpdateTenantRequest) =>
    apiClient.put<Tenant>(`/v1/tenants/${id}`, data),

  delete: (id: string) =>
    apiClient.delete<void>(`/v1/tenants/${id}`),

  getStats: (id: string) =>
    apiClient.get<any>(`/v1/tenants/${id}/stats`),

  listUsers: (id: string, params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<User[]>(`/v1/tenants/${id}/users?${searchParams.toString()}`);
  },

  assignUser: (tenantId: string, userId: string) =>
    apiClient.post<{ message: string }>(`/v1/tenants/${tenantId}/users/${userId}`),

  removeUser: (tenantId: string, userId: string) =>
    apiClient.delete<void>(`/v1/tenants/${tenantId}/users/${userId}`),
};

// ============================================================================
// Audit Service
// ============================================================================

export const auditService = {
  listLogs: (params?: AuditLogQuery) => {
    const searchParams = new URLSearchParams();
    if (params?.user_id) searchParams.append('user_id', params.user_id);
    if (params?.limit !== undefined) searchParams.append('limit', params.limit.toString());
    if (params?.offset !== undefined) searchParams.append('offset', params.offset.toString());
    if (params?.event_type) searchParams.append('event_type', params.event_type);
    
    return apiClient.get<AuditLog[]>(`/v1/audit/logs?${searchParams.toString()}`);
  },
};

// ============================================================================
// Admin Service
// ============================================================================

export const adminService = {
  getSystemStats: async (): Promise<SystemStats> => {
    return await apiClient.get<SystemStats>('/v1/admin/stats');
  },

  getServiceStatus: async (): Promise<ServiceStatus[]> => {
    return await apiClient.get<ServiceStatus[]>('/v1/admin/services');
  },

  // Role Management
  listRoles: async (): Promise<Role[]> => {
    return await apiClient.get<Role[]>('/v1/admin/roles');
  },

  getRole: async (id: string): Promise<Role> => {
    return await apiClient.get<Role>(`/v1/admin/roles/${id}`);
  },

  createRole: async (data: { name: string; description?: string; tenant_id?: string }): Promise<Role> => {
    return await apiClient.post<Role>('/v1/admin/roles', data);
  },

  updateRole: async (id: string, data: { description?: string }): Promise<Role> => {
    return await apiClient.put<Role>(`/v1/admin/roles/${id}`, data);
  },

  deleteRole: async (id: string): Promise<void> => {
    return await apiClient.delete<void>(`/v1/admin/roles/${id}`);
  },

  getRolePermissions: async (roleId: string): Promise<any[]> => {
    return await apiClient.get<any[]>(`/v1/admin/roles/${roleId}/permissions`);
  },

  assignPermissionToRole: async (roleId: string, permissionId: string): Promise<void> => {
    return await apiClient.post<void>(`/v1/admin/roles/${roleId}/permissions`, { permission_id: permissionId });
  },

  removePermissionFromRole: async (roleId: string, permissionId: string): Promise<void> => {
    return await apiClient.delete<void>(`/v1/admin/roles/${roleId}/permissions/${permissionId}`);
  },

  listPermissions: async (): Promise<any[]> => {
    return await apiClient.get<any[]>('/v1/admin/permissions');
  },

  // User Role Assignment
  assignRole: async (userId: string, roleId: string): Promise<void> => {
    return await apiClient.post<void>(`/v1/admin/users/${userId}/roles`, { role_id: roleId });
  },

  removeRole: async (userId: string, roleId: string): Promise<void> => {
    return await apiClient.delete<void>(`/v1/admin/users/${userId}/roles/${roleId}`);
  },

  // Settings
  listSettings: (category?: string) =>
    apiClient.get<SystemSetting[]>(`/v1/admin/settings${category ? `?category=${category}` : ''}`),

  updateSetting: (key: string, value: any) =>
    apiClient.patch<{ message: string }>(`/v1/admin/settings/${key}`, { value }),
};
