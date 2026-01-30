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
  Tenant, CreateTenantRequest, UpdateTenantRequest, TenantStats, TenantSecurityStats,
  TenantAPIKey, CreateAPIKeyRequest as CreateTenantAPIKeyRequest, CreateAPIKeyResponse,
  DomainVerificationResult, BulkUserEntry, BulkImportResult, TenantFeatures,
  SystemStats, ServiceStatus, SystemSetting,
  TokensResponse,
  MFAStatus, WebAuthnCredential, LinkedOAuthProvider,
  EmailTemplateSummary, EmailTemplate, EmailTemplateVariables, EmailBranding
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

  // MFA Status & Preferences
  getMfaStatus: async (): Promise<MFAStatus> => {
    const res = await apiClient.get<{
      is_enabled: boolean;
      methods: string[];
      preferred_method: string;
      backup_codes_remaining: number;
      totp_setup_at?: string;
      webauthn_credentials: number;
    }>('/v1/auth/mfa/status');
    
    // Map backend response to frontend type
    // Backend only adds methods to the array if they are actually enabled
    const methods = res.methods || [];
    return {
      totp_enabled: methods.includes('totp'),
      email_enabled: methods.includes('email'),
      webauthn_enabled: methods.includes('webauthn'),
      backup_codes_remaining: res.backup_codes_remaining || 0,
      preferred_method: res.is_enabled && res.preferred_method ? (res.preferred_method as 'totp' | 'email' | 'webauthn') : null,
      methods: methods,
    };
  },

  setPreferredMfaMethod: (method: 'totp' | 'email' | 'webauthn') =>
    apiClient.post<{ message: string }>('/v1/auth/mfa/preferred', { method }),

  // Email MFA
  enableEmailMfa: () =>
    apiClient.post<{ message: string }>('/v1/auth/mfa/email/enable'),

  disableEmailMfa: () =>
    apiClient.post<{ message: string }>('/v1/auth/mfa/email/disable'),

  sendEmailMfaCode: (userId: string) =>
    apiClient.post<{ message: string }>('/v1/auth/login/mfa/email/send', { user_id: userId }),

  verifyEmailMfa: (userId: string, code: string) =>
    apiClient.post<LoginResponse>('/v1/auth/login/mfa/email', { user_id: userId, code }),

  // Backup Code Login
  loginWithBackupCode: (userId: string, code: string) =>
    apiClient.post<LoginResponse>('/v1/auth/login/mfa/backup', { user_id: userId, code }),

  // WebAuthn/Passkeys
  // Begin registration – returns { options, challenge_id }
  webauthnRegisterBegin: (credentialName: string) =>
    apiClient.post<{ options: any; challenge_id: string }>('/v1/auth/mfa/webauthn/register/begin', { credential_name: credentialName }),

  // Finish registration – requires challenge_id and credential payload
  webauthnRegisterFinish: (challengeId: string, credentialName: string, credential: any) =>
    apiClient.post<{ message: string }>('/v1/auth/mfa/webauthn/register/finish', {
      challenge_id: challengeId,
      credential_name: credentialName,
      credential,
    }),

  webauthnListCredentials: () =>
    apiClient
      .get<{ credentials: WebAuthnCredential[] }>('/v1/auth/mfa/webauthn/credentials')
      .then(res => res.credentials || []),

  // Backend expects DELETE /v1/auth/mfa/webauthn/credentials/{id}
  webauthnDeleteCredential: (credentialId: string) =>
    apiClient.delete<void>(`/v1/auth/mfa/webauthn/credentials/${credentialId}`),

  // Begin WebAuthn login – returns { options, challenge_id }
  webauthnLoginBegin: (userId: string) =>
    apiClient.post<{ options: any; challenge_id: string }>('/v1/auth/login/mfa/webauthn/begin', { user_id: userId }),

  // Finish WebAuthn login – requires challenge_id and credential
  webauthnLoginFinish: (userId: string, challengeId: string, credential: any) =>
    apiClient.post<LoginResponse>('/v1/auth/login/mfa/webauthn/finish', {
      user_id: userId,
      challenge_id: challengeId,
      credential,
    }),

  // Device Trust during MFA – backend uses authenticated user from context
  // and expects { device_fingerprint, trust_days }
  trustDeviceDuringMfa: (deviceFingerprint: string, trustDays: number = 30) =>
    apiClient.post<{ message: string; trust_days: number }>('/v1/auth/mfa/trust-device', {
      device_fingerprint: deviceFingerprint,
      trust_days: trustDays,
    }),
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
    apiClient.get<{ data: UserDevice[] }>('/v1/devices').then(res => res.data || []),

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
    return apiClient.get<{ data: LoginHistory[] }>(`/v1/sessions/history?${searchParams.toString()}`).then(res => res.data || []);
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
    return apiClient.get<{ data: Session[] }>(`/v1/sessions?${searchParams.toString()}`).then(res => res.data || []);
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
    return apiClient.get<{ data: APIKey[] }>(`/v1/api-keys?${searchParams.toString()}`).then(res => res.data || []);
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

  rotate: (id: string) =>
    apiClient.post<{ api_key: APIKey; key: string }>(`/v1/api-keys/${id}/rotate`, {}).then(res => ({
      api_key: res.api_key,
      key: res.key,
    })),
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

  test: (id: string) =>
    apiClient.post<{ success: boolean; status_code?: number; response_time?: number; error?: string }>(`/v1/webhooks/${id}/test`, {}),
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

  resend: (id: string) =>
    apiClient.post<void>(`/v1/invitations/${id}/resend`, {}),

  // Public invitation endpoints (no auth required)
  validate: (token: string) =>
    apiClient.post<{
      valid: boolean;
      email: string;
      first_name?: string;
      last_name?: string;
      expires_at: string;
    }>('/v1/invitations/public/validate', { token }),

  accept: (token: string, data: { password: string; username?: string }) =>
    apiClient.post<{ message: string }>('/v1/invitations/public/accept', {
      token,
      password: data.password,
      username: data.username,
    }),
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
    apiClient.get<TenantStats>(`/v1/tenants/${id}/stats`),

  getSecurityStats: (id: string) =>
    apiClient.get<TenantSecurityStats>(`/v1/tenants/${id}/security-stats`),

  listUsers: (id: string, params?: { limit?: number; offset?: number }) => {
    const searchParams = new URLSearchParams();
    if (params?.limit) searchParams.append('limit', params.limit.toString());
    if (params?.offset) searchParams.append('offset', params.offset.toString());
    return apiClient.get<{ data: User[] }>(`/v1/tenants/${id}/users?${searchParams.toString()}`).then(res => res.data || []);
  },

  assignUser: (tenantId: string, userId: string) =>
    apiClient.post<{ message: string }>(`/v1/tenants/${tenantId}/users/${userId}`),

  removeUser: (tenantId: string, userId: string) =>
    apiClient.delete<void>(`/v1/tenants/${tenantId}/users/${userId}`),

  // Suspension
  suspend: (id: string) =>
    apiClient.post<{ message: string }>(`/v1/tenants/${id}/suspend`),

  activate: (id: string) =>
    apiClient.post<{ message: string }>(`/v1/tenants/${id}/activate`),

  // Audit export - returns raw text, caller handles conversion
  exportAuditLogs: async (id: string, format: 'json' | 'csv' = 'json'): Promise<Blob> => {
    const token = localStorage.getItem('access_token');
    const response = await fetch(`/v1/tenants/${id}/audit-logs/export?format=${format}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    if (!response.ok) throw new Error('Failed to export');
    return response.blob();
  },

  // API Keys
  listAPIKeys: (id: string) =>
    apiClient.get<{ data: TenantAPIKey[]; count: number }>(`/v1/tenants/${id}/api-keys`),

  createAPIKey: (id: string, data: CreateTenantAPIKeyRequest) =>
    apiClient.post<CreateAPIKeyResponse>(`/v1/tenants/${id}/api-keys`, data),

  revokeAPIKey: (tenantId: string, keyId: string) =>
    apiClient.delete<void>(`/v1/tenants/${tenantId}/api-keys/${keyId}`),

  // Domain verification
  initiateDomainVerification: (id: string) =>
    apiClient.post<DomainVerificationResult>(`/v1/tenants/${id}/verify-domain`),

  checkDomainVerification: (id: string) =>
    apiClient.get<DomainVerificationResult>(`/v1/tenants/${id}/verify-domain/status`),

  // Bulk import
  bulkImportUsers: (id: string, users: BulkUserEntry[]) =>
    apiClient.post<BulkImportResult>(`/v1/tenants/${id}/users/import`, { users }),

  // Feature flags
  getFeatures: (id: string) =>
    apiClient.get<TenantFeatures>(`/v1/tenants/${id}/features`),

  updateFeatures: (id: string, features: Partial<TenantFeatures>) =>
    apiClient.put<TenantFeatures>(`/v1/tenants/${id}/features`, features),
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

  // Email Templates
  listEmailTemplates: () =>
    apiClient.get<{ templates: EmailTemplateSummary[] }>('/v1/admin/email-templates').then(res => res.templates),

  getEmailTemplateVariables: () =>
    apiClient.get<EmailTemplateVariables>('/v1/admin/email-templates/variables'),

  getEmailTemplate: (type: string) =>
    apiClient.get<EmailTemplate>(`/v1/admin/email-templates/${type}`),

  updateEmailTemplate: (type: string, data: Partial<EmailTemplate>) =>
    apiClient.put<EmailTemplate>(`/v1/admin/email-templates/${type}`, data),

  deleteEmailTemplate: (type: string) =>
    apiClient.delete<void>(`/v1/admin/email-templates/${type}`),

  previewEmailTemplate: (type: string, data?: Record<string, any>) =>
    apiClient.post<{ html: string; text: string }>(`/v1/admin/email-templates/${type}/preview`, data || {}),

  // Email Branding
  getEmailBranding: () =>
    apiClient.get<EmailBranding>('/v1/admin/email-branding'),

  updateEmailBranding: (data: EmailBranding) =>
    apiClient.put<EmailBranding>('/v1/admin/email-branding', data),
};

// ============================================================================
// OAuth Linking Service
// ============================================================================

export const oauthService = {
  // Currently only provider listing is implemented on the backend.
  getProviders: () =>
    apiClient.get<{ providers: string[] }>('/v1/oauth/providers'),

  // The following linking endpoints are not yet implemented on the backend.
  // To avoid runtime errors, expose them as no-ops for now.
  getLinkedProviders: async (): Promise<LinkedOAuthProvider[]> => {
    return [];
  },

  linkProvider: async (_provider: string): Promise<{ authorization_url: string }> => {
    throw new Error('OAuth account linking is not yet available.');
  },

  unlinkProvider: async (_provider: string): Promise<void> => {
    throw new Error('OAuth account linking is not yet available.');
  },

  getAuthorizationUrl: async (_provider: string): Promise<{ authorization_url: string; state: string }> => {
    throw new Error('OAuth account linking is not yet available.');
  },
};
