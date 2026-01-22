// ModernAuth Frontend Types

// ============================================================================
// Core Types
// ============================================================================

export type UserRole = 'admin' | 'user';
export type UserStatus = 'active' | 'suspended' | 'terminated';

export interface User {
  id: string;
  tenant_id?: string;
  email: string;
  username?: string;
  phone?: string;
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  role?: UserRole;
  status?: UserStatus;
  is_email_verified: boolean;
  is_active: boolean;
  timezone?: string;
  locale?: string;
  metadata?: Record<string, any>;
  last_login_at?: string;
  password_changed_at?: string;
  created_at: string;
  updated_at?: string;
}

// ============================================================================
// Authentication Types
// ============================================================================

export interface LoginRequest {
  email: string;
  password: string;
  fingerprint?: string;
}

export interface LoginMFARequest {
  user_id: string;
  code: string;
  fingerprint?: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  username?: string;
}

export interface SetupMFAResponse {
  secret: string;
  url: string;
}

export interface EnableMFARequest {
  code: string;
}

export interface ResetPasswordRequest {
  token: string;
  new_password: string;
}

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface TokensResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

export interface LoginResponse {
  user: User;
  tokens: TokensResponse;
}

// ============================================================================
// RBAC Types
// ============================================================================

export interface Role {
  id: string;
  name: string;
  description?: string;
  is_system?: boolean;
  created_at?: string;
}

export interface Permission {
  id: string;
  name: string;
  description?: string;
  created_at?: string;
}

export interface AssignRoleRequest {
  role_id: string;
}

// ============================================================================
// Device & Session Types
// ============================================================================

export interface UserDevice {
  id: string;
  user_id: string;
  device_fingerprint?: string;
  device_name?: string;
  device_type?: string; // mobile, desktop, tablet, unknown
  browser?: string;
  browser_version?: string;
  os?: string;
  os_version?: string;
  ip_address?: string;
  location_country?: string;
  location_city?: string;
  is_trusted: boolean;
  is_current: boolean;
  last_seen_at?: string;
  created_at: string;
}

export interface Session {
  id: string;
  user_id: string;
  tenant_id?: string;
  device_id?: string;
  fingerprint?: string;
  created_at: string;
  expires_at: string;
  revoked: boolean;
  is_current?: boolean;
  metadata?: Record<string, any>;
}

export interface LoginHistory {
  id: string;
  user_id: string;
  tenant_id?: string;
  session_id?: string;
  device_id?: string;
  ip_address?: string;
  user_agent?: string;
  location_country?: string;
  location_city?: string;
  login_method?: string; // password, mfa, social, magic_link, api_key
  status: string; // success, failed, blocked, mfa_required
  failure_reason?: string;
  created_at: string;
}

// ============================================================================
// API Key Types
// ============================================================================

export interface APIKey {
  id: string;
  tenant_id?: string;
  user_id?: string;
  name: string;
  description?: string;
  key_prefix: string;
  scopes?: string[];
  rate_limit?: number;
  allowed_ips?: string[];
  expires_at?: string;
  last_used_at?: string;
  last_used_ip?: string;
  is_active: boolean;
  created_at: string;
  revoked_at?: string;
  revoked_by?: string;
}

export interface CreateAPIKeyRequest {
  name: string;
  description?: string;
  scopes?: string[];
  rate_limit?: number;
  allowed_ips?: string[];
  expires_at?: string;
}

export interface CreateAPIKeyResponse {
  id: string;
  key: string; // Only shown once on creation
  key_prefix: string;
  name: string;
  created_at: string;
}

// ============================================================================
// Webhook Types
// ============================================================================

export interface Webhook {
  id: string;
  tenant_id?: string;
  name: string;
  description?: string;
  url: string;
  events: string[];
  headers?: Record<string, any>;
  is_active: boolean;
  retry_count: number;
  timeout_seconds: number;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateWebhookRequest {
  name: string;
  description?: string;
  url: string;
  events: string[];
  headers?: Record<string, any>;
  retry_count?: number;
  timeout_seconds?: number;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event_id: string;
  event_type: string;
  payload: Record<string, any>;
  response_status_code?: number;
  response_time_ms?: number;
  attempt_number: number;
  status: 'pending' | 'success' | 'failed' | 'retrying';
  error_message?: string;
  next_retry_at?: string;
  created_at: string;
  completed_at?: string;
}

// ============================================================================
// Invitation Types
// ============================================================================

export interface UserInvitation {
  id: string;
  tenant_id?: string;
  email: string;
  first_name?: string;
  last_name?: string;
  role_ids?: string[];
  group_ids?: string[];
  invited_by?: string;
  message?: string;
  expires_at: string;
  accepted_at?: string;
  created_at: string;
}

export interface CreateInvitationRequest {
  email: string;
  first_name?: string;
  last_name?: string;
  role_ids?: string[];
  group_ids?: string[];
  message?: string;
  expires_at?: string;
}

// ============================================================================
// Tenant Types
// ============================================================================

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  domain?: string;
  logo_url?: string;
  settings?: Record<string, any>;
  plan: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateTenantRequest {
  name: string;
  slug: string;
  domain?: string;
  logo_url?: string;
  settings?: Record<string, any>;
  plan?: string;
}

export interface UpdateTenantRequest {
  name?: string;
  domain?: string;
  logo_url?: string;
  settings?: Record<string, any>;
  plan?: string;
  is_active?: boolean;
}

export interface TenantStats {
  tenant_id: string;
  user_count: number;
  plan?: string;
  max_users?: number;
}

export interface TenantSecurityStats {
  tenant_id: string;
  total_users: number;
  active_users: number;
  verified_users: number;
  mfa_enabled_users: number;
}

// ============================================================================
// Audit Log Types
// ============================================================================

export interface AuditLog {
  id: string;
  tenant_id?: string;
  user_id?: string;
  actor_id?: string;
  event_type: string;
  ip?: string;
  user_agent?: string;
  data?: Record<string, any>;
  created_at: string;
}

export interface AuditLogQuery {
  user_id?: string;
  limit?: number;
  offset?: number;
  event_type?: string;
}

// ============================================================================
// Admin Types
// ============================================================================

export interface SystemStats {
  users: {
    total: number;
    active: number;
    suspended: number;
    byRole: {
      admin: number;
      user: number;
    };
  };
}

export interface ServiceStatus {
  name: string;
  status: 'healthy' | 'degraded' | 'down' | 'not_configured';
  uptime?: string;
  latency?: string;
  version?: string;
}

export interface SystemSetting {
  key: string;
  value: any;
  category: string;
  is_secret: boolean;
  description: string;
  updated_at: string;
}

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiResponse<T> {
  success?: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

// ============================================================================
// Update User Types
// ============================================================================

export interface UpdateUserRequest {
  email?: string;
  username?: string;
  phone?: string;
  first_name?: string;
  last_name?: string;
  avatar_url?: string;
  timezone?: string;
  locale?: string;
  status?: UserStatus;
  is_active?: boolean;
  metadata?: Record<string, any>;
}
