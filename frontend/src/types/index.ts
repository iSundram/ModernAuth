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

/** Response when login succeeds but MFA is required. */
export interface LoginMfaRequiredResponse {
  mfa_required: true;
  user_id: string;
  preferred_method?: 'totp' | 'email' | 'webauthn';
  methods?: string[];
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

export interface TenantAPIKey {
  id: string;
  name: string;
  key_prefix: string;
  scopes?: string[];
  expires_at?: string;
  last_used_at?: string;
  created_at: string;
}

export interface CreateAPIKeyRequest {
  name: string;
  scopes?: string[];
  expires_in?: number; // seconds
}

export interface CreateAPIKeyResponse extends TenantAPIKey {
  key: string; // Full key, only shown once
}

export interface DomainVerificationResult {
  domain: string;
  txt_record: string;
  status: 'pending' | 'verified' | 'failed';
  verified_at?: string;
}

export interface BulkUserEntry {
  email: string;
  first_name?: string;
  last_name?: string;
  role_ids?: string[];
}

export interface BulkImportResult {
  total: number;
  succeeded: number;
  failed: number;
  errors?: Array<{ email: string; reason: string }>;
}

export interface TenantFeatures {
  sso_enabled: boolean;
  api_access_enabled: boolean;
  webhooks_enabled: boolean;
  mfa_required: boolean;
  custom_branding: boolean;
  custom_flags?: Record<string, boolean | string | number>;
}

export interface TenantOnboardingStatusResponse {
  is_domain_verified: boolean;
  has_users: boolean;
  has_feature_flags: boolean;
  is_complete: boolean;
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

// ============================================================================
// MFA Types
// ============================================================================

export interface MFAStatus {
  totp_enabled: boolean;
  email_enabled: boolean;
  webauthn_enabled: boolean;
  backup_codes_remaining: number;
  preferred_method: 'totp' | 'email' | 'webauthn' | null;
  methods: string[];
}

export interface WebAuthnCredential {
  id: string;
  name: string;
  created_at: string;
  last_used_at?: string;
  credential_id: string;
}

export interface WebAuthnRegistrationOptions {
  publicKey: PublicKeyCredentialCreationOptions;
}

export interface WebAuthnAuthenticationOptions {
  publicKey: PublicKeyCredentialRequestOptions;
}

// ============================================================================
// OAuth Linking Types
// ============================================================================

export interface LinkedOAuthProvider {
  provider: string;
  provider_user_id: string;
  email?: string;
  name?: string;
  avatar_url?: string;
  linked_at: string;
}

// ============================================================================
// Email Template Types
// ============================================================================

export interface EmailTemplateSummary {
  type: string;
  description: string;
  has_custom: boolean;
  is_active: boolean;
}

export interface EmailTemplate {
  id: string;
  tenant_id?: string;
  type: string;
  subject: string;
  html_body: string;
  text_body?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface EmailTemplateVariableItem {
  name: string;
  description: string;
}

export interface EmailTemplateVariables {
  branding: EmailTemplateVariableItem[];
  user: EmailTemplateVariableItem[];
  context: Record<string, EmailTemplateVariableItem[]>;
}

export interface EmailBranding {
  id?: string;
  tenant_id?: string;
  app_name?: string;
  logo_url?: string;
  primary_color?: string;
  secondary_color?: string;
  company_name?: string;
  support_email?: string;
  footer_text?: string;
  created_at?: string;
  updated_at?: string;
}

export interface EmailTemplateVersion {
  id: string;
  template_id: string;
  version: number;
  subject: string;
  html_body: string;
  text_body?: string;
  changed_by?: string;
  change_reason?: string;
  created_at: string;
}

export interface EmailStats {
  total_sent: number;
  total_delivered: number;
  total_opened: number;
  total_clicked: number;
  total_bounced: number;
  total_dropped: number;
  by_template: Record<string, number>;
  by_day: Record<string, number>;
}

export interface EmailBounce {
  id: string;
  email: string;
  bounce_type: string;
  bounce_subtype?: string;
  template_type?: string;
  error_message?: string;
  created_at: string;
}

export interface EmailSuppression {
  id: string;
  email: string;
  reason: string;
  source?: string;
  created_at: string;
}

export interface EmailTemplateExport {
  version: string;
  exported_at: string;
  templates: EmailTemplate[];
  branding: EmailBranding;
}

export interface EmailABTest {
  id: string;
  template_type: string;
  name: string;
  variant_a: string;
  variant_b: string;
  weight_a: number;
  weight_b: number;
  is_active: boolean;
  start_date?: string;
  end_date?: string;
  winner_variant?: string;
  created_at: string;
}

export interface EmailABTestResult {
  variant: string;
  sent: number;
  delivered: number;
  opened: number;
  clicked: number;
  bounce_rate: number;
  open_rate: number;
  click_rate: number;
}

export interface EmailBrandingAdvanced {
  id?: string;
  tenant_id?: string;
  social_links?: {
    facebook?: string;
    twitter?: string;
    linkedin?: string;
    instagram?: string;
  };
  custom_css?: string;
  header_image_url?: string;
  font_family?: string;
  font_family_url?: string;
  created_at?: string;
  updated_at?: string;
}

export interface EmailPreviewRequest {
  first_name?: string;
  last_name?: string;
  email?: string;
  custom_vars?: Record<string, string>;
}

export interface EmailPreviewResponse {
  subject: string;
  html_body: string;
  text_body: string;
}

// ============================================================================
// Magic Link Authentication
// ============================================================================

export interface MagicLinkSendRequest {
  email: string;
}

export interface MagicLinkVerifyRequest {
  token: string;
  allow_registration?: boolean;
}

export interface MagicLinkVerifyResponse {
  user: User;
  tokens: TokensResponse;
  is_new_user: boolean;
}

// ============================================================================
// Impersonation
// ============================================================================

export interface ImpersonateRequest {
  reason?: string;
}

export interface ImpersonationSession {
  id: string;
  session_id: string;
  admin_user_id: string;
  target_user_id: string;
  reason?: string;
  started_at: string;
  ended_at?: string;
  ip_address?: string;
  user_agent?: string;
}

export interface ImpersonationStatus {
  is_impersonation: boolean;
  admin_user_id?: string;
  admin_user_email?: string;
}

export interface ImpersonationResult {
  session: Session;
  tokens: TokensResponse;
  message: string;
  expires_at: string;
}

// ============================================================================
// Bulk User Import/Export
// ============================================================================

export interface BulkUserRecord {
  email: string;
  first_name?: string;
  last_name?: string;
  username?: string;
  phone?: string;
  roles?: string;
  password?: string;
  active?: boolean;
}

export interface UserBulkImportError {
  row: number;
  email: string;
  field?: string;
  message: string;
}

export interface UserBulkImportResult {
  total_records: number;
  success_count: number;
  failure_count: number;
  skipped_count: number;
  errors?: UserBulkImportError[];
  created_users?: string[];
  validate_only: boolean;
}

export interface UserBulkImportRequest {
  users: BulkUserRecord[];
  send_welcome?: boolean;
  skip_existing?: boolean;
  validate_only?: boolean;
}

// ============================================================================
// Rate Limit
// ============================================================================

export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number;
  retryAfter?: number;
}
