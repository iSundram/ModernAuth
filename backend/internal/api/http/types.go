// Package http provides shared types for ModernAuth API.
package http

// RegisterRequest represents the register request body.
type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=128"`
	Username string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
}

// RegisterResponse represents the register response.
type RegisterResponse struct {
	User   UserResponse   `json:"user"`
	Tokens TokensResponse `json:"tokens"`
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID              string                 `json:"id"`
	Email           string                 `json:"email"`
	Username        *string                `json:"username,omitempty"`
	Phone           *string                `json:"phone,omitempty"`
	FirstName       *string                `json:"first_name,omitempty"`
	LastName        *string                `json:"last_name,omitempty"`
	IsEmailVerified bool                   `json:"is_email_verified"`
	IsActive        bool                   `json:"is_active"`
	Role            string                 `json:"role"`
	Timezone        *string                `json:"timezone,omitempty"`
	Locale          *string                `json:"locale,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
	LastLoginAt     *string                `json:"last_login_at,omitempty"`
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       *string                `json:"updated_at,omitempty"`
}

// TokensResponse represents tokens in API responses.
type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// LoginRequest represents the login request body.
type LoginRequest struct {
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// LoginResponse represents the login response.
type LoginResponse struct {
	User   UserResponse   `json:"user"`
	Tokens TokensResponse `json:"tokens"`
}

// LoginMFARequest represents the login MFA request body.
type LoginMFARequest struct {
	UserID      string `json:"user_id" validate:"required,uuid"`
	Code        string `json:"code" validate:"required,len=6"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// RefreshRequest represents the refresh request body.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// RefreshResponse represents the refresh response.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// SetupMFAResponse represents the MFA setup response.
type SetupMFAResponse struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
}

// EnableMFARequest represents the enable MFA request body.
type EnableMFARequest struct {
	Code string `json:"code" validate:"required,len=6"`
}

// VerifyEmailHTTPRequest represents the verify email request body.
type VerifyEmailHTTPRequest struct {
	Token string `json:"token" validate:"required"`
}

// ForgotPasswordRequest represents the forgot password request body.
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordHTTPRequest represents the reset password request body.
type ResetPasswordHTTPRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// ChangePasswordHTTPRequest represents the change password request body.
type ChangePasswordHTTPRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// UpdateUserHTTPRequest represents the update user request body.
type UpdateUserHTTPRequest struct {
	Email    *string `json:"email,omitempty" validate:"omitempty,email"`
	Username *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	Phone    *string `json:"phone,omitempty"`
}

// UpdateProfileRequest represents a request to update the user's own profile.
type UpdateProfileRequest struct {
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,max=100"`
	LastName  *string `json:"last_name,omitempty" validate:"omitempty,max=100"`
	Username  *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	Phone     *string `json:"phone,omitempty"`
	AvatarURL *string `json:"avatar_url,omitempty" validate:"omitempty,url"`
	Timezone  *string `json:"timezone,omitempty"`
	Locale    *string `json:"locale,omitempty"`
}

// AuditLogResponse represents an audit log in API responses.
type AuditLogResponse struct {
	ID        string                 `json:"id"`
	UserID    *string                `json:"user_id,omitempty"`
	ActorID   *string                `json:"actor_id,omitempty"`
	EventType string                 `json:"event_type"`
	IP        *string                `json:"ip,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	CreatedAt string                 `json:"created_at"`
}

// RoleResponse represents a role in API responses.
type RoleResponse struct {
	ID          string  `json:"id"`
	TenantID    *string `json:"tenant_id,omitempty"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	IsSystem    bool    `json:"is_system"`
	CreatedAt   string  `json:"created_at,omitempty"`
}

// CreateRoleRequest represents the create role request body.
type CreateRoleRequest struct {
	TenantID    *string `json:"tenant_id,omitempty" validate:"omitempty,uuid"`
	Name        string  `json:"name" validate:"required,min=1,max=50"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=255"`
}

// UpdateRoleRequest represents the update role request body.
type UpdateRoleRequest struct {
	Name        *string `json:"name,omitempty" validate:"omitempty,min=1,max=50"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=255"`
}

// PermissionResponse represents a permission in API responses.
type PermissionResponse struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// AssignPermissionRequest represents the assign permission request body.
type AssignPermissionRequest struct {
	PermissionID string `json:"permission_id" validate:"required,uuid"`
}

// AssignUserRoleRequest represents the assign role request body.
type AssignUserRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}

// SessionResponse represents a session in API responses.
type SessionResponse struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	TenantID    *string                `json:"tenant_id,omitempty"`
	DeviceID    *string                `json:"device_id,omitempty"`
	Fingerprint *string                `json:"fingerprint,omitempty"`
	CreatedAt   string                 `json:"created_at"`
	ExpiresAt   string                 `json:"expires_at"`
	Revoked     bool                   `json:"revoked"`
	IsCurrent   bool                   `json:"is_current"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DeleteOwnAccountRequest represents a request to self-delete a user account.
type DeleteOwnAccountRequest struct {
	Password string `json:"password" validate:"required"`
}

// GoogleOneTapRequest represents a Google One Tap login request.
type GoogleOneTapRequest struct {
	Credential string `json:"credential" validate:"required"`
}

// JoinWaitlistRequest represents a request to join the waitlist.
type JoinWaitlistRequest struct {
	Email string `json:"email" validate:"required,email"`
	Name  string `json:"name,omitempty" validate:"omitempty,max=100"`
}

// WaitlistStatusRequest represents a request to check waitlist status.
type WaitlistStatusRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// DataExportResponse represents the GDPR data export response.
// Rate limiting recommended: 1 request per 24 hours per user.
type DataExportResponse struct {
	ExportedAt   string                    `json:"exported_at"`
	User         UserResponse              `json:"user"`
	Preferences  *UserPreferencesResponse  `json:"preferences,omitempty"`
	LoginHistory []LoginHistoryResponse    `json:"login_history,omitempty"`
	Devices      []DeviceExportResponse    `json:"devices,omitempty"`
	AuditLogs    []AuditLogResponse        `json:"audit_logs,omitempty"`
}

// UserPreferencesResponse represents user preferences in API responses.
type UserPreferencesResponse struct {
	EmailSecurityAlerts      bool   `json:"email_security_alerts"`
	EmailMarketing           bool   `json:"email_marketing"`
	EmailProductUpdates      bool   `json:"email_product_updates"`
	EmailDigestFrequency     string `json:"email_digest_frequency"`
	PushEnabled              bool   `json:"push_enabled"`
	AccentColor              string `json:"accent_color"`
	FontSize                 string `json:"font_size"`
	HighContrast             bool   `json:"high_contrast"`
	ReducedMotion            bool   `json:"reduced_motion"`
	ProfileVisibility        string `json:"profile_visibility"`
	ShowActivityStatus       bool   `json:"show_activity_status"`
	ShowEmailPublicly        bool   `json:"show_email_publicly"`
	KeyboardShortcutsEnabled bool   `json:"keyboard_shortcuts_enabled"`
	CreatedAt                string `json:"created_at"`
	UpdatedAt                string `json:"updated_at"`
}

// DeviceExportResponse represents a device in data export responses.
type DeviceExportResponse struct {
	ID              string  `json:"id"`
	DeviceName      *string `json:"device_name,omitempty"`
	DeviceType      *string `json:"device_type,omitempty"`
	Browser         *string `json:"browser,omitempty"`
	OS              *string `json:"os,omitempty"`
	IPAddress       *string `json:"ip_address,omitempty"`
	LocationCountry *string `json:"location_country,omitempty"`
	LocationCity    *string `json:"location_city,omitempty"`
	IsTrusted       bool    `json:"is_trusted"`
	LastSeenAt      *string `json:"last_seen_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
}
