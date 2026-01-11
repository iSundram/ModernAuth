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
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Username        *string `json:"username,omitempty"`
	IsEmailVerified bool    `json:"is_email_verified"`
	CreatedAt       string  `json:"created_at"`
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
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// AssignUserRoleRequest represents the assign role request body.
type AssignUserRoleRequest struct {
	RoleID string `json:"role_id" validate:"required,uuid"`
}
