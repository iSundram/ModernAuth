// Package tenant provides multi-tenancy support for ModernAuth.
package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrTenantNotFound indicates the tenant was not found.
	ErrTenantNotFound = errors.New("tenant not found")
	// ErrTenantExists indicates a tenant with the given slug already exists.
	ErrTenantExists = errors.New("tenant already exists")
	// ErrTenantInactive indicates the tenant is not active.
	ErrTenantInactive = errors.New("tenant is inactive")
	// ErrInvalidTenant indicates an invalid tenant configuration.
	ErrInvalidTenant = errors.New("invalid tenant configuration")
	// ErrUserNotFound indicates the user was not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrPlanLimitExceeded indicates the tenant has reached its user limit.
	ErrPlanLimitExceeded = errors.New("tenant user limit exceeded")
	// ErrAPIKeyNotFound indicates the API key was not found.
	ErrAPIKeyNotFound = errors.New("API key not found")
	// ErrNoDomainConfigured indicates no domain is configured for the tenant.
	ErrNoDomainConfigured = errors.New("no domain configured for tenant")
)

// Service provides tenant management operations.
type Service struct {
	storage storage.Storage
	logger  *slog.Logger
}

// NewService creates a new tenant service.
func NewService(store storage.Storage) *Service {
	return &Service{
		storage: store,
		logger:  slog.Default().With("component", "tenant_service"),
	}
}

// CreateTenantRequest represents a request to create a tenant.
type CreateTenantRequest struct {
	Name     string                 `json:"name"`
	Slug     string                 `json:"slug"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Plan     string                 `json:"plan,omitempty"`
}

// CreateTenant creates a new tenant.
func (s *Service) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*storage.Tenant, error) {
	// Check if slug is already taken
	existing, err := s.storage.GetTenantBySlug(ctx, req.Slug)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrTenantExists
	}

	// Check if domain is already taken
	if req.Domain != nil && *req.Domain != "" {
		existing, err = s.storage.GetTenantByDomain(ctx, *req.Domain)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, ErrTenantExists
		}
	}

	now := time.Now()
	plan := req.Plan
	if plan == "" {
		plan = "free"
	}

	tenant := &storage.Tenant{
		ID:        uuid.New(),
		Name:      req.Name,
		Slug:      req.Slug,
		Domain:    req.Domain,
		LogoURL:   req.LogoURL,
		Settings:  req.Settings,
		Plan:      plan,
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.storage.CreateTenant(ctx, tenant); err != nil {
		return nil, err
	}

	s.logger.Info("Tenant created", "tenant_id", tenant.ID, "slug", tenant.Slug)
	return tenant, nil
}

// GetTenantByID retrieves a tenant by ID.
func (s *Service) GetTenantByID(ctx context.Context, id uuid.UUID) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// GetTenantBySlug retrieves a tenant by slug.
func (s *Service) GetTenantBySlug(ctx context.Context, slug string) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// GetTenantByDomain retrieves a tenant by domain.
func (s *Service) GetTenantByDomain(ctx context.Context, domain string) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

// ListTenants retrieves all tenants with pagination.
func (s *Service) ListTenants(ctx context.Context, limit, offset int) ([]*storage.Tenant, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.ListTenants(ctx, limit, offset)
}

// UpdateTenantRequest represents a request to update a tenant.
type UpdateTenantRequest struct {
	TenantID uuid.UUID              `json:"-"`
	Name     *string                `json:"name,omitempty"`
	Domain   *string                `json:"domain,omitempty"`
	LogoURL  *string                `json:"logo_url,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
	Plan     *string                `json:"plan,omitempty"`
	IsActive *bool                  `json:"is_active,omitempty"`
}

// UpdateTenant updates a tenant.
func (s *Service) UpdateTenant(ctx context.Context, req *UpdateTenantRequest) (*storage.Tenant, error) {
	tenant, err := s.storage.GetTenantByID(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	if req.Name != nil {
		tenant.Name = *req.Name
	}
	if req.Domain != nil {
		// Check if domain is already taken by another tenant
		existing, err := s.storage.GetTenantByDomain(ctx, *req.Domain)
		if err != nil {
			return nil, err
		}
		if existing != nil && existing.ID != tenant.ID {
			return nil, ErrTenantExists
		}
		tenant.Domain = req.Domain
	}
	if req.LogoURL != nil {
		tenant.LogoURL = req.LogoURL
	}
	if req.Settings != nil {
		tenant.Settings = req.Settings
	}
	if req.Plan != nil {
		tenant.Plan = *req.Plan
	}
	if req.IsActive != nil {
		tenant.IsActive = *req.IsActive
	}

	tenant.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
		return nil, err
	}

	return tenant, nil
}

// DeleteTenant deletes a tenant.
func (s *Service) DeleteTenant(ctx context.Context, id uuid.UUID) error {
	tenant, err := s.storage.GetTenantByID(ctx, id)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	if err := s.storage.DeleteTenant(ctx, id); err != nil {
		return err
	}

	s.logger.Info("Tenant deleted", "tenant_id", id, "slug", tenant.Slug)
	return nil
}

// GetTenantStats retrieves statistics for a tenant.
func (s *Service) GetTenantStats(ctx context.Context, tenantID uuid.UUID) (*TenantStats, error) {
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, ErrTenantNotFound
	}

	userCount, err := s.storage.CountTenantUsers(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &TenantStats{
		TenantID:  tenantID,
		UserCount: userCount,
		Plan:      tenant.Plan,
		MaxUsers:  getPlanMaxUsers(tenant.Plan),
	}, nil
}

// TenantStats represents statistics for a tenant.
type TenantStats struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	UserCount int       `json:"user_count"`
	Plan      string    `json:"plan"`
	MaxUsers  int       `json:"max_users"`
}

// getPlanMaxUsers returns the soft user limit for a given plan.
// A value of 0 means "unlimited" (no enforced limit).
func getPlanMaxUsers(plan string) int {
	switch plan {
	case "free":
		return 5
	case "starter":
		return 20
	case "professional":
		return 100
	case "enterprise":
		return 0
	default:
		return 0
	}
}

// TenantSecurityStats represents security posture for a tenant.
type TenantSecurityStats struct {
	TenantID              uuid.UUID `json:"tenant_id"`
	TotalUsers            int       `json:"total_users"`
	ActiveUsers           int       `json:"active_users"`
	VerifiedUsers         int       `json:"verified_users"`
	MFAEnabledUsers       int       `json:"mfa_enabled_users"`
	TOTPEnabledUsers      int       `json:"totp_enabled_users"`
	EmailMFAEnabledUsers  int       `json:"email_mfa_enabled_users"`
	WebAuthnUsers         int       `json:"webauthn_users"`
	UsersWithTrustedDevice int      `json:"users_with_trusted_device"`
	RecentFailedLogins    int       `json:"recent_failed_logins"`
	RecentLockouts        int       `json:"recent_lockouts"`
}

// GetTenantSecurityStats computes security-related statistics for a tenant.
func (s *Service) GetTenantSecurityStats(ctx context.Context, tenantID uuid.UUID) (*TenantSecurityStats, error) {
	// Reuse ListTenantUsers; for now we fetch up to 1000 users per tenant.
	const maxUsersPerTenant = 1000

	users, err := s.storage.ListTenantUsers(ctx, tenantID, maxUsersPerTenant, 0)
	if err != nil {
		return nil, err
	}

	stats := &TenantSecurityStats{
		TenantID:   tenantID,
		TotalUsers: len(users),
	}

	// Track which users have at least one trusted device.
	usersWithTrusted := make(map[uuid.UUID]struct{})

	for _, u := range users {
		if u.IsActive {
			stats.ActiveUsers++
		}
		if u.IsEmailVerified {
			stats.VerifiedUsers++
		}

		// MFA settings per user
		mfaSettings, err := s.storage.GetMFASettings(ctx, u.ID)
		if err != nil {
			// Log and continue; a single failure shouldn't break the whole stats call.
			s.logger.Warn("Failed to load MFA settings for tenant security stats",
				"user_id", u.ID, "tenant_id", tenantID, "error", err)
		} else if mfaSettings != nil {
			if mfaSettings.IsTOTPEnabled {
				stats.TOTPEnabledUsers++
				stats.MFAEnabledUsers++
			}
			if mfaSettings.IsEmailMFAEnabled {
				stats.EmailMFAEnabledUsers++
				stats.MFAEnabledUsers++
			}
			// WebAuthn presence is approximated via credentials count below.
		}

		// Trusted devices per user (best-effort; ignore errors)
		if devices, err := s.storage.ListUserDevices(ctx, u.ID); err == nil {
			for _, d := range devices {
				if d.IsTrusted {
					usersWithTrusted[u.ID] = struct{}{}
					break
				}
			}
		}

		// WebAuthn credentials per user (best-effort)
		if creds, err := s.storage.GetWebAuthnCredentials(ctx, u.ID); err == nil && len(creds) > 0 {
			stats.WebAuthnUsers++
		}
	}

	stats.UsersWithTrustedDevice = len(usersWithTrusted)

	// Recent failed logins / lockouts can be derived from login_history and audit_logs.
	// For now, we count failed login_history entries in the last 7 days for this tenant.
	// This keeps the implementation data-source-agnostic: storage can provide a helper
	// without changing the HTTP surface.
	sevenDaysAgo := time.Now().Add(-7 * 24 * time.Hour)
	if logs, err := s.storage.ListAuditLogsByTenant(ctx, tenantID, 1000, 0); err == nil {
		for _, log := range logs {
			if log.CreatedAt.Before(sevenDaysAgo) {
				continue
			}
			switch {
			case strings.Contains(log.EventType, "login.failed"):
				stats.RecentFailedLogins++
			case strings.Contains(log.EventType, "account_locked") || strings.Contains(log.EventType, "mfa_locked"):
				stats.RecentLockouts++
			}
		}
	}

	return stats, nil
}

// ResolveTenant resolves a tenant from various identifiers.
func (s *Service) ResolveTenant(ctx context.Context, identifier string) (*storage.Tenant, error) {
	// Try as UUID first
	if id, err := uuid.Parse(identifier); err == nil {
		return s.GetTenantByID(ctx, id)
	}

	// Try as slug
	tenant, err := s.storage.GetTenantBySlug(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		return tenant, nil
	}

	// Try as domain
	tenant, err = s.storage.GetTenantByDomain(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if tenant != nil {
		return tenant, nil
	}

	return nil, ErrTenantNotFound
}

// ListTenantUsers lists users in a tenant.
func (s *Service) ListTenantUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*storage.User, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return s.storage.ListTenantUsers(ctx, tenantID, limit, offset)
}

// AssignUserToTenant assigns a user to a tenant.
func (s *Service) AssignUserToTenant(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Verify tenant exists
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	// Verify user exists
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Update user's tenant_id
	user.TenantID = &tenantID
	user.UpdatedAt = time.Now()
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	s.logger.Info("User assigned to tenant", "user_id", userID, "tenant_id", tenantID)
	return nil
}

// RemoveUserFromTenant removes a user from a tenant.
func (s *Service) RemoveUserFromTenant(ctx context.Context, tenantID, userID uuid.UUID) error {
	// Verify tenant exists
	tenant, err := s.storage.GetTenantByID(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant == nil {
		return ErrTenantNotFound
	}

	// Verify user exists and belongs to this tenant
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Check if user belongs to this tenant
	if user.TenantID == nil || *user.TenantID != tenantID {
		return ErrUserNotFound // User doesn't belong to this tenant
	}

	// Remove user from tenant by setting tenant_id to nil
	user.TenantID = nil
	user.UpdatedAt = time.Now()
	if err := s.storage.UpdateUser(ctx, user); err != nil {
		return err
	}

	s.logger.Info("User removed from tenant", "user_id", userID, "tenant_id", tenantID)
	return nil
}

// IsUserTenantMember checks if a user belongs to or can manage a tenant.
// Returns true if the user is a member of the tenant or has admin privileges.
func (s *Service) IsUserTenantMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	// Get user to check their tenant membership
	user, err := s.storage.GetUserByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, ErrUserNotFound
	}

	// Check if user belongs to this tenant
	if user.TenantID != nil && *user.TenantID == tenantID {
		return true, nil
	}

	// Check if user has admin role (admins can manage all tenants)
	roles, err := s.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if role.Name == "admin" || role.Name == "super_admin" {
			return true, nil
		}
	}

	return false, nil
}

// IsUserTenantAdmin checks if a user has admin privileges for a specific tenant.
func (s *Service) IsUserTenantAdmin(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	// First check if user is a member
	isMember, err := s.IsUserTenantMember(ctx, userID, tenantID)
	if err != nil {
		return false, err
	}
	if !isMember {
		return false, nil
	}

	// Check if user has admin role
	roles, err := s.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, role := range roles {
		if role.Name == "admin" || role.Name == "super_admin" || role.Name == "tenant_admin" {
			return true, nil
		}
	}

	return false, nil
}

// SuspendTenant suspends a tenant, preventing access.
func (s *Service) SuspendTenant(ctx context.Context, tenantID uuid.UUID) error {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return err
}
if tenant == nil {
return ErrTenantNotFound
}

tenant.IsActive = false
tenant.UpdatedAt = time.Now()

if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
return err
}

s.logger.Info("Tenant suspended", "tenant_id", tenantID)
return nil
}

// ActivateTenant activates a suspended tenant.
func (s *Service) ActivateTenant(ctx context.Context, tenantID uuid.UUID) error {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return err
}
if tenant == nil {
return ErrTenantNotFound
}

tenant.IsActive = true
tenant.UpdatedAt = time.Now()

if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
return err
}

s.logger.Info("Tenant activated", "tenant_id", tenantID)
return nil
}

// CheckPlanLimit checks if adding users would exceed the plan limit.
func (s *Service) CheckPlanLimit(ctx context.Context, tenantID uuid.UUID, additionalUsers int) error {
stats, err := s.GetTenantStats(ctx, tenantID)
if err != nil {
return err
}

// 0 means unlimited
if stats.MaxUsers == 0 {
return nil
}

if stats.UserCount+additionalUsers > stats.MaxUsers {
return ErrPlanLimitExceeded
}

return nil
}

// ExportAuditLogs exports audit logs for a tenant in the specified format.
func (s *Service) ExportAuditLogs(ctx context.Context, tenantID uuid.UUID, format string) ([]byte, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

// Fetch audit logs for this tenant (up to 10000 for export)
logs, err := s.storage.ListAuditLogsByTenant(ctx, tenantID, 10000, 0)
if err != nil {
return nil, err
}

if format == "csv" {
return s.exportAuditLogsCSV(logs)
}
return s.exportAuditLogsJSON(logs)
}

func (s *Service) exportAuditLogsCSV(logs []*storage.AuditLog) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Header
	writer.Write([]string{"ID", "TenantID", "UserID", "ActorID", "EventType", "IP", "UserAgent", "CreatedAt"})

	for _, log := range logs {
		tenantID := ""
		if log.TenantID != nil {
			tenantID = log.TenantID.String()
		}
		userID := ""
		if log.UserID != nil {
			userID = log.UserID.String()
		}
		actorID := ""
		if log.ActorID != nil {
			actorID = log.ActorID.String()
		}
		ipAddr := ""
		if log.IP != nil {
			ipAddr = *log.IP
		}
		userAgent := ""
		if log.UserAgent != nil {
			userAgent = *log.UserAgent
		}

		writer.Write([]string{
			log.ID.String(),
			tenantID,
			userID,
			actorID,
			log.EventType,
			ipAddr,
			userAgent,
			log.CreatedAt.Format(time.RFC3339),
		})
	}

	writer.Flush()
	return []byte(buf.String()), nil
}

func (s *Service) exportAuditLogsJSON(logs []*storage.AuditLog) ([]byte, error) {
return json.MarshalIndent(logs, "", "  ")
}

// TenantAPIKey represents an API key for a tenant.
type TenantAPIKey struct {
ID         uuid.UUID  `json:"id"`
TenantID   uuid.UUID  `json:"tenant_id"`
Name       string     `json:"name"`
KeyHash    string     `json:"-"`
KeyPrefix  string     `json:"key_prefix"`
Scopes     []string   `json:"scopes,omitempty"`
ExpiresAt  *time.Time `json:"expires_at,omitempty"`
LastUsedAt *time.Time `json:"last_used_at,omitempty"`
CreatedAt  time.Time  `json:"created_at"`
}

// CreateAPIKeyRequest represents a request to create an API key.
type CreateAPIKeyRequest struct {
Name      string   `json:"name"`
Scopes    []string `json:"scopes,omitempty"`
ExpiresIn *int     `json:"expires_in,omitempty"` // seconds
}

// CreateAPIKeyResult contains the created key and raw key (shown once).
type CreateAPIKeyResult struct {
APIKey *TenantAPIKey
RawKey string
}

// ListAPIKeys lists API keys for a tenant.
func (s *Service) ListAPIKeys(ctx context.Context, tenantID uuid.UUID) ([]*TenantAPIKey, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

// Get API keys from settings (stored as JSON array)
keys := s.getAPIKeysFromSettings(tenant.Settings)
return keys, nil
}

// CreateAPIKey creates a new API key for a tenant.
func (s *Service) CreateAPIKey(ctx context.Context, tenantID uuid.UUID, req *CreateAPIKeyRequest) (*CreateAPIKeyResult, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

// Generate a secure random key
rawKey := generateAPIKey()
keyHash := hashAPIKey(rawKey)
keyPrefix := rawKey[:8] + "..."

now := time.Now()
var expiresAt *time.Time
if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
exp := now.Add(time.Duration(*req.ExpiresIn) * time.Second)
expiresAt = &exp
}

apiKey := &TenantAPIKey{
ID:        uuid.New(),
TenantID:  tenantID,
Name:      req.Name,
KeyHash:   keyHash,
KeyPrefix: keyPrefix,
Scopes:    req.Scopes,
ExpiresAt: expiresAt,
CreatedAt: now,
}

// Store in tenant settings
if err := s.addAPIKeyToSettings(ctx, tenant, apiKey); err != nil {
return nil, err
}

s.logger.Info("API key created", "tenant_id", tenantID, "key_id", apiKey.ID, "name", req.Name)

return &CreateAPIKeyResult{
APIKey: apiKey,
RawKey: rawKey,
}, nil
}

// RevokeAPIKey revokes an API key.
func (s *Service) RevokeAPIKey(ctx context.Context, tenantID, keyID uuid.UUID) error {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return err
}
if tenant == nil {
return ErrTenantNotFound
}

if err := s.removeAPIKeyFromSettings(ctx, tenant, keyID); err != nil {
return err
}

s.logger.Info("API key revoked", "tenant_id", tenantID, "key_id", keyID)
return nil
}

func generateAPIKey() string {
bytes := make([]byte, 32)
rand.Read(bytes)
return "ma_" + hex.EncodeToString(bytes)
}

func hashAPIKey(key string) string {
hash := sha256.Sum256([]byte(key))
return hex.EncodeToString(hash[:])
}

func (s *Service) getAPIKeysFromSettings(settings map[string]interface{}) []*TenantAPIKey {
keysData, ok := settings["api_keys"]
if !ok {
return []*TenantAPIKey{}
}

keysJSON, err := json.Marshal(keysData)
if err != nil {
return []*TenantAPIKey{}
}

var keys []*TenantAPIKey
if err := json.Unmarshal(keysJSON, &keys); err != nil {
return []*TenantAPIKey{}
}
return keys
}

func (s *Service) addAPIKeyToSettings(ctx context.Context, tenant *storage.Tenant, key *TenantAPIKey) error {
keys := s.getAPIKeysFromSettings(tenant.Settings)
keys = append(keys, key)

if tenant.Settings == nil {
tenant.Settings = make(map[string]interface{})
}
tenant.Settings["api_keys"] = keys
tenant.UpdatedAt = time.Now()

return s.storage.UpdateTenant(ctx, tenant)
}

func (s *Service) removeAPIKeyFromSettings(ctx context.Context, tenant *storage.Tenant, keyID uuid.UUID) error {
keys := s.getAPIKeysFromSettings(tenant.Settings)
found := false
newKeys := make([]*TenantAPIKey, 0, len(keys))
for _, k := range keys {
if k.ID != keyID {
newKeys = append(newKeys, k)
} else {
found = true
}
}

if !found {
return ErrAPIKeyNotFound
}

if tenant.Settings == nil {
tenant.Settings = make(map[string]interface{})
}
tenant.Settings["api_keys"] = newKeys
tenant.UpdatedAt = time.Now()

return s.storage.UpdateTenant(ctx, tenant)
}

// DomainVerificationResult represents domain verification status.
type DomainVerificationResult struct {
Domain     string     `json:"domain"`
TXTRecord  string     `json:"txt_record"`
Status     string     `json:"status"` // pending, verified, failed
VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// InitiateDomainVerification starts domain verification for a tenant.
func (s *Service) InitiateDomainVerification(ctx context.Context, tenantID uuid.UUID) (*DomainVerificationResult, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

if tenant.Domain == nil || *tenant.Domain == "" {
return nil, ErrNoDomainConfigured
}

// Generate verification token if not exists
verificationToken := s.getOrCreateVerificationToken(tenant)

// Update tenant settings with verification token
if tenant.Settings == nil {
tenant.Settings = make(map[string]interface{})
}
tenant.Settings["domain_verification_token"] = verificationToken
tenant.Settings["domain_verification_status"] = "pending"
tenant.UpdatedAt = time.Now()

if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
return nil, err
}

return &DomainVerificationResult{
Domain:    *tenant.Domain,
TXTRecord: fmt.Sprintf("modernauth-verify=%s", verificationToken),
Status:    "pending",
}, nil
}

// CheckDomainVerification checks domain verification status.
func (s *Service) CheckDomainVerification(ctx context.Context, tenantID uuid.UUID) (*DomainVerificationResult, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

if tenant.Domain == nil || *tenant.Domain == "" {
return nil, ErrNoDomainConfigured
}

token, _ := tenant.Settings["domain_verification_token"].(string)
status, _ := tenant.Settings["domain_verification_status"].(string)

result := &DomainVerificationResult{
Domain:    *tenant.Domain,
TXTRecord: fmt.Sprintf("modernauth-verify=%s", token),
Status:    status,
}

// If already verified, return
if status == "verified" {
if verifiedAtStr, ok := tenant.Settings["domain_verified_at"].(string); ok {
if t, err := time.Parse(time.RFC3339, verifiedAtStr); err == nil {
result.VerifiedAt = &t
}
}
return result, nil
}

// Perform DNS TXT lookup
expectedRecord := fmt.Sprintf("modernauth-verify=%s", token)
txtRecords, err := net.LookupTXT("_modernauth." + *tenant.Domain)
if err != nil {
result.Status = "pending"
return result, nil
}

for _, txt := range txtRecords {
if txt == expectedRecord {
// Verified!
now := time.Now()
tenant.Settings["domain_verification_status"] = "verified"
tenant.Settings["domain_verified_at"] = now.Format(time.RFC3339)
tenant.UpdatedAt = now

if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
s.logger.Error("Failed to update domain verification status", "error", err)
}

result.Status = "verified"
result.VerifiedAt = &now
s.logger.Info("Domain verified", "tenant_id", tenantID, "domain", *tenant.Domain)
return result, nil
}
}

result.Status = "pending"
return result, nil
}

func (s *Service) getOrCreateVerificationToken(tenant *storage.Tenant) string {
if token, ok := tenant.Settings["domain_verification_token"].(string); ok && token != "" {
return token
}

bytes := make([]byte, 16)
rand.Read(bytes)
return hex.EncodeToString(bytes)
}

// BulkUserEntry represents a single user in bulk import.
type BulkUserEntry struct {
Email     string      `json:"email"`
FirstName *string     `json:"first_name,omitempty"`
LastName  *string     `json:"last_name,omitempty"`
RoleIDs   []uuid.UUID `json:"role_ids,omitempty"`
}

// BulkImportResult represents the result of a bulk import.
type BulkImportResult struct {
Total     int               `json:"total"`
Succeeded int               `json:"succeeded"`
Failed    int               `json:"failed"`
Errors    []BulkImportError `json:"errors,omitempty"`
}

// BulkImportError represents an error for a specific user.
type BulkImportError struct {
Email  string `json:"email"`
Reason string `json:"reason"`
}

// BulkImportUsers imports multiple users to a tenant.
func (s *Service) BulkImportUsers(ctx context.Context, tenantID uuid.UUID, users []BulkUserEntry) (*BulkImportResult, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

// Check plan limit
if err := s.CheckPlanLimit(ctx, tenantID, len(users)); err != nil {
return nil, err
}

result := &BulkImportResult{
Total:  len(users),
Errors: []BulkImportError{},
}

for _, entry := range users {
// Check if user already exists
existingUser, err := s.storage.GetUserByEmail(ctx, entry.Email)
if err != nil {
result.Failed++
result.Errors = append(result.Errors, BulkImportError{
Email:  entry.Email,
Reason: "Failed to check existing user",
})
continue
}

if existingUser != nil {
// User exists, assign to tenant
existingUser.TenantID = &tenantID
existingUser.UpdatedAt = time.Now()
if err := s.storage.UpdateUser(ctx, existingUser); err != nil {
result.Failed++
result.Errors = append(result.Errors, BulkImportError{
Email:  entry.Email,
Reason: "Failed to assign existing user to tenant",
})
continue
}
} else {
// Create new user with invitation flow
// For bulk import, we just create placeholder users that need to be activated
newUser := &storage.User{
ID:        uuid.New(),
Email:     entry.Email,
FirstName: entry.FirstName,
LastName:  entry.LastName,
TenantID:  &tenantID,
IsActive:  false, // Needs activation via invitation
CreatedAt: time.Now(),
UpdatedAt: time.Now(),
}

if err := s.storage.CreateUser(ctx, newUser); err != nil {
result.Failed++
result.Errors = append(result.Errors, BulkImportError{
Email:  entry.Email,
Reason: "Failed to create user: " + err.Error(),
})
continue
}
}

result.Succeeded++
}

s.logger.Info("Bulk import completed",
"tenant_id", tenantID,
"total", result.Total,
"succeeded", result.Succeeded,
"failed", result.Failed)

return result, nil
}

// TenantFeatures represents feature flags for a tenant.
type TenantFeatures struct {
SSOEnabled       bool `json:"sso_enabled"`
APIAccessEnabled bool `json:"api_access_enabled"`
WebhooksEnabled  bool `json:"webhooks_enabled"`
MFARequired      bool `json:"mfa_required"`
CustomBranding   bool `json:"custom_branding"`
}

// UpdateFeaturesRequest represents a request to update feature flags.
type UpdateFeaturesRequest struct {
SSOEnabled       *bool `json:"sso_enabled,omitempty"`
APIAccessEnabled *bool `json:"api_access_enabled,omitempty"`
WebhooksEnabled  *bool `json:"webhooks_enabled,omitempty"`
MFARequired      *bool `json:"mfa_required,omitempty"`
CustomBranding   *bool `json:"custom_branding,omitempty"`
}

// GetFeatures retrieves feature flags for a tenant.
func (s *Service) GetFeatures(ctx context.Context, tenantID uuid.UUID) (*TenantFeatures, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

return s.extractFeaturesFromSettings(tenant.Settings), nil
}

// UpdateFeatures updates feature flags for a tenant.
func (s *Service) UpdateFeatures(ctx context.Context, tenantID uuid.UUID, req *UpdateFeaturesRequest) (*TenantFeatures, error) {
tenant, err := s.storage.GetTenantByID(ctx, tenantID)
if err != nil {
return nil, err
}
if tenant == nil {
return nil, ErrTenantNotFound
}

if tenant.Settings == nil {
tenant.Settings = make(map[string]interface{})
}

features := s.extractFeaturesFromSettings(tenant.Settings)

if req.SSOEnabled != nil {
features.SSOEnabled = *req.SSOEnabled
}
if req.APIAccessEnabled != nil {
features.APIAccessEnabled = *req.APIAccessEnabled
}
if req.WebhooksEnabled != nil {
features.WebhooksEnabled = *req.WebhooksEnabled
}
if req.MFARequired != nil {
features.MFARequired = *req.MFARequired
}
if req.CustomBranding != nil {
features.CustomBranding = *req.CustomBranding
}

// Store features in settings
tenant.Settings["features"] = map[string]interface{}{
"sso_enabled":        features.SSOEnabled,
"api_access_enabled": features.APIAccessEnabled,
"webhooks_enabled":   features.WebhooksEnabled,
"mfa_required":       features.MFARequired,
"custom_branding":    features.CustomBranding,
}
tenant.UpdatedAt = time.Now()

if err := s.storage.UpdateTenant(ctx, tenant); err != nil {
return nil, err
}

s.logger.Info("Tenant features updated", "tenant_id", tenantID)
return features, nil
}

func (s *Service) extractFeaturesFromSettings(settings map[string]interface{}) *TenantFeatures {
features := &TenantFeatures{
SSOEnabled:       false,
APIAccessEnabled: true, // Default enabled
WebhooksEnabled:  true, // Default enabled
MFARequired:      false,
CustomBranding:   false,
}

if settings == nil {
return features
}

featuresData, ok := settings["features"].(map[string]interface{})
if !ok {
return features
}

if v, ok := featuresData["sso_enabled"].(bool); ok {
features.SSOEnabled = v
}
if v, ok := featuresData["api_access_enabled"].(bool); ok {
features.APIAccessEnabled = v
}
if v, ok := featuresData["webhooks_enabled"].(bool); ok {
features.WebhooksEnabled = v
}
if v, ok := featuresData["mfa_required"].(bool); ok {
features.MFARequired = v
}
if v, ok := featuresData["custom_branding"].(bool); ok {
features.CustomBranding = v
}

return features
}
