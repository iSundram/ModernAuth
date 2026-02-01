// Package audit provides admin audit logging for ModernAuth.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// AdminAction represents types of admin actions.
type AdminAction string

const (
	// Tenant operations
	ActionTenantCreate  AdminAction = "admin.tenant.create"
	ActionTenantUpdate  AdminAction = "admin.tenant.update"
	ActionTenantDelete  AdminAction = "admin.tenant.delete"
	ActionTenantSuspend AdminAction = "admin.tenant.suspend"
	ActionTenantActivate AdminAction = "admin.tenant.activate"

	// User management
	ActionUserCreate       AdminAction = "admin.user.create"
	ActionUserUpdate       AdminAction = "admin.user.update"
	ActionUserDelete       AdminAction = "admin.user.delete"
	ActionUserAssignTenant AdminAction = "admin.user.assign_tenant"
	ActionUserRemoveTenant AdminAction = "admin.user.remove_tenant"
	ActionUserBulkImport   AdminAction = "admin.user.bulk_import"

	// Role management
	ActionRoleCreate     AdminAction = "admin.role.create"
	ActionRoleUpdate     AdminAction = "admin.role.update"
	ActionRoleDelete     AdminAction = "admin.role.delete"
	ActionRoleAssign     AdminAction = "admin.role.assign"
	ActionRoleRevoke     AdminAction = "admin.role.revoke"

	// Permission management
	ActionPermissionCreate AdminAction = "admin.permission.create"
	ActionPermissionUpdate AdminAction = "admin.permission.update"
	ActionPermissionDelete AdminAction = "admin.permission.delete"
	ActionPermissionAssign AdminAction = "admin.permission.assign"
	ActionPermissionRevoke AdminAction = "admin.permission.revoke"

	// API Key management
	ActionAPIKeyCreate AdminAction = "admin.apikey.create"
	ActionAPIKeyRevoke AdminAction = "admin.apikey.revoke"

	// Settings
	ActionSettingsUpdate AdminAction = "admin.settings.update"
	ActionFeaturesUpdate AdminAction = "admin.features.update"

	// Security
	ActionImpersonationStart AdminAction = "admin.impersonation.start"
	ActionImpersonationEnd   AdminAction = "admin.impersonation.end"
	ActionForceLogout        AdminAction = "admin.security.force_logout"
	ActionForcePasswordReset AdminAction = "admin.security.force_password_reset"
)

// AdminAuditLog represents an admin audit log entry.
type AdminAuditLog struct {
	ID          uuid.UUID              `json:"id"`
	ActorID     uuid.UUID              `json:"actor_id"`
	ActorEmail  string                 `json:"actor_email"`
	Action      AdminAction            `json:"action"`
	ResourceType string                `json:"resource_type"`
	ResourceID  *uuid.UUID             `json:"resource_id,omitempty"`
	TenantID    *uuid.UUID             `json:"tenant_id,omitempty"`
	Changes     map[string]interface{} `json:"changes,omitempty"`
	IP          string                 `json:"ip"`
	UserAgent   string                 `json:"user_agent"`
	Success     bool                   `json:"success"`
	ErrorMsg    *string                `json:"error_message,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// Service provides admin audit logging operations.
type Service struct {
	storage storage.Storage
	logger  *slog.Logger
}

// NewService creates a new admin audit service.
func NewService(store storage.Storage) *Service {
	return &Service{
		storage: store,
		logger:  slog.Default().With("component", "admin_audit"),
	}
}

// LogRequest represents a request to create an admin audit log.
type LogRequest struct {
	ActorID      uuid.UUID
	Action       AdminAction
	ResourceType string
	ResourceID   *uuid.UUID
	TenantID     *uuid.UUID
	Changes      map[string]interface{}
	IP           string
	UserAgent    string
	Success      bool
	ErrorMsg     *string
}

// Log creates an admin audit log entry.
func (s *Service) Log(ctx context.Context, req *LogRequest) error {
	// Get actor email for display
	actorEmail := ""
	if actor, err := s.storage.GetUserByID(ctx, req.ActorID); err == nil && actor != nil {
		actorEmail = actor.Email
	}

	log := &storage.AuditLog{
		ID:        uuid.New(),
		ActorID:   &req.ActorID,
		EventType: string(req.Action),
		IP:        &req.IP,
		UserAgent: &req.UserAgent,
		TenantID:  req.TenantID,
		Data: map[string]interface{}{
			"actor_email":   actorEmail,
			"resource_type": req.ResourceType,
			"resource_id":   req.ResourceID,
			"changes":       req.Changes,
			"success":       req.Success,
			"error_message": req.ErrorMsg,
		},
		CreatedAt: time.Now(),
	}

	if req.ResourceID != nil {
		log.UserID = req.ResourceID // Use UserID field for resource tracking
	}

	if err := s.storage.CreateAuditLog(ctx, log); err != nil {
		s.logger.Error("Failed to create admin audit log",
			"action", req.Action,
			"actor_id", req.ActorID,
			"error", err,
		)
		return err
	}

	// Log to structured logger as well
	logLevel := slog.LevelInfo
	if !req.Success {
		logLevel = slog.LevelWarn
	}

	s.logger.Log(ctx, logLevel, "Admin action",
		"action", req.Action,
		"actor_id", req.ActorID,
		"actor_email", actorEmail,
		"resource_type", req.ResourceType,
		"resource_id", req.ResourceID,
		"tenant_id", req.TenantID,
		"success", req.Success,
		"ip", req.IP,
	)

	return nil
}

// LogSuccess is a convenience method for logging successful admin actions.
func (s *Service) LogSuccess(ctx context.Context, actorID uuid.UUID, action AdminAction, resourceType string, resourceID *uuid.UUID, tenantID *uuid.UUID, changes map[string]interface{}, ip, userAgent string) {
	s.Log(ctx, &LogRequest{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		TenantID:     tenantID,
		Changes:      changes,
		IP:           ip,
		UserAgent:    userAgent,
		Success:      true,
	})
}

// LogFailure is a convenience method for logging failed admin actions.
func (s *Service) LogFailure(ctx context.Context, actorID uuid.UUID, action AdminAction, resourceType string, resourceID *uuid.UUID, tenantID *uuid.UUID, errMsg string, ip, userAgent string) {
	s.Log(ctx, &LogRequest{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		TenantID:     tenantID,
		IP:           ip,
		UserAgent:    userAgent,
		Success:      false,
		ErrorMsg:     &errMsg,
	})
}

// ListAdminLogs retrieves admin audit logs with filtering.
func (s *Service) ListAdminLogs(ctx context.Context, filter *AdminLogFilter, limit, offset int) ([]*storage.AuditLog, int, error) {
	// Build filter for admin actions
	eventTypes := []string{
		string(ActionTenantCreate), string(ActionTenantUpdate), string(ActionTenantDelete),
		string(ActionTenantSuspend), string(ActionTenantActivate),
		string(ActionUserCreate), string(ActionUserUpdate), string(ActionUserDelete),
		string(ActionUserAssignTenant), string(ActionUserRemoveTenant), string(ActionUserBulkImport),
		string(ActionRoleCreate), string(ActionRoleUpdate), string(ActionRoleDelete),
		string(ActionRoleAssign), string(ActionRoleRevoke),
		string(ActionAPIKeyCreate), string(ActionAPIKeyRevoke),
		string(ActionSettingsUpdate), string(ActionFeaturesUpdate),
		string(ActionImpersonationStart), string(ActionImpersonationEnd),
	}

	logs, err := s.storage.ListAuditLogsByEventTypes(ctx, eventTypes, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	// Count total for pagination
	count, err := s.storage.CountAuditLogsByEventTypes(ctx, eventTypes)
	if err != nil {
		return nil, 0, err
	}

	return logs, count, nil
}

// AdminLogFilter provides filtering options for admin logs.
type AdminLogFilter struct {
	ActorID   *uuid.UUID
	TenantID  *uuid.UUID
	Action    *AdminAction
	StartTime *time.Time
	EndTime   *time.Time
}
