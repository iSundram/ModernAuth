package tenant

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

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
	Row    int    `json:"row"`
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

	for i, entry := range users {
		// Check if user already exists
		existingUser, err := s.storage.GetUserByEmail(ctx, entry.Email)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, BulkImportError{
				Row:    i + 2, // +2 because 0-index + 1 for header
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
					Row:    i + 2, // +2 because 0-index + 1 for header
					Email:  entry.Email,
					Reason: "Failed to assign existing user to tenant",
				})
				continue
			}

			// Assign requested roles
			for _, roleID := range entry.RoleIDs {
				_ = s.storage.AssignRoleToUserInTenant(ctx, existingUser.ID, roleID, tenantID, nil)
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
					Row:    i + 2, // +2 because 0-index + 1 for header
					Email:  entry.Email,
					Reason: "Failed to create user: " + err.Error(),
				})
				continue
			}

			// Assign requested roles
			for _, roleID := range entry.RoleIDs {
				_ = s.storage.AssignRoleToUserInTenant(ctx, newUser.ID, roleID, tenantID, nil)
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
