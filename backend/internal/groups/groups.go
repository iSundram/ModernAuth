// Package groups provides user group management for ModernAuth.
package groups

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrGroupNotFound indicates the group was not found.
	ErrGroupNotFound = errors.New("group not found")
	// ErrGroupExists indicates a group with that name already exists.
	ErrGroupExists = errors.New("group already exists")
	// ErrMemberNotFound indicates the member was not found in the group.
	ErrMemberNotFound = errors.New("member not found")
	// ErrAlreadyMember indicates the user is already a member of the group.
	ErrAlreadyMember = errors.New("user is already a member")
)

// Service provides group management operations.
type Service struct {
	storage storage.UserGroupStorage
}

// NewService creates a new groups service.
func NewService(storage storage.UserGroupStorage) *Service {
	return &Service{storage: storage}
}

// Create creates a new group.
func (s *Service) Create(ctx context.Context, name string, description *string, tenantID *uuid.UUID) (*storage.UserGroup, error) {
	group := &storage.UserGroup{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.storage.CreateGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

// GetByID retrieves a group by ID.
func (s *Service) GetByID(ctx context.Context, id uuid.UUID) (*storage.UserGroup, error) {
	group, err := s.storage.GetGroupByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, ErrGroupNotFound
	}
	return group, nil
}

// List retrieves groups with optional tenant filter and pagination.
func (s *Service) List(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.UserGroup, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.ListGroups(ctx, tenantID, limit, offset)
}

// Update updates a group's details.
func (s *Service) Update(ctx context.Context, id uuid.UUID, name string, description *string) (*storage.UserGroup, error) {
	group, err := s.storage.GetGroupByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if group == nil {
		return nil, ErrGroupNotFound
	}

	group.Name = name
	group.Description = description
	group.UpdatedAt = time.Now()

	if err := s.storage.UpdateGroup(ctx, group); err != nil {
		return nil, err
	}
	return group, nil
}

// Delete deletes a group.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	group, err := s.storage.GetGroupByID(ctx, id)
	if err != nil {
		return err
	}
	if group == nil {
		return ErrGroupNotFound
	}
	return s.storage.DeleteGroup(ctx, id)
}

// AddMember adds a user to a group with a given role.
func (s *Service) AddMember(ctx context.Context, groupID, userID uuid.UUID, role string) error {
	if role == "" {
		role = "member"
	}
	return s.storage.AddUserToGroup(ctx, userID, groupID, role)
}

// RemoveMember removes a user from a group.
func (s *Service) RemoveMember(ctx context.Context, groupID, userID uuid.UUID) error {
	return s.storage.RemoveUserFromGroup(ctx, userID, groupID)
}

// ListMembers lists all members of a group with pagination.
func (s *Service) ListMembers(ctx context.Context, groupID uuid.UUID, limit, offset int) ([]*storage.UserGroupMember, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.GetGroupMembers(ctx, groupID, limit, offset)
}

// ListUserGroups lists all groups a user belongs to.
func (s *Service) ListUserGroups(ctx context.Context, userID uuid.UUID) ([]*storage.UserGroup, error) {
	return s.storage.GetUserGroups(ctx, userID)
}
