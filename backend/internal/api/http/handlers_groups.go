// Package http provides group management HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/groups"
	"github.com/iSundram/ModernAuth/internal/storage"
	tenantpkg "github.com/iSundram/ModernAuth/internal/tenant"
)

// GroupHandler provides HTTP handlers for group management.
type GroupHandler struct {
	groupService *groups.Service
}

// NewGroupHandler creates a new group handler.
func NewGroupHandler(service *groups.Service) *GroupHandler {
	return &GroupHandler{groupService: service}
}

// GroupRoutes returns chi routes for group management.
func (h *GroupHandler) GroupRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListGroups)
	r.Post("/", h.CreateGroup)
	r.Get("/{id}", h.GetGroup)
	r.Put("/{id}", h.UpdateGroup)
	r.Delete("/{id}", h.DeleteGroup)
	r.Get("/{id}/members", h.ListMembers)
	r.Post("/{id}/members", h.AddMember)
	r.Delete("/{id}/members/{userId}", h.RemoveMember)

	return r
}

// CreateGroupRequest represents the request to create a group.
type CreateGroupRequest struct {
	Name        string  `json:"name" validate:"required,min=1,max=100"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=500"`
}

// UpdateGroupRequest represents the request to update a group.
type UpdateGroupRequest struct {
	Name        string  `json:"name" validate:"required,min=1,max=100"`
	Description *string `json:"description,omitempty" validate:"omitempty,max=500"`
}

// AddMemberRequest represents the request to add a member to a group.
type AddMemberRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Role   string `json:"role,omitempty" validate:"omitempty,oneof=owner admin member"`
}

// GroupResponse represents a group in API responses.
type GroupResponse struct {
	ID          string  `json:"id"`
	TenantID    *string `json:"tenant_id,omitempty"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// GroupMemberResponse represents a group member in API responses.
type GroupMemberResponse struct {
	UserID   string `json:"user_id"`
	GroupID  string `json:"group_id"`
	Role     string `json:"role"`
	JoinedAt string `json:"joined_at"`
}

// CreateGroup creates a new group.
func (h *GroupHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	tenantID := tenantpkg.GetTenantIDFromContext(r.Context())

	group, err := h.groupService.Create(r.Context(), req.Name, req.Description, tenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to create group", err)
		return
	}

	writeJSON(w, http.StatusCreated, h.toGroupResponse(group))
}

// GetGroup retrieves a group by ID.
func (h *GroupHandler) GetGroup(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	group, err := h.groupService.GetByID(r.Context(), id)
	if err != nil {
		if err == groups.ErrGroupNotFound {
			writeError(w, http.StatusNotFound, "Group not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get group", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toGroupResponse(group))
}

// ListGroups lists groups with optional tenant filter and pagination.
func (h *GroupHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantpkg.GetTenantIDFromContext(r.Context())
	limit, offset := parsePagination(r)

	groupList, err := h.groupService.List(r.Context(), tenantID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list groups", err)
		return
	}

	response := make([]GroupResponse, len(groupList))
	for i, g := range groupList {
		response[i] = h.toGroupResponse(g)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

// UpdateGroup updates a group.
func (h *GroupHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	var req UpdateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	group, err := h.groupService.Update(r.Context(), id, req.Name, req.Description)
	if err != nil {
		if err == groups.ErrGroupNotFound {
			writeError(w, http.StatusNotFound, "Group not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to update group", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toGroupResponse(group))
}

// DeleteGroup deletes a group.
func (h *GroupHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	if err := h.groupService.Delete(r.Context(), id); err != nil {
		if err == groups.ErrGroupNotFound {
			writeError(w, http.StatusNotFound, "Group not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete group", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AddMember adds a member to a group.
func (h *GroupHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if errors := ValidateStruct(req); errors != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "Validation failed",
			"details": errors,
		})
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	if err := h.groupService.AddMember(r.Context(), groupID, userID, req.Role); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to add member", err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Member added to group",
	})
}

// RemoveMember removes a member from a group.
func (h *GroupHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	userIDStr := chi.URLParam(r, "userId")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	if err := h.groupService.RemoveMember(r.Context(), groupID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to remove member", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ListMembers lists members of a group.
func (h *GroupHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid group ID", err)
		return
	}

	limit, offset := parsePagination(r)

	members, err := h.groupService.ListMembers(r.Context(), groupID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list members", err)
		return
	}

	response := make([]GroupMemberResponse, len(members))
	for i, m := range members {
		response[i] = GroupMemberResponse{
			UserID:   m.UserID.String(),
			GroupID:  m.GroupID.String(),
			Role:     m.Role,
			JoinedAt: m.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *GroupHandler) toGroupResponse(g *storage.UserGroup) GroupResponse {
	resp := GroupResponse{
		ID:          g.ID.String(),
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   g.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:   g.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if g.TenantID != nil {
		tid := g.TenantID.String()
		resp.TenantID = &tid
	}
	return resp
}
