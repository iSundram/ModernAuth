// Package http provides invitation HTTP handlers for ModernAuth API.
package http

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/invitation"
	"github.com/iSundram/ModernAuth/internal/storage"
	tenantpkg "github.com/iSundram/ModernAuth/internal/tenant"
)

// InvitationHandler provides HTTP handlers for invitation management.
type InvitationHandler struct {
	invitationService *invitation.Service
}

// NewInvitationHandler creates a new invitation handler.
func NewInvitationHandler(service *invitation.Service) *InvitationHandler {
	return &InvitationHandler{invitationService: service}
}

// InvitationRoutes returns chi routes for invitation management.
func (h *InvitationHandler) InvitationRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListInvitations)
	r.Post("/", h.CreateInvitation)
	r.Get("/{id}", h.GetInvitation)
	r.Delete("/{id}", h.DeleteInvitation)
	r.Post("/{id}/resend", h.ResendInvitation)

	return r
}

// PublicInvitationRoutes returns chi routes for public invitation endpoints.
func (h *InvitationHandler) PublicInvitationRoutes() chi.Router {
	r := chi.NewRouter()

	r.Post("/validate", h.ValidateInvitation)
	r.Post("/accept", h.AcceptInvitation)

	return r
}

// CreateInvitationRequest represents the request to create an invitation.
type CreateInvitationRequest struct {
	Email     string      `json:"email" validate:"required,email"`
	FirstName *string     `json:"first_name,omitempty"`
	LastName  *string     `json:"last_name,omitempty"`
	RoleIDs   []uuid.UUID `json:"role_ids,omitempty"`
	GroupIDs  []uuid.UUID `json:"group_ids,omitempty"`
	Message   *string     `json:"message,omitempty"`
	ExpiresIn *int        `json:"expires_in,omitempty"` // seconds
}

// InvitationResponse represents an invitation in API responses.
type InvitationResponse struct {
	ID         string      `json:"id"`
	Email      string      `json:"email"`
	FirstName  *string     `json:"first_name,omitempty"`
	LastName   *string     `json:"last_name,omitempty"`
	RoleIDs    []uuid.UUID `json:"role_ids,omitempty"`
	Status     string      `json:"status"` // pending, accepted, expired
	ExpiresAt  string      `json:"expires_at"`
	AcceptedAt *string     `json:"accepted_at,omitempty"`
	CreatedAt  string      `json:"created_at"`
}

// CreateInvitation creates a new invitation.
func (h *InvitationHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	var req CreateInvitationRequest
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

	// Get inviter ID from context
	userIDStr, _ := r.Context().Value(userIDKey).(string)
	var invitedBy *uuid.UUID
	if uid, err := uuid.Parse(userIDStr); err == nil {
		invitedBy = &uid
	}

	// Get tenant ID from context
	tenantID := tenantpkg.GetTenantIDFromContext(r.Context())

	result, err := h.invitationService.CreateInvitation(r.Context(), &invitation.CreateInvitationRequest{
		TenantID:  tenantID,
		Email:     req.Email,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		RoleIDs:   req.RoleIDs,
		GroupIDs:  req.GroupIDs,
		Message:   req.Message,
		InvitedBy: invitedBy,
		ExpiresIn: req.ExpiresIn,
	})

	if err != nil {
		switch err {
		case invitation.ErrUserAlreadyExists:
			writeError(w, http.StatusConflict, "User with this email already exists", err)
		case invitation.ErrInvitationExists:
			writeError(w, http.StatusConflict, "Invitation already exists for this email", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to create invitation", err)
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"invitation": h.toInvitationResponse(result.Invitation),
		"token":      result.Token, // Include token for testing/development
	})
}

// GetInvitation retrieves an invitation by ID.
func (h *InvitationHandler) GetInvitation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid invitation ID", err)
		return
	}

	inv, err := h.invitationService.GetInvitation(r.Context(), id)
	if err != nil {
		if err == invitation.ErrInvitationNotFound {
			writeError(w, http.StatusNotFound, "Invitation not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get invitation", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toInvitationResponse(inv))
}

// ListInvitations lists invitations.
func (h *InvitationHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	tenantID := tenantpkg.GetTenantIDFromContext(r.Context())
	limit, offset := parsePagination(r)

	invitations, err := h.invitationService.ListInvitations(r.Context(), tenantID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list invitations", err)
		return
	}

	response := make([]InvitationResponse, len(invitations))
	for i, inv := range invitations {
		response[i] = h.toInvitationResponse(inv)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

// DeleteInvitation deletes an invitation.
func (h *InvitationHandler) DeleteInvitation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid invitation ID", err)
		return
	}

	if err := h.invitationService.DeleteInvitation(r.Context(), id); err != nil {
		if err == invitation.ErrInvitationNotFound {
			writeError(w, http.StatusNotFound, "Invitation not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to delete invitation", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResendInvitation resends an invitation email.
func (h *InvitationHandler) ResendInvitation(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid invitation ID", err)
		return
	}

	if err := h.invitationService.ResendInvitation(r.Context(), id); err != nil {
		if err == invitation.ErrInvitationNotFound {
			writeError(w, http.StatusNotFound, "Invitation not found", err)
			return
		}
		if err == invitation.ErrInvitationAlreadyAccepted {
			writeError(w, http.StatusBadRequest, "Invitation already accepted", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to resend invitation", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Invitation resent",
	})
}

// ValidateInvitationRequest represents the request to validate an invitation.
type ValidateInvitationRequest struct {
	Token string `json:"token" validate:"required"`
}

// ValidateInvitation validates an invitation token.
func (h *InvitationHandler) ValidateInvitation(w http.ResponseWriter, r *http.Request) {
	var req ValidateInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	inv, err := h.invitationService.ValidateInvitation(r.Context(), req.Token)
	if err != nil {
		switch err {
		case invitation.ErrInvitationNotFound:
			writeError(w, http.StatusNotFound, "Invalid invitation token", err)
		case invitation.ErrInvitationExpired:
			writeError(w, http.StatusGone, "Invitation has expired", err)
		case invitation.ErrInvitationAlreadyAccepted:
			writeError(w, http.StatusConflict, "Invitation already accepted", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to validate invitation", err)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":      true,
		"email":      inv.Email,
		"first_name": inv.FirstName,
		"last_name":  inv.LastName,
		"expires_at": inv.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// AcceptInvitationRequest represents the request to accept an invitation.
type AcceptInvitationRequest struct {
	Token    string  `json:"token" validate:"required"`
	Password string  `json:"password" validate:"required,min=8,max=128"`
	Username *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
}

// AcceptInvitation accepts an invitation and creates a user.
func (h *InvitationHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req AcceptInvitationRequest
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

	user, err := h.invitationService.AcceptInvitation(r.Context(), &invitation.AcceptInvitationRequest{
		Token:    req.Token,
		Password: req.Password,
		Username: req.Username,
	})

	if err != nil {
		switch err {
		case invitation.ErrInvitationNotFound:
			writeError(w, http.StatusNotFound, "Invalid invitation token", err)
		case invitation.ErrInvitationExpired:
			writeError(w, http.StatusGone, "Invitation has expired", err)
		case invitation.ErrInvitationAlreadyAccepted:
			writeError(w, http.StatusConflict, "Invitation already accepted", err)
		default:
			writeError(w, http.StatusInternalServerError, "Failed to accept invitation", err)
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "Account created successfully",
		"user": UserResponse{
			ID:              user.ID.String(),
			Email:           user.Email,
			Username:        user.Username,
			IsEmailVerified: user.IsEmailVerified,
			CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		},
	})
}

func (h *InvitationHandler) toInvitationResponse(inv *storage.UserInvitation) InvitationResponse {
	status := "pending"
	if inv.AcceptedAt != nil {
		status = "accepted"
	} else if time.Now().After(inv.ExpiresAt) {
		status = "expired"
	}

	resp := InvitationResponse{
		ID:        inv.ID.String(),
		Email:     inv.Email,
		FirstName: inv.FirstName,
		LastName:  inv.LastName,
		RoleIDs:   inv.RoleIDs,
		Status:    status,
		ExpiresAt: inv.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		CreatedAt: inv.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if inv.AcceptedAt != nil {
		aa := inv.AcceptedAt.Format("2006-01-02T15:04:05Z07:00")
		resp.AcceptedAt = &aa
	}
	return resp
}
