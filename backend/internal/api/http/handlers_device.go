// Package http provides device and session HTTP handlers for ModernAuth API.
package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/device"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// DeviceHandler provides HTTP handlers for device management.
type DeviceHandler struct {
	deviceService *device.Service
}

// NewDeviceHandler creates a new device handler.
func NewDeviceHandler(service *device.Service) *DeviceHandler {
	return &DeviceHandler{deviceService: service}
}

// DeviceRoutes returns chi routes for device management.
func (h *DeviceHandler) DeviceRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/", h.ListDevices)
	r.Get("/{id}", h.GetDevice)
	r.Delete("/{id}", h.RemoveDevice)
	r.Post("/{id}/trust", h.TrustDevice)
	r.Delete("/{id}/trust", h.UntrustDevice)

	return r
}

// SessionRoutes returns chi routes for session management.
func (h *DeviceHandler) SessionRoutes() chi.Router {
	r := chi.NewRouter()

	r.Get("/history", h.GetLoginHistory)

	return r
}

// DeviceResponse represents a device in API responses.
type DeviceResponse struct {
	ID              string  `json:"id"`
	DeviceName      *string `json:"device_name,omitempty"`
	DeviceType      *string `json:"device_type,omitempty"`
	Browser         *string `json:"browser,omitempty"`
	OS              *string `json:"os,omitempty"`
	IPAddress       *string `json:"ip_address,omitempty"`
	LocationCountry *string `json:"location_country,omitempty"`
	LocationCity    *string `json:"location_city,omitempty"`
	IsTrusted       bool    `json:"is_trusted"`
	IsCurrent       bool    `json:"is_current"`
	LastSeenAt      *string `json:"last_seen_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

// LoginHistoryResponse represents a login history entry in API responses.
type LoginHistoryResponse struct {
	ID              string  `json:"id"`
	IPAddress       *string `json:"ip_address,omitempty"`
	LocationCountry *string `json:"location_country,omitempty"`
	LocationCity    *string `json:"location_city,omitempty"`
	LoginMethod     *string `json:"login_method,omitempty"`
	Status          string  `json:"status"`
	FailureReason   *string `json:"failure_reason,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

// ListDevices lists devices for the current user.
func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := r.Context().Value(userIDKey).(string)
	if !ok || userIDStr == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	devices, err := h.deviceService.ListUserDevices(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to list devices", err)
		return
	}

	response := make([]DeviceResponse, len(devices))
	for i, d := range devices {
		response[i] = h.toDeviceResponse(d)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": response,
	})
}

// GetDevice retrieves a device by ID.
func (h *DeviceHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid device ID", err)
		return
	}

	d, err := h.deviceService.GetDevice(r.Context(), id)
	if err != nil {
		if err == device.ErrDeviceNotFound {
			writeError(w, http.StatusNotFound, "Device not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to get device", err)
		return
	}

	writeJSON(w, http.StatusOK, h.toDeviceResponse(d))
}

// RemoveDevice removes a device.
func (h *DeviceHandler) RemoveDevice(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid device ID", err)
		return
	}

	userIDStr, _ := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	if err := h.deviceService.RemoveDevice(r.Context(), id, userID); err != nil {
		if err == device.ErrDeviceNotFound {
			writeError(w, http.StatusNotFound, "Device not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to remove device", err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TrustDevice marks a device as trusted.
func (h *DeviceHandler) TrustDevice(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid device ID", err)
		return
	}

	userIDStr, _ := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	if err := h.deviceService.TrustDevice(r.Context(), id, userID); err != nil {
		if err == device.ErrDeviceNotFound {
			writeError(w, http.StatusNotFound, "Device not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to trust device", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Device marked as trusted",
	})
}

// UntrustDevice removes trust from a device.
func (h *DeviceHandler) UntrustDevice(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid device ID", err)
		return
	}

	userIDStr, _ := r.Context().Value(userIDKey).(string)
	userID, _ := uuid.Parse(userIDStr)

	if err := h.deviceService.UntrustDevice(r.Context(), id, userID); err != nil {
		if err == device.ErrDeviceNotFound {
			writeError(w, http.StatusNotFound, "Device not found", err)
			return
		}
		writeError(w, http.StatusInternalServerError, "Failed to untrust device", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Device trust removed",
	})
}

// GetLoginHistory retrieves login history for the current user.
func (h *DeviceHandler) GetLoginHistory(w http.ResponseWriter, r *http.Request) {
	userIDStr, ok := r.Context().Value(userIDKey).(string)
	if !ok || userIDStr == "" {
		writeError(w, http.StatusUnauthorized, "Authentication required", nil)
		return
	}
	userID, _ := uuid.Parse(userIDStr)

	limit, offset := parsePagination(r)

	history, err := h.deviceService.GetLoginHistory(r.Context(), userID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get login history", err)
		return
	}

	response := make([]LoginHistoryResponse, len(history))
	for i, h := range history {
		response[i] = toLoginHistoryResponse(h)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data":   response,
		"limit":  limit,
		"offset": offset,
	})
}

func (h *DeviceHandler) toDeviceResponse(d *storage.UserDevice) DeviceResponse {
	resp := DeviceResponse{
		ID:              d.ID.String(),
		DeviceName:      d.DeviceName,
		DeviceType:      d.DeviceType,
		Browser:         d.Browser,
		OS:              d.OS,
		IPAddress:       d.IPAddress,
		LocationCountry: d.LocationCountry,
		LocationCity:    d.LocationCity,
		IsTrusted:       d.IsTrusted,
		IsCurrent:       d.IsCurrent,
		CreatedAt:       d.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
	if d.LastSeenAt != nil {
		ls := d.LastSeenAt.Format("2006-01-02T15:04:05Z07:00")
		resp.LastSeenAt = &ls
	}
	return resp
}

func toLoginHistoryResponse(h *storage.LoginHistory) LoginHistoryResponse {
	return LoginHistoryResponse{
		ID:              h.ID.String(),
		IPAddress:       h.IPAddress,
		LocationCountry: h.LocationCountry,
		LocationCity:    h.LocationCity,
		LoginMethod:     h.LoginMethod,
		Status:          h.Status,
		FailureReason:   h.FailureReason,
		CreatedAt:       h.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}
}
