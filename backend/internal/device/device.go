// Package device provides device management for ModernAuth.
package device

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/email"
	"github.com/iSundram/ModernAuth/internal/storage"
)

var (
	// ErrDeviceNotFound indicates the device was not found.
	ErrDeviceNotFound = errors.New("device not found")
)

// Service provides device management operations.
type Service struct {
	storage      storage.DeviceStorage
	userStorage  storage.UserStorage
	emailService email.Service
	logger       *slog.Logger
}

// NewService creates a new device service.
func NewService(store storage.DeviceStorage, userStore storage.UserStorage, emailSvc email.Service) *Service {
	return &Service{
		storage:      store,
		userStorage:  userStore,
		emailService: emailSvc,
		logger:       slog.Default().With("component", "device_service"),
	}
}

// DeviceInfo contains parsed device information from user agent.
type DeviceInfo struct {
	DeviceName     string
	DeviceType     string // mobile, desktop, tablet, unknown
	Browser        string
	BrowserVersion string
	OS             string
	OSVersion      string
}

// RecordDeviceRequest represents a request to record a device.
type RecordDeviceRequest struct {
	UserID          uuid.UUID
	DeviceFingerprint *string
	UserAgent       string
	IPAddress       string
	Location        *LocationInfo
}

// LocationInfo contains geolocation information.
type LocationInfo struct {
	Country string
	City    string
	Coords  string
}

// RecordDevice records a device for a user, creating or updating as needed.
func (s *Service) RecordDevice(ctx context.Context, req *RecordDeviceRequest) (*storage.UserDevice, bool, error) {
	var device *storage.UserDevice
	var isNewDevice bool

	// Try to find existing device by fingerprint
	if req.DeviceFingerprint != nil && *req.DeviceFingerprint != "" {
		existingDevice, err := s.storage.GetDeviceByFingerprint(ctx, req.UserID, *req.DeviceFingerprint)
		if err != nil {
			return nil, false, err
		}
		device = existingDevice
	}

	// Parse user agent
	deviceInfo := ParseUserAgent(req.UserAgent)

	now := time.Now()

	if device != nil {
		// Update existing device
		device.LastSeenAt = &now
		device.IPAddress = &req.IPAddress
		if req.Location != nil {
			device.LocationCountry = &req.Location.Country
			device.LocationCity = &req.Location.City
		}

		if err := s.storage.UpdateDevice(ctx, device); err != nil {
			return nil, false, err
		}
	} else {
		// Create new device
		isNewDevice = true
		device = &storage.UserDevice{
			ID:                uuid.New(),
			UserID:            req.UserID,
			DeviceFingerprint: req.DeviceFingerprint,
			DeviceName:        &deviceInfo.DeviceName,
			DeviceType:        &deviceInfo.DeviceType,
			Browser:           &deviceInfo.Browser,
			BrowserVersion:    &deviceInfo.BrowserVersion,
			OS:                &deviceInfo.OS,
			OSVersion:         &deviceInfo.OSVersion,
			IPAddress:         &req.IPAddress,
			IsTrusted:         false,
			IsCurrent:         true,
			LastSeenAt:        &now,
			CreatedAt:         now,
		}

		if req.Location != nil {
			device.LocationCountry = &req.Location.Country
			device.LocationCity = &req.Location.City
		}

		if err := s.storage.CreateDevice(ctx, device); err != nil {
			return nil, false, err
		}

		// Send new device alert email
		if s.emailService != nil {
			user, _ := s.userStorage.GetUserByID(ctx, req.UserID)
			if user != nil {
				location := "Unknown"
				if req.Location != nil {
					location = req.Location.City + ", " + req.Location.Country
				}
				go func() {
					s.emailService.SendLoginAlertEmail(context.Background(), user, &email.DeviceInfo{
						DeviceName: deviceInfo.DeviceName,
						Browser:    deviceInfo.Browser,
						OS:         deviceInfo.OS,
						IPAddress:  req.IPAddress,
						Location:   location,
						Time:       now.Format(time.RFC3339),
					})
				}()
			}
		}

		s.logger.Info("New device recorded", "device_id", device.ID, "user_id", req.UserID)
	}

	return device, isNewDevice, nil
}

// GetDevice retrieves a device by ID.
func (s *Service) GetDevice(ctx context.Context, id uuid.UUID) (*storage.UserDevice, error) {
	device, err := s.storage.GetDeviceByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrDeviceNotFound
	}
	return device, nil
}

// ListUserDevices lists all devices for a user.
func (s *Service) ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*storage.UserDevice, error) {
	return s.storage.ListUserDevices(ctx, userID)
}

// TrustDevice marks a device as trusted.
func (s *Service) TrustDevice(ctx context.Context, deviceID uuid.UUID, userID uuid.UUID) error {
	device, err := s.storage.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device == nil {
		return ErrDeviceNotFound
	}

	// Verify the device belongs to the user
	if device.UserID != userID {
		return ErrDeviceNotFound
	}

	return s.storage.TrustDevice(ctx, deviceID, true)
}

// UntrustDevice marks a device as untrusted.
func (s *Service) UntrustDevice(ctx context.Context, deviceID uuid.UUID, userID uuid.UUID) error {
	device, err := s.storage.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device == nil {
		return ErrDeviceNotFound
	}

	if device.UserID != userID {
		return ErrDeviceNotFound
	}

	return s.storage.TrustDevice(ctx, deviceID, false)
}

// RemoveDevice removes a device from the user's account.
func (s *Service) RemoveDevice(ctx context.Context, deviceID uuid.UUID, userID uuid.UUID) error {
	device, err := s.storage.GetDeviceByID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device == nil {
		return ErrDeviceNotFound
	}

	if device.UserID != userID {
		return ErrDeviceNotFound
	}

	return s.storage.DeleteDevice(ctx, deviceID)
}

// RecordLogin records a login attempt.
func (s *Service) RecordLogin(ctx context.Context, history *storage.LoginHistory) error {
	history.ID = uuid.New()
	history.CreatedAt = time.Now()
	return s.storage.CreateLoginHistory(ctx, history)
}

// GetLoginHistory retrieves login history for a user.
func (s *Service) GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.LoginHistory, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.storage.GetLoginHistory(ctx, userID, limit, offset)
}

// ParseUserAgent parses a user agent string to extract device information.
func ParseUserAgent(userAgent string) *DeviceInfo {
	// Simple user agent parsing - in production, use a library like mssola/user_agent
	info := &DeviceInfo{
		DeviceName:     "Unknown Device",
		DeviceType:     "unknown",
		Browser:        "Unknown",
		BrowserVersion: "",
		OS:             "Unknown",
		OSVersion:      "",
	}

	if userAgent == "" {
		return info
	}

	// Detect device type
	if containsAny(userAgent, "Mobile", "Android", "iPhone", "iPod") {
		info.DeviceType = "mobile"
		if containsAny(userAgent, "iPad", "Tablet") {
			info.DeviceType = "tablet"
		}
	} else {
		info.DeviceType = "desktop"
	}

	// Detect OS
	switch {
	case containsAny(userAgent, "Windows"):
		info.OS = "Windows"
	case containsAny(userAgent, "Mac OS X", "Macintosh"):
		info.OS = "macOS"
	case containsAny(userAgent, "Linux"):
		info.OS = "Linux"
	case containsAny(userAgent, "Android"):
		info.OS = "Android"
	case containsAny(userAgent, "iPhone", "iPad", "iPod"):
		info.OS = "iOS"
	}

	// Detect browser
	switch {
	case containsAny(userAgent, "Chrome") && !containsAny(userAgent, "Edg"):
		info.Browser = "Chrome"
	case containsAny(userAgent, "Firefox"):
		info.Browser = "Firefox"
	case containsAny(userAgent, "Safari") && !containsAny(userAgent, "Chrome"):
		info.Browser = "Safari"
	case containsAny(userAgent, "Edg"):
		info.Browser = "Edge"
	case containsAny(userAgent, "Opera", "OPR"):
		info.Browser = "Opera"
	}

	// Set device name
	info.DeviceName = info.Browser + " on " + info.OS

	return info
}

// containsAny checks if the string contains any of the substrings.
func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
