package pg

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// DeviceStorage methods
// ============================================================================

func (s *PostgresStorage) CreateDevice(ctx context.Context, device *storage.UserDevice) error {
	query := `
		INSERT INTO user_devices (id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		                          os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		                          last_seen_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err := s.pool.Exec(ctx, query,
		device.ID, device.UserID, device.DeviceFingerprint, device.DeviceName, device.DeviceType,
		device.Browser, device.BrowserVersion, device.OS, device.OSVersion, device.IPAddress,
		device.LocationCountry, device.LocationCity, device.IsTrusted, device.IsCurrent,
		device.LastSeenAt, device.CreatedAt,
	)
	return err
}

func (s *PostgresStorage) GetDeviceByID(ctx context.Context, id uuid.UUID) (*storage.UserDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		       os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		       last_seen_at, created_at
		FROM user_devices WHERE id = $1
	`
	device := &storage.UserDevice{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&device.ID, &device.UserID, &device.DeviceFingerprint, &device.DeviceName, &device.DeviceType,
		&device.Browser, &device.BrowserVersion, &device.OS, &device.OSVersion, &device.IPAddress,
		&device.LocationCountry, &device.LocationCity, &device.IsTrusted, &device.IsCurrent,
		&device.LastSeenAt, &device.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return device, nil
}

func (s *PostgresStorage) GetDeviceByFingerprint(ctx context.Context, userID uuid.UUID, fingerprint string) (*storage.UserDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		       os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		       last_seen_at, created_at
		FROM user_devices WHERE user_id = $1 AND device_fingerprint = $2
	`
	device := &storage.UserDevice{}
	err := s.pool.QueryRow(ctx, query, userID, fingerprint).Scan(
		&device.ID, &device.UserID, &device.DeviceFingerprint, &device.DeviceName, &device.DeviceType,
		&device.Browser, &device.BrowserVersion, &device.OS, &device.OSVersion, &device.IPAddress,
		&device.LocationCountry, &device.LocationCity, &device.IsTrusted, &device.IsCurrent,
		&device.LastSeenAt, &device.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return device, nil
}

func (s *PostgresStorage) ListUserDevices(ctx context.Context, userID uuid.UUID) ([]*storage.UserDevice, error) {
	query := `
		SELECT id, user_id, device_fingerprint, device_name, device_type, browser, browser_version,
		       os, os_version, ip_address, location_country, location_city, is_trusted, is_current,
		       last_seen_at, created_at
		FROM user_devices WHERE user_id = $1 ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
	`
	rows, err := s.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []*storage.UserDevice
	for rows.Next() {
		device := &storage.UserDevice{}
		err := rows.Scan(
			&device.ID, &device.UserID, &device.DeviceFingerprint, &device.DeviceName, &device.DeviceType,
			&device.Browser, &device.BrowserVersion, &device.OS, &device.OSVersion, &device.IPAddress,
			&device.LocationCountry, &device.LocationCity, &device.IsTrusted, &device.IsCurrent,
			&device.LastSeenAt, &device.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *PostgresStorage) UpdateDevice(ctx context.Context, device *storage.UserDevice) error {
	query := `
		UPDATE user_devices
		SET device_name = $2, device_type = $3, browser = $4, browser_version = $5, os = $6, os_version = $7,
		    ip_address = $8, location_country = $9, location_city = $10, is_trusted = $11, is_current = $12,
		    last_seen_at = $13
		WHERE id = $1
	`
	_, err := s.pool.Exec(ctx, query,
		device.ID, device.DeviceName, device.DeviceType, device.Browser, device.BrowserVersion,
		device.OS, device.OSVersion, device.IPAddress, device.LocationCountry, device.LocationCity,
		device.IsTrusted, device.IsCurrent, device.LastSeenAt,
	)
	return err
}

func (s *PostgresStorage) DeleteDevice(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM user_devices WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

func (s *PostgresStorage) TrustDevice(ctx context.Context, id uuid.UUID, trusted bool) error {
	query := `UPDATE user_devices SET is_trusted = $2 WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, trusted)
	return err
}

func (s *PostgresStorage) CreateLoginHistory(ctx context.Context, history *storage.LoginHistory) error {
	query := `
		INSERT INTO login_history (id, user_id, tenant_id, session_id, device_id, ip_address, user_agent,
		                          location_country, location_city, login_method, status, failure_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err := s.pool.Exec(ctx, query,
		history.ID, history.UserID, history.TenantID, history.SessionID, history.DeviceID,
		history.IPAddress, history.UserAgent, history.LocationCountry, history.LocationCity,
		history.LoginMethod, history.Status, history.FailureReason, history.CreatedAt,
	)
	return err
}

func (s *PostgresStorage) GetLoginHistory(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*storage.LoginHistory, error) {
	query := `
		SELECT id, user_id, tenant_id, session_id, device_id, ip_address, user_agent,
		       location_country, location_city, login_method, status, failure_reason, created_at
		FROM login_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*storage.LoginHistory
	for rows.Next() {
		h := &storage.LoginHistory{}
		err := rows.Scan(
			&h.ID, &h.UserID, &h.TenantID, &h.SessionID, &h.DeviceID,
			&h.IPAddress, &h.UserAgent, &h.LocationCountry, &h.LocationCity,
			&h.LoginMethod, &h.Status, &h.FailureReason, &h.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, rows.Err()
}
