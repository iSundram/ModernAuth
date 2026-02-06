package pg

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/iSundram/ModernAuth/internal/storage"
)

// ============================================================================
// Email Template Storage
// ============================================================================

// GetEmailTemplate retrieves an email template by tenant and type.
// Falls back to global template (tenant_id IS NULL) if tenant-specific not found.
func (s *PostgresStorage) GetEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) (*storage.EmailTemplate, error) {
	query := `
		SELECT id, tenant_id, type, subject, html_body, text_body, is_active, created_at, updated_at
		FROM email_templates
		WHERE type = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`
	template := &storage.EmailTemplate{}
	err := s.pool.QueryRow(ctx, query, templateType, tenantID).Scan(
		&template.ID,
		&template.TenantID,
		&template.Type,
		&template.Subject,
		&template.HTMLBody,
		&template.TextBody,
		&template.IsActive,
		&template.CreatedAt,
		&template.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return template, nil
}

// ListEmailTemplates lists all email templates for a tenant.
func (s *PostgresStorage) ListEmailTemplates(ctx context.Context, tenantID *uuid.UUID) ([]*storage.EmailTemplate, error) {
	query := `
		SELECT id, tenant_id, type, subject, html_body, text_body, is_active, created_at, updated_at
		FROM email_templates
		WHERE tenant_id = $1 OR (tenant_id IS NULL AND $1 IS NULL)
		ORDER BY type
	`
	rows, err := s.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*storage.EmailTemplate
	for rows.Next() {
		template := &storage.EmailTemplate{}
		if err := rows.Scan(
			&template.ID,
			&template.TenantID,
			&template.Type,
			&template.Subject,
			&template.HTMLBody,
			&template.TextBody,
			&template.IsActive,
			&template.CreatedAt,
			&template.UpdatedAt,
		); err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}
	return templates, rows.Err()
}

// UpsertEmailTemplate creates or updates an email template.
func (s *PostgresStorage) UpsertEmailTemplate(ctx context.Context, template *storage.EmailTemplate) error {
	query := `
		INSERT INTO email_templates (id, tenant_id, type, subject, html_body, text_body, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, type) DO UPDATE SET
			subject = EXCLUDED.subject,
			html_body = EXCLUDED.html_body,
			text_body = EXCLUDED.text_body,
			is_active = EXCLUDED.is_active,
			updated_at = EXCLUDED.updated_at
	`
	if template.ID == uuid.Nil {
		template.ID = uuid.New()
	}
	now := time.Now()
	if template.CreatedAt.IsZero() {
		template.CreatedAt = now
	}
	template.UpdatedAt = now

	_, err := s.pool.Exec(ctx, query,
		template.ID,
		template.TenantID,
		template.Type,
		template.Subject,
		template.HTMLBody,
		template.TextBody,
		template.IsActive,
		template.CreatedAt,
		template.UpdatedAt,
	)
	return err
}

// DeleteEmailTemplate deletes an email template.
func (s *PostgresStorage) DeleteEmailTemplate(ctx context.Context, tenantID *uuid.UUID, templateType string) error {
	query := `
		DELETE FROM email_templates
		WHERE type = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
	`
	_, err := s.pool.Exec(ctx, query, templateType, tenantID)
	return err
}

// GetEmailBranding retrieves email branding for a tenant.
// Falls back to global branding (tenant_id IS NULL) if tenant-specific not found.
func (s *PostgresStorage) GetEmailBranding(ctx context.Context, tenantID *uuid.UUID) (*storage.EmailBranding, error) {
	query := `
		SELECT id, tenant_id, app_name, logo_url, primary_color, secondary_color, 
		       company_name, support_email, footer_text, created_at, updated_at
		FROM email_branding
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`
	branding := &storage.EmailBranding{}
	err := s.pool.QueryRow(ctx, query, tenantID).Scan(
		&branding.ID,
		&branding.TenantID,
		&branding.AppName,
		&branding.LogoURL,
		&branding.PrimaryColor,
		&branding.SecondaryColor,
		&branding.CompanyName,
		&branding.SupportEmail,
		&branding.FooterText,
		&branding.CreatedAt,
		&branding.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return default branding (matches templates.go DefaultPrimaryColor/DefaultSecondaryColor)
			return &storage.EmailBranding{
				AppName:        "ModernAuth",
				PrimaryColor:   "#2B2B2B",
				SecondaryColor: "#B3B3B3",
			}, nil
		}
		return nil, err
	}
	return branding, nil
}

// UpsertEmailBranding creates or updates email branding.
func (s *PostgresStorage) UpsertEmailBranding(ctx context.Context, branding *storage.EmailBranding) error {
	query := `
		INSERT INTO email_branding (id, tenant_id, app_name, logo_url, primary_color, secondary_color, 
		                            company_name, support_email, footer_text, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id) DO UPDATE SET
			app_name = EXCLUDED.app_name,
			logo_url = EXCLUDED.logo_url,
			primary_color = EXCLUDED.primary_color,
			secondary_color = EXCLUDED.secondary_color,
			company_name = EXCLUDED.company_name,
			support_email = EXCLUDED.support_email,
			footer_text = EXCLUDED.footer_text,
			updated_at = EXCLUDED.updated_at
	`
	if branding.ID == uuid.Nil {
		branding.ID = uuid.New()
	}
	now := time.Now()
	if branding.CreatedAt.IsZero() {
		branding.CreatedAt = now
	}
	branding.UpdatedAt = now

	_, err := s.pool.Exec(ctx, query,
		branding.ID,
		branding.TenantID,
		branding.AppName,
		branding.LogoURL,
		branding.PrimaryColor,
		branding.SecondaryColor,
		branding.CompanyName,
		branding.SupportEmail,
		branding.FooterText,
		branding.CreatedAt,
		branding.UpdatedAt,
	)
	return err
}

// ============================================================================
// Email Dead Letter Storage
// ============================================================================

// CreateEmailDeadLetter stores a failed email in the dead letter queue.
func (s *PostgresStorage) CreateEmailDeadLetter(ctx context.Context, dl *storage.EmailDeadLetter) error {
	query := `
		INSERT INTO email_dead_letters (id, tenant_id, job_type, recipient, subject, payload, error_message, attempts, created_at, failed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	if dl.ID == uuid.Nil {
		dl.ID = uuid.New()
	}
	now := time.Now()
	if dl.CreatedAt.IsZero() {
		dl.CreatedAt = now
	}
	if dl.FailedAt.IsZero() {
		dl.FailedAt = now
	}

	_, err := s.pool.Exec(ctx, query,
		dl.ID,
		dl.TenantID,
		dl.JobType,
		dl.Recipient,
		dl.Subject,
		dl.Payload,
		dl.ErrorMessage,
		dl.Attempts,
		dl.CreatedAt,
		dl.FailedAt,
	)
	return err
}

// ListEmailDeadLetters lists failed emails from the dead letter queue.
func (s *PostgresStorage) ListEmailDeadLetters(ctx context.Context, tenantID *uuid.UUID, resolved bool, limit, offset int) ([]*storage.EmailDeadLetter, error) {
	query := `
		SELECT id, tenant_id, job_type, recipient, subject, payload, error_message, attempts, created_at, failed_at, retried_at, resolved
		FROM email_dead_letters
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL)) AND resolved = $2
		ORDER BY failed_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := s.pool.Query(ctx, query, tenantID, resolved, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deadLetters []*storage.EmailDeadLetter
	for rows.Next() {
		dl := &storage.EmailDeadLetter{}
		if err := rows.Scan(
			&dl.ID,
			&dl.TenantID,
			&dl.JobType,
			&dl.Recipient,
			&dl.Subject,
			&dl.Payload,
			&dl.ErrorMessage,
			&dl.Attempts,
			&dl.CreatedAt,
			&dl.FailedAt,
			&dl.RetriedAt,
			&dl.Resolved,
		); err != nil {
			return nil, err
		}
		deadLetters = append(deadLetters, dl)
	}
	return deadLetters, rows.Err()
}

// MarkEmailDeadLetterResolved marks a dead letter as resolved.
func (s *PostgresStorage) MarkEmailDeadLetterResolved(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE email_dead_letters SET resolved = true, retried_at = $1 WHERE id = $2`
	_, err := s.pool.Exec(ctx, query, time.Now(), id)
	return err
}

// ========== Email Template Version Storage ==========

// CreateEmailTemplateVersion creates a new version record for a template.
func (s *PostgresStorage) CreateEmailTemplateVersion(ctx context.Context, version *storage.EmailTemplateVersion) error {
	query := `
		INSERT INTO email_template_versions (id, template_id, tenant_id, template_type, version, subject, html_body, text_body, changed_by, change_reason, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	if version.ID == uuid.Nil {
		version.ID = uuid.New()
	}
	if version.CreatedAt.IsZero() {
		version.CreatedAt = time.Now()
	}

	_, err := s.pool.Exec(ctx, query,
		version.ID,
		version.TemplateID,
		version.TenantID,
		version.TemplateType,
		version.Version,
		version.Subject,
		version.HTMLBody,
		version.TextBody,
		version.ChangedBy,
		version.ChangeReason,
		version.CreatedAt,
	)
	return err
}

// ListEmailTemplateVersions lists version history for a template.
func (s *PostgresStorage) ListEmailTemplateVersions(ctx context.Context, tenantID *uuid.UUID, templateType string, limit, offset int) ([]*storage.EmailTemplateVersion, error) {
	query := `
		SELECT id, template_id, tenant_id, template_type, version, subject, html_body, text_body, changed_by, change_reason, created_at
		FROM email_template_versions
		WHERE template_type = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
		ORDER BY version DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := s.pool.Query(ctx, query, templateType, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []*storage.EmailTemplateVersion
	for rows.Next() {
		v := &storage.EmailTemplateVersion{}
		if err := rows.Scan(
			&v.ID, &v.TemplateID, &v.TenantID, &v.TemplateType, &v.Version,
			&v.Subject, &v.HTMLBody, &v.TextBody, &v.ChangedBy, &v.ChangeReason, &v.CreatedAt,
		); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetEmailTemplateVersion retrieves a specific version by ID.
func (s *PostgresStorage) GetEmailTemplateVersion(ctx context.Context, id uuid.UUID) (*storage.EmailTemplateVersion, error) {
	query := `
		SELECT id, template_id, tenant_id, template_type, version, subject, html_body, text_body, changed_by, change_reason, created_at
		FROM email_template_versions
		WHERE id = $1
	`
	v := &storage.EmailTemplateVersion{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&v.ID, &v.TemplateID, &v.TenantID, &v.TemplateType, &v.Version,
		&v.Subject, &v.HTMLBody, &v.TextBody, &v.ChangedBy, &v.ChangeReason, &v.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

// ========== Email Bounce Storage ==========

// CreateEmailBounce creates a new bounce record.
func (s *PostgresStorage) CreateEmailBounce(ctx context.Context, bounce *storage.EmailBounce) error {
	query := `
		INSERT INTO email_bounces (id, tenant_id, email, bounce_type, bounce_subtype, event_id, template_type, error_message, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	if bounce.ID == uuid.Nil {
		bounce.ID = uuid.New()
	}
	if bounce.CreatedAt.IsZero() {
		bounce.CreatedAt = time.Now()
	}

	_, err := s.pool.Exec(ctx, query,
		bounce.ID,
		bounce.TenantID,
		bounce.Email,
		bounce.BounceType,
		bounce.BounceSubtype,
		bounce.EventID,
		bounce.TemplateType,
		bounce.ErrorMessage,
		bounce.CreatedAt,
	)
	return err
}

// ListEmailBounces lists bounce records.
func (s *PostgresStorage) ListEmailBounces(ctx context.Context, tenantID *uuid.UUID, bounceType string, limit, offset int) ([]*storage.EmailBounce, error) {
	query := `
		SELECT id, tenant_id, email, bounce_type, bounce_subtype, event_id, template_type, error_message, created_at
		FROM email_bounces
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL))
		AND ($2 = '' OR bounce_type = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	rows, err := s.pool.Query(ctx, query, tenantID, bounceType, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bounces []*storage.EmailBounce
	for rows.Next() {
		b := &storage.EmailBounce{}
		if err := rows.Scan(
			&b.ID, &b.TenantID, &b.Email, &b.BounceType, &b.BounceSubtype,
			&b.EventID, &b.TemplateType, &b.ErrorMessage, &b.CreatedAt,
		); err != nil {
			return nil, err
		}
		bounces = append(bounces, b)
	}
	return bounces, rows.Err()
}

// GetEmailBounceByEmail retrieves the most recent bounce for an email.
func (s *PostgresStorage) GetEmailBounceByEmail(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.EmailBounce, error) {
	query := `
		SELECT id, tenant_id, email, bounce_type, bounce_subtype, event_id, template_type, error_message, created_at
		FROM email_bounces
		WHERE email = $1 AND (tenant_id = $2 OR ($2 IS NULL AND tenant_id IS NULL))
		ORDER BY created_at DESC
		LIMIT 1
	`
	b := &storage.EmailBounce{}
	err := s.pool.QueryRow(ctx, query, email, tenantID).Scan(
		&b.ID, &b.TenantID, &b.Email, &b.BounceType, &b.BounceSubtype,
		&b.EventID, &b.TemplateType, &b.ErrorMessage, &b.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return b, nil
}

// ========== Email Event Storage ==========

// CreateEmailEvent creates a new email event record.
func (s *PostgresStorage) CreateEmailEvent(ctx context.Context, event *storage.EmailEvent) error {
	query := `
		INSERT INTO email_events (id, tenant_id, job_id, template_type, event_type, recipient, user_id, metadata, event_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	_, err := s.pool.Exec(ctx, query,
		event.ID,
		event.TenantID,
		event.JobID,
		event.TemplateType,
		event.EventType,
		event.Recipient,
		event.UserID,
		event.Metadata,
		event.EventID,
		event.CreatedAt,
	)
	return err
}

// GetEmailStats retrieves aggregated email statistics.
func (s *PostgresStorage) GetEmailStats(ctx context.Context, tenantID *uuid.UUID, days int) (*storage.EmailStats, error) {
	stats := &storage.EmailStats{
		ByTemplate: make(map[string]int),
		ByDay:      make(map[string]int),
	}

	since := time.Now().AddDate(0, 0, -days)

	// Get counts by event type
	query := `
		SELECT event_type, COUNT(*) as count
		FROM email_events
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL))
		AND created_at > $2
		GROUP BY event_type
	`
	rows, err := s.pool.Query(ctx, query, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			return nil, err
		}
		switch eventType {
		case "sent":
			stats.TotalSent = count
		case "delivered":
			stats.TotalDelivered = count
		case "opened":
			stats.TotalOpened = count
		case "clicked":
			stats.TotalClicked = count
		case "bounced":
			stats.TotalBounced = count
		case "dropped":
			stats.TotalDropped = count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Get counts by template
	query = `
		SELECT template_type, COUNT(*) as count
		FROM email_events
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL))
		AND created_at > $2 AND event_type = 'sent'
		GROUP BY template_type
	`
	rows, err = s.pool.Query(ctx, query, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var templateType string
		var count int
		if err := rows.Scan(&templateType, &count); err != nil {
			return nil, err
		}
		stats.ByTemplate[templateType] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Get counts by day
	query = `
		SELECT DATE(created_at)::text as day, COUNT(*) as count
		FROM email_events
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL))
		AND created_at > $2 AND event_type = 'sent'
		GROUP BY DATE(created_at)
		ORDER BY day
	`
	rows, err = s.pool.Query(ctx, query, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var day string
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			return nil, err
		}
		stats.ByDay[day] = count
	}

	return stats, rows.Err()
}

// ========== Email Suppression Storage ==========

// CreateEmailSuppression adds an email to the suppression list.
func (s *PostgresStorage) CreateEmailSuppression(ctx context.Context, suppression *storage.EmailSuppression) error {
	query := `
		INSERT INTO email_suppressions (id, tenant_id, email, reason, source, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, email) DO UPDATE SET
			reason = EXCLUDED.reason,
			source = EXCLUDED.source
	`
	if suppression.ID == uuid.Nil {
		suppression.ID = uuid.New()
	}
	if suppression.CreatedAt.IsZero() {
		suppression.CreatedAt = time.Now()
	}

	_, err := s.pool.Exec(ctx, query,
		suppression.ID,
		suppression.TenantID,
		suppression.Email,
		suppression.Reason,
		suppression.Source,
		suppression.CreatedAt,
	)
	return err
}

// GetEmailSuppression checks if an email is suppressed.
func (s *PostgresStorage) GetEmailSuppression(ctx context.Context, tenantID *uuid.UUID, email string) (*storage.EmailSuppression, error) {
	query := `
		SELECT id, tenant_id, email, reason, source, created_at
		FROM email_suppressions
		WHERE email = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
	`
	sup := &storage.EmailSuppression{}
	err := s.pool.QueryRow(ctx, query, email, tenantID).Scan(
		&sup.ID, &sup.TenantID, &sup.Email, &sup.Reason, &sup.Source, &sup.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return sup, nil
}

// DeleteEmailSuppression removes an email from the suppression list.
func (s *PostgresStorage) DeleteEmailSuppression(ctx context.Context, tenantID *uuid.UUID, email string) error {
	query := `
		DELETE FROM email_suppressions
		WHERE email = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND $2 IS NULL))
	`
	_, err := s.pool.Exec(ctx, query, email, tenantID)
	return err
}

// ListEmailSuppressions lists suppressed emails.
func (s *PostgresStorage) ListEmailSuppressions(ctx context.Context, tenantID *uuid.UUID, limit, offset int) ([]*storage.EmailSuppression, error) {
	query := `
		SELECT id, tenant_id, email, reason, source, created_at
		FROM email_suppressions
		WHERE (tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL))
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var suppressions []*storage.EmailSuppression
	for rows.Next() {
		sup := &storage.EmailSuppression{}
		if err := rows.Scan(&sup.ID, &sup.TenantID, &sup.Email, &sup.Reason, &sup.Source, &sup.CreatedAt); err != nil {
			return nil, err
		}
		suppressions = append(suppressions, sup)
	}
	return suppressions, rows.Err()
}

// ========== Email A/B Testing Storage ==========

// ListEmailABTests lists all A/B tests for a tenant.
func (s *PostgresStorage) ListEmailABTests(ctx context.Context, tenantID *uuid.UUID) ([]*storage.EmailABTest, error) {
	query := `
		SELECT id, tenant_id, template_type, name, variant_a, variant_b, weight_a, weight_b, 
		       is_active, start_date, end_date, winner_variant, created_at, updated_at
		FROM email_ab_tests
		WHERE tenant_id = $1 OR ($1 IS NULL AND tenant_id IS NULL)
		ORDER BY created_at DESC
	`
	rows, err := s.pool.Query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tests []*storage.EmailABTest
	for rows.Next() {
		t := &storage.EmailABTest{}
		if err := rows.Scan(
			&t.ID, &t.TenantID, &t.TemplateType, &t.Name, &t.VariantA, &t.VariantB,
			&t.WeightA, &t.WeightB, &t.IsActive, &t.StartDate, &t.EndDate,
			&t.WinnerVariant, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		tests = append(tests, t)
	}
	return tests, rows.Err()
}

// CreateEmailABTest creates a new A/B test.
func (s *PostgresStorage) CreateEmailABTest(ctx context.Context, test *storage.EmailABTest) error {
	query := `
		INSERT INTO email_ab_tests (id, tenant_id, template_type, name, variant_a, variant_b, 
		                            weight_a, weight_b, is_active, start_date, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	if test.ID == uuid.Nil {
		test.ID = uuid.New()
	}
	now := time.Now()
	if test.CreatedAt.IsZero() {
		test.CreatedAt = now
	}
	test.UpdatedAt = now

	startDate := now.Format("2006-01-02")
	if test.StartDate == nil {
		test.StartDate = &startDate
	}

	_, err := s.pool.Exec(ctx, query,
		test.ID, test.TenantID, test.TemplateType, test.Name, test.VariantA, test.VariantB,
		test.WeightA, test.WeightB, test.IsActive, test.StartDate, test.CreatedAt, test.UpdatedAt,
	)
	return err
}

// GetEmailABTest retrieves a specific A/B test by ID.
func (s *PostgresStorage) GetEmailABTest(ctx context.Context, id uuid.UUID) (*storage.EmailABTest, error) {
	query := `
		SELECT id, tenant_id, template_type, name, variant_a, variant_b, weight_a, weight_b,
		       is_active, start_date, end_date, winner_variant, created_at, updated_at
		FROM email_ab_tests
		WHERE id = $1
	`
	t := &storage.EmailABTest{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&t.ID, &t.TenantID, &t.TemplateType, &t.Name, &t.VariantA, &t.VariantB,
		&t.WeightA, &t.WeightB, &t.IsActive, &t.StartDate, &t.EndDate,
		&t.WinnerVariant, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return t, nil
}

// UpdateEmailABTest updates an existing A/B test.
func (s *PostgresStorage) UpdateEmailABTest(ctx context.Context, test *storage.EmailABTest) error {
	query := `
		UPDATE email_ab_tests SET
			name = $1, variant_a = $2, variant_b = $3, weight_a = $4, weight_b = $5,
			is_active = $6, end_date = $7, winner_variant = $8, updated_at = $9
		WHERE id = $10
	`
	test.UpdatedAt = time.Now()
	_, err := s.pool.Exec(ctx, query,
		test.Name, test.VariantA, test.VariantB, test.WeightA, test.WeightB,
		test.IsActive, test.EndDate, test.WinnerVariant, test.UpdatedAt, test.ID,
	)
	return err
}

// DeleteEmailABTest deletes an A/B test.
func (s *PostgresStorage) DeleteEmailABTest(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM email_ab_tests WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id)
	return err
}

// ========== Email Advanced Branding Storage ==========

// GetEmailBrandingAdvanced retrieves advanced email branding settings.
func (s *PostgresStorage) GetEmailBrandingAdvanced(ctx context.Context, tenantID *uuid.UUID) (*storage.EmailBrandingAdvanced, error) {
	query := `
		SELECT id, tenant_id, social_facebook, social_twitter, social_linkedin, social_instagram,
		       custom_css, header_image_url, font_family, font_family_url, created_at, updated_at
		FROM email_branding_advanced
		WHERE tenant_id = $1 OR (tenant_id IS NULL AND $1 IS NULL)
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`
	b := &storage.EmailBrandingAdvanced{
		SocialLinks: &storage.EmailSocialLinks{},
	}
	var socialFacebook, socialTwitter, socialLinkedIn, socialInstagram *string
	err := s.pool.QueryRow(ctx, query, tenantID).Scan(
		&b.ID, &b.TenantID, &socialFacebook, &socialTwitter, &socialLinkedIn, &socialInstagram,
		&b.CustomCSS, &b.HeaderImageURL, &b.FontFamily, &b.FontFamilyURL, &b.CreatedAt, &b.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Return default empty advanced branding
			return &storage.EmailBrandingAdvanced{
				ID:          uuid.New(),
				SocialLinks: &storage.EmailSocialLinks{},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}, nil
		}
		return nil, err
	}
	b.SocialLinks.Facebook = socialFacebook
	b.SocialLinks.Twitter = socialTwitter
	b.SocialLinks.LinkedIn = socialLinkedIn
	b.SocialLinks.Instagram = socialInstagram
	return b, nil
}

// UpsertEmailBrandingAdvanced creates or updates advanced email branding.
func (s *PostgresStorage) UpsertEmailBrandingAdvanced(ctx context.Context, branding *storage.EmailBrandingAdvanced) error {
	query := `
		INSERT INTO email_branding_advanced (id, tenant_id, social_facebook, social_twitter, social_linkedin, social_instagram,
		                                     custom_css, header_image_url, font_family, font_family_url, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (tenant_id) DO UPDATE SET
			social_facebook = EXCLUDED.social_facebook,
			social_twitter = EXCLUDED.social_twitter,
			social_linkedin = EXCLUDED.social_linkedin,
			social_instagram = EXCLUDED.social_instagram,
			custom_css = EXCLUDED.custom_css,
			header_image_url = EXCLUDED.header_image_url,
			font_family = EXCLUDED.font_family,
			font_family_url = EXCLUDED.font_family_url,
			updated_at = EXCLUDED.updated_at
	`
	if branding.ID == uuid.Nil {
		branding.ID = uuid.New()
	}
	now := time.Now()
	if branding.CreatedAt.IsZero() {
		branding.CreatedAt = now
	}
	branding.UpdatedAt = now

	var socialFacebook, socialTwitter, socialLinkedIn, socialInstagram *string
	if branding.SocialLinks != nil {
		socialFacebook = branding.SocialLinks.Facebook
		socialTwitter = branding.SocialLinks.Twitter
		socialLinkedIn = branding.SocialLinks.LinkedIn
		socialInstagram = branding.SocialLinks.Instagram
	}

	_, err := s.pool.Exec(ctx, query,
		branding.ID, branding.TenantID, socialFacebook, socialTwitter, socialLinkedIn, socialInstagram,
		branding.CustomCSS, branding.HeaderImageURL, branding.FontFamily, branding.FontFamilyURL,
		branding.CreatedAt, branding.UpdatedAt,
	)
	return err
}

// ========== Email Tracking Pixel Storage ==========

// CreateEmailTrackingPixel creates a new tracking pixel.
func (s *PostgresStorage) CreateEmailTrackingPixel(ctx context.Context, pixel *storage.EmailTrackingPixel) error {
	query := `
		INSERT INTO email_tracking_pixels (id, email_job_id, tenant_id, recipient, template_id, url, is_opened, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	if pixel.ID == uuid.Nil {
		pixel.ID = uuid.New()
	}
	if pixel.CreatedAt.IsZero() {
		pixel.CreatedAt = time.Now()
	}

	_, err := s.pool.Exec(ctx, query,
		pixel.ID, pixel.EmailJobID, pixel.TenantID, pixel.Recipient,
		pixel.TemplateID, pixel.URL, pixel.IsOpened, pixel.CreatedAt,
	)
	return err
}

// GetEmailTrackingPixel retrieves a tracking pixel by ID.
func (s *PostgresStorage) GetEmailTrackingPixel(ctx context.Context, id uuid.UUID) (*storage.EmailTrackingPixel, error) {
	query := `
		SELECT id, email_job_id, tenant_id, recipient, template_id, url, is_opened, opened_at, created_at
		FROM email_tracking_pixels
		WHERE id = $1
	`
	p := &storage.EmailTrackingPixel{}
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.EmailJobID, &p.TenantID, &p.Recipient, &p.TemplateID,
		&p.URL, &p.IsOpened, &p.OpenedAt, &p.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

// MarkTrackingPixelOpened marks a tracking pixel as opened.
func (s *PostgresStorage) MarkTrackingPixelOpened(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE email_tracking_pixels SET is_opened = true, opened_at = $1 WHERE id = $2 AND is_opened = false`
	_, err := s.pool.Exec(ctx, query, time.Now(), id)
	return err
}
