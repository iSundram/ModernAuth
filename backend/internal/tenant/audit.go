package tenant

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

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
