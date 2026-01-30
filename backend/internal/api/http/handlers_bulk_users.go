// Package http provides HTTP handlers for ModernAuth API.
// This file contains bulk user import/export handlers.
package http

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
	"github.com/iSundram/ModernAuth/internal/utils"
)

// BulkUserImportRequest represents a request to import users from CSV/JSON.
type BulkUserImportRequest struct {
	Users         []BulkUserRecord `json:"users"`
	SendWelcome   bool             `json:"send_welcome_email"`
	SkipExisting  bool             `json:"skip_existing"`
	ValidateOnly  bool             `json:"validate_only"` // Dry run mode
}

// BulkUserRecord represents a single user record for import.
type BulkUserRecord struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Roles     string `json:"roles,omitempty"` // Comma-separated role names
	Password  string `json:"password,omitempty"`
	Active    bool   `json:"active"`
}

// BulkImportResult represents the result of a bulk import operation.
type BulkImportResult struct {
	TotalRecords   int                `json:"total_records"`
	SuccessCount   int                `json:"success_count"`
	FailureCount   int                `json:"failure_count"`
	SkippedCount   int                `json:"skipped_count"`
	Errors         []UserBulkImportError  `json:"errors,omitempty"`
	CreatedUsers   []string           `json:"created_users,omitempty"` // User IDs
	ValidateOnly   bool               `json:"validate_only"`
}

// UserBulkImportError represents an error during import.
type UserBulkImportError struct {
	Row     int    `json:"row"`
	Email   string `json:"email"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// BulkUserExportRequest represents a request to export users.
type BulkUserExportRequest struct {
	Format      string   `json:"format"` // csv, json
	Fields      []string `json:"fields,omitempty"` // Fields to include
	ActiveOnly  bool     `json:"active_only"`
	IncludeRoles bool    `json:"include_roles"`
}

// ImportUsersJSON handles POST /v1/admin/users/import
func (h *Handler) ImportUsersJSON(w http.ResponseWriter, r *http.Request) {
	var req BulkUserImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if len(req.Users) == 0 {
		h.writeError(w, http.StatusBadRequest, "No users provided", nil)
		return
	}

	if len(req.Users) > 1000 {
		h.writeError(w, http.StatusBadRequest, "Maximum 1000 users per import", nil)
		return
	}

	result := h.processUserImport(r, req)
	writeJSON(w, http.StatusOK, result)
}

// ImportUsersCSV handles POST /v1/admin/users/import/csv
func (h *Handler) ImportUsersCSV(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		h.writeError(w, http.StatusBadRequest, "Failed to parse form", err)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "No file provided", err)
		return
	}
	defer file.Close()

	// Read CSV
	reader := csv.NewReader(file)
	
	// Read header
	header, err := reader.Read()
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "Failed to read CSV header", err)
		return
	}

	// Map header columns
	colIndex := make(map[string]int)
	for i, col := range header {
		colIndex[col] = i
	}

	// Validate required columns
	if _, ok := colIndex["email"]; !ok {
		h.writeError(w, http.StatusBadRequest, "CSV must contain 'email' column", nil)
		return
	}

	// Parse options from form
	skipExisting := r.FormValue("skip_existing") == "true"
	validateOnly := r.FormValue("validate_only") == "true"
	sendWelcome := r.FormValue("send_welcome") == "true"

	// Read all records
	var users []BulkUserRecord
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "Failed to read CSV", err)
			return
		}

		user := BulkUserRecord{
			Active: true, // Default to active
		}

		if idx, ok := colIndex["email"]; ok && idx < len(record) {
			user.Email = record[idx]
		}
		if idx, ok := colIndex["first_name"]; ok && idx < len(record) {
			user.FirstName = record[idx]
		}
		if idx, ok := colIndex["last_name"]; ok && idx < len(record) {
			user.LastName = record[idx]
		}
		if idx, ok := colIndex["username"]; ok && idx < len(record) {
			user.Username = record[idx]
		}
		if idx, ok := colIndex["phone"]; ok && idx < len(record) {
			user.Phone = record[idx]
		}
		if idx, ok := colIndex["roles"]; ok && idx < len(record) {
			user.Roles = record[idx]
		}
		if idx, ok := colIndex["password"]; ok && idx < len(record) {
			user.Password = record[idx]
		}
		if idx, ok := colIndex["active"]; ok && idx < len(record) {
			user.Active = record[idx] == "true" || record[idx] == "1" || record[idx] == "yes"
		}

		users = append(users, user)
	}

	if len(users) > 1000 {
		h.writeError(w, http.StatusBadRequest, "Maximum 1000 users per import", nil)
		return
	}

	req := BulkUserImportRequest{
		Users:        users,
		SkipExisting: skipExisting,
		ValidateOnly: validateOnly,
		SendWelcome:  sendWelcome,
	}

	result := h.processUserImport(r, req)
	writeJSON(w, http.StatusOK, result)
}

// processUserImport processes the user import request.
func (h *Handler) processUserImport(r *http.Request, req BulkUserImportRequest) *BulkImportResult {
	result := &BulkImportResult{
		TotalRecords: len(req.Users),
		ValidateOnly: req.ValidateOnly,
	}

	ctx := r.Context()

	for i, record := range req.Users {
		row := i + 1 // 1-indexed for user-friendly messages

		// Validate email
		if record.Email == "" {
			result.Errors = append(result.Errors, UserBulkImportError{
				Row:     row,
				Email:   record.Email,
				Field:   "email",
				Message: "Email is required",
			})
			result.FailureCount++
			continue
		}

		// Check if user exists
		existingUser, _ := h.storage.GetUserByEmail(ctx, record.Email)
		if existingUser != nil {
			if req.SkipExisting {
				result.SkippedCount++
				continue
			}
			result.Errors = append(result.Errors, UserBulkImportError{
				Row:     row,
				Email:   record.Email,
				Field:   "email",
				Message: "User already exists",
			})
			result.FailureCount++
			continue
		}

		// Validate password if provided
		if record.Password != "" {
			if err := utils.ValidatePasswordWithContext(record.Password, nil, record.Email, record.Username); err != nil {
				result.Errors = append(result.Errors, UserBulkImportError{
					Row:     row,
					Email:   record.Email,
					Field:   "password",
					Message: err.Error(),
				})
				result.FailureCount++
				continue
			}
		}

		// Skip actual creation in validate-only mode
		if req.ValidateOnly {
			result.SuccessCount++
			continue
		}

		// Create user
		now := time.Now()
		user := &storage.User{
			ID:              uuid.New(),
			Email:           record.Email,
			IsEmailVerified: false,
			IsActive:        record.Active,
			Timezone:        "UTC",
			Locale:          "en",
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		if record.FirstName != "" {
			user.FirstName = &record.FirstName
		}
		if record.LastName != "" {
			user.LastName = &record.LastName
		}
		if record.Username != "" {
			user.Username = &record.Username
		}
		if record.Phone != "" {
			user.Phone = &record.Phone
		}

		// Hash password or generate temporary one
		if record.Password != "" {
			hashedPassword, err := utils.HashPassword(record.Password, nil)
			if err != nil {
				result.Errors = append(result.Errors, UserBulkImportError{
					Row:     row,
					Email:   record.Email,
					Message: "Failed to hash password",
				})
				result.FailureCount++
				continue
			}
			user.HashedPassword = hashedPassword
		} else {
			// Generate a random password that user must reset
			tempPassword := utils.GenerateRandomToken(16)
			hashedPassword, err := utils.HashPassword(tempPassword, nil)
			if err != nil {
				result.Errors = append(result.Errors, UserBulkImportError{
					Row:     row,
					Email:   record.Email,
					Message: "Failed to generate password",
				})
				result.FailureCount++
				continue
			}
			user.HashedPassword = hashedPassword
		}

		// Create user in database
		if err := h.storage.CreateUser(ctx, user); err != nil {
			result.Errors = append(result.Errors, UserBulkImportError{
				Row:     row,
				Email:   record.Email,
				Message: fmt.Sprintf("Failed to create user: %v", err),
			})
			result.FailureCount++
			continue
		}

		result.SuccessCount++
		result.CreatedUsers = append(result.CreatedUsers, user.ID.String())

		// TODO: Assign roles if specified
		// TODO: Send welcome email if requested
	}

	return result
}

// ExportUsers handles GET /v1/admin/users/export
func (h *Handler) ExportUsers(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	activeOnly := r.URL.Query().Get("active_only") == "true"
	includeRoles := r.URL.Query().Get("include_roles") == "true"

	// Get all users (with pagination for large datasets)
	limit := 10000
	offset := 0

	users, err := h.storage.ListUsers(r.Context(), limit, offset)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to list users", err)
		return
	}

	// Filter if needed
	if activeOnly {
		var filtered []*storage.User
		for _, u := range users {
			if u.IsActive {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	switch format {
	case "csv":
		h.exportUsersCSV(w, users, includeRoles)
	case "json":
		h.exportUsersJSON(w, users, includeRoles)
	default:
		h.writeError(w, http.StatusBadRequest, "Invalid format. Use 'csv' or 'json'", nil)
	}
}

// exportUsersCSV exports users in CSV format.
func (h *Handler) exportUsersCSV(w http.ResponseWriter, users []*storage.User, includeRoles bool) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=users_export_%s.csv", time.Now().Format("20060102")))

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"id", "email", "username", "first_name", "last_name", "phone", "is_active", "is_email_verified", "created_at"}
	if includeRoles {
		header = append(header, "roles")
	}
	if err := writer.Write(header); err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to write CSV header", err)
		return
	}

	// Write records
	for _, user := range users {
		record := []string{
			user.ID.String(),
			user.Email,
			stringOrEmpty(user.Username),
			stringOrEmpty(user.FirstName),
			stringOrEmpty(user.LastName),
			stringOrEmpty(user.Phone),
			fmt.Sprintf("%v", user.IsActive),
			fmt.Sprintf("%v", user.IsEmailVerified),
			user.CreatedAt.Format(time.RFC3339),
		}
		if includeRoles {
			// TODO: Get user roles
			record = append(record, "")
		}
		if err := writer.Write(record); err != nil {
			h.writeError(w, http.StatusInternalServerError, "Failed to write CSV record", err)
			return
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "Failed to flush CSV", err)
		return
	}

	w.Write(buf.Bytes())
}

// exportUsersJSON exports users in JSON format.
func (h *Handler) exportUsersJSON(w http.ResponseWriter, users []*storage.User, includeRoles bool) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=users_export_%s.json", time.Now().Format("20060102")))

	response := map[string]interface{}{
		"users":      users,
		"count":      len(users),
		"exported_at": time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode JSON export", "error", err)
	}
}

// stringOrEmpty returns the string value or empty string if nil.
func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
