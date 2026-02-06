package email

import (
	"context"
	"testing"

	"github.com/iSundram/ModernAuth/internal/storage"
)

func TestNewTemplateVars(t *testing.T) {
	firstName := "John"
	lastName := "Doe"
	user := &storage.User{
		Email:     "john@example.com",
		FirstName: &firstName,
		LastName:  &lastName,
	}

	branding := &storage.EmailBranding{
		AppName:        "TestApp",
		PrimaryColor:   "#FF0000",
		SecondaryColor: "#00FF00",
	}

	vars := NewTemplateVars(user, branding)

	if vars.FullName != "John Doe" {
		t.Errorf("Expected FullName 'John Doe', got '%s'", vars.FullName)
	}

	if vars.PrimaryColor != "#FF0000" {
		t.Errorf("Expected PrimaryColor '#FF0000', got '%s'", vars.PrimaryColor)
	}

	if vars.AppName != "TestApp" {
		t.Errorf("Expected AppName 'TestApp', got '%s'", vars.AppName)
	}
}

func TestTemplateVars_WithVerification(t *testing.T) {
	firstName := "Jane"
	user := &storage.User{
		Email:     "jane@example.com",
		FirstName: &firstName,
	}

	vars := NewTemplateVars(user, nil).WithVerification("token123", "https://example.com/verify")

	if vars.Token != "token123" {
		t.Errorf("Expected Token 'token123', got '%s'", vars.Token)
	}

	if vars.VerifyURL != "https://example.com/verify" {
		t.Errorf("Expected VerifyURL 'https://example.com/verify', got '%s'", vars.VerifyURL)
	}
}

func TestTemplateVars_WithMFACode(t *testing.T) {
	user := &storage.User{
		Email: "test@example.com",
	}

	vars := NewTemplateVars(user, nil).WithMFACode("123456")

	if vars.MFACode != "123456" {
		t.Errorf("Expected MFACode '123456', got '%s'", vars.MFACode)
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name       string
		acceptLang string
		userLang   string
		expected   string
	}{
		{"user lang priority", "fr", "es", "es"},
		{"accept language", "de", "", "de"},
		{"empty", "", "", "en"},
		{"extract primary", "en-US,fr-CA", "", "en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectLanguage(context.Background(), tt.acceptLang, tt.userLang)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestTemplateVars_WithSecurityAlert(t *testing.T) {
	user := &storage.User{
		Email: "alert@example.com",
	}

	vars := NewTemplateVars(user, nil).WithSecurityAlert(
		"Login Attempt",
		"Someone tried to login",
		"From IP 192.168.1.1",
		"https://example.com/review",
		"Review Now",
	)

	if vars.AlertTitle != "Login Attempt" {
		t.Errorf("Expected AlertTitle 'Login Attempt', got '%s'", vars.AlertTitle)
	}

	if vars.AlertMessage != "Someone tried to login" {
		t.Errorf("Expected AlertMessage 'Someone tried to login', got '%s'", vars.AlertMessage)
	}

	if vars.ActionURL != "https://example.com/review" {
		t.Errorf("Expected ActionURL 'https://example.com/review', got '%s'", vars.ActionURL)
	}
}

func TestTemplateVars_WithMagicLink(t *testing.T) {
	user := &storage.User{
		Email: "magic@example.com",
	}

	vars := NewTemplateVars(user, nil).WithMagicLink("https://example.com/login?token=xyz")

	if vars.MagicLinkURL != "https://example.com/login?token=xyz" {
		t.Errorf("Expected MagicLinkURL, got '%s'", vars.MagicLinkURL)
	}
}

func TestTemplateVars_WithEmailChange(t *testing.T) {
	user := &storage.User{
		Email: "new@example.com",
	}

	vars := NewTemplateVars(user, nil).WithEmailChange("old@example.com", "new@example.com")

	if vars.OldEmail != "old@example.com" {
		t.Errorf("Expected OldEmail 'old@example.com', got '%s'", vars.OldEmail)
	}

	if vars.NewEmail != "new@example.com" {
		t.Errorf("Expected NewEmail 'new@example.com', got '%s'", vars.NewEmail)
	}
}
