// Package branding provides tenant branding management for ModernAuth.
package branding

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/iSundram/ModernAuth/internal/storage"
)

// Common errors
var (
	ErrBrandingNotFound      = errors.New("branding not found")
	ErrThemeNotFound         = errors.New("theme not found")
	ErrAssetNotFound         = errors.New("asset not found")
	ErrPageNotFound          = errors.New("page not found")
	ErrDomainNotFound        = errors.New("domain not found")
	ErrDomainAlreadyExists   = errors.New("domain already exists")
	ErrDomainNotVerified     = errors.New("domain not verified")
	ErrDomainVerificationFailed = errors.New("domain verification failed")
	ErrDarkModeNotFound      = errors.New("dark mode settings not found")
)

// Service provides branding management operations.
type Service struct {
	storage storage.BrandingStorage
	logger  *slog.Logger
}

// NewService creates a new branding service.
func NewService(store storage.BrandingStorage) *Service {
	return &Service{
		storage: store,
		logger:  slog.Default().With("component", "branding_service"),
	}
}

// ============================================================================
// Tenant Branding
// ============================================================================

// CreateBrandingRequest represents a request to create tenant branding.
type CreateBrandingRequest struct {
	TenantID             uuid.UUID              `json:"tenant_id"`
	CompanyName          string                 `json:"company_name,omitempty"`
	Tagline              *string                `json:"tagline,omitempty"`
	PrimaryColor         string                 `json:"primary_color,omitempty"`
	SecondaryColor       string                 `json:"secondary_color,omitempty"`
	AccentColor          string                 `json:"accent_color,omitempty"`
	FontFamily           string                 `json:"font_family,omitempty"`
	FontFamilyURL        *string                `json:"font_family_url,omitempty"`
	HeadingFont          *string                `json:"heading_font,omitempty"`
	HeadingFontURL       *string                `json:"heading_font_url,omitempty"`
	BaseFontSize         int                    `json:"base_font_size,omitempty"`
	LogoURL              *string                `json:"logo_url,omitempty"`
	LogoURLDark          *string                `json:"logo_url_dark,omitempty"`
	FaviconURL           *string                `json:"favicon_url,omitempty"`
	LogoWidth            int                    `json:"logo_width,omitempty"`
	LogoHeight           int                    `json:"logo_height,omitempty"`
	BackgroundColor      string                 `json:"background_color,omitempty"`
	BackgroundURL        *string                `json:"background_url,omitempty"`
	BackgroundPosition   string                 `json:"background_position,omitempty"`
	BackgroundSize       string                 `json:"background_size,omitempty"`
	CardBackground       string                 `json:"card_background,omitempty"`
	CardBorderRadius     int                    `json:"card_border_radius,omitempty"`
	CardShadow           string                 `json:"card_shadow,omitempty"`
	InputBorderRadius    int                    `json:"input_border_radius,omitempty"`
	InputBorderColor     string                 `json:"input_border_color,omitempty"`
	InputFocusColor      string                 `json:"input_focus_color,omitempty"`
	ButtonBorderRadius   int                    `json:"button_border_radius,omitempty"`
	ButtonStyle          string                 `json:"button_style,omitempty"`
	LinkColor            string                 `json:"link_color,omitempty"`
	LinkHoverColor       string                 `json:"link_hover_color,omitempty"`
	FooterText           *string                `json:"footer_text,omitempty"`
	FooterLinks          []storage.BrandingFooterLink `json:"footer_links,omitempty"`
	ShowPoweredBy        *bool                  `json:"show_powered_by,omitempty"`
	CustomCSS            *string                `json:"custom_css,omitempty"`
	CustomJS             *string                `json:"custom_js,omitempty"`
	ThemeMode            string                 `json:"theme_mode,omitempty"`
	EnableDarkMode       *bool                  `json:"enable_dark_mode,omitempty"`
}

// CreateBranding creates tenant branding.
func (s *Service) CreateBranding(ctx context.Context, req *CreateBrandingRequest) (*storage.TenantBranding, error) {
	now := time.Now()

	// Set defaults
	showPoweredBy := true
	if req.ShowPoweredBy != nil {
		showPoweredBy = *req.ShowPoweredBy
	}
	enableDarkMode := false
	if req.EnableDarkMode != nil {
		enableDarkMode = *req.EnableDarkMode
	}

	branding := &storage.TenantBranding{
		ID:                 uuid.New(),
		TenantID:           req.TenantID,
		CompanyName:        req.CompanyName,
		Tagline:            req.Tagline,
		PrimaryColor:       defaultValue(req.PrimaryColor, "#2563EB"),
		SecondaryColor:     defaultValue(req.SecondaryColor, "#1E40AF"),
		AccentColor:        defaultValue(req.AccentColor, "#3B82F6"),
		FontFamily:         defaultValue(req.FontFamily, "Inter"),
		FontFamilyURL:      req.FontFamilyURL,
		HeadingFont:        req.HeadingFont,
		HeadingFontURL:     req.HeadingFontURL,
		BaseFontSize:       defaultInt(req.BaseFontSize, 16),
		LogoURL:            req.LogoURL,
		LogoURLDark:        req.LogoURLDark,
		FaviconURL:         req.FaviconURL,
		LogoWidth:          defaultInt(req.LogoWidth, 150),
		LogoHeight:         defaultInt(req.LogoHeight, 50),
		BackgroundColor:    defaultValue(req.BackgroundColor, "#FFFFFF"),
		BackgroundURL:      req.BackgroundURL,
		BackgroundPosition: defaultValue(req.BackgroundPosition, "center"),
		BackgroundSize:     defaultValue(req.BackgroundSize, "cover"),
		CardBackground:     defaultValue(req.CardBackground, "#FFFFFF"),
		CardBorderRadius:   defaultInt(req.CardBorderRadius, 12),
		CardShadow:         defaultValue(req.CardShadow, "0 4px 6px -1px rgb(0 0 0 / 0.1)"),
		InputBorderRadius:  defaultInt(req.InputBorderRadius, 8),
		InputBorderColor:   defaultValue(req.InputBorderColor, "#D1D5DB"),
		InputFocusColor:    defaultValue(req.InputFocusColor, "#2563EB"),
		ButtonBorderRadius: defaultInt(req.ButtonBorderRadius, 8),
		ButtonStyle:        defaultValue(req.ButtonStyle, "rounded"),
		LinkColor:          defaultValue(req.LinkColor, "#2563EB"),
		LinkHoverColor:     defaultValue(req.LinkHoverColor, "#1E40AF"),
		FooterText:         req.FooterText,
		FooterLinks:        req.FooterLinks,
		ShowPoweredBy:      showPoweredBy,
		CustomCSS:          req.CustomCSS,
		CustomJS:           req.CustomJS,
		ThemeMode:          defaultValue(req.ThemeMode, "light"),
		EnableDarkMode:     enableDarkMode,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := s.storage.CreateTenantBranding(ctx, branding); err != nil {
		return nil, err
	}

	s.logger.Info("Branding created", "tenant_id", req.TenantID)
	return branding, nil
}

// GetBranding retrieves branding for a tenant.
func (s *Service) GetBranding(ctx context.Context, tenantID uuid.UUID) (*storage.TenantBranding, error) {
	branding, err := s.storage.GetTenantBranding(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if branding == nil {
		return nil, ErrBrandingNotFound
	}
	return branding, nil
}

// GetOrCreateBranding retrieves or creates branding for a tenant.
func (s *Service) GetOrCreateBranding(ctx context.Context, tenantID uuid.UUID) (*storage.TenantBranding, error) {
	branding, err := s.storage.GetTenantBranding(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if branding != nil {
		return branding, nil
	}

	// Create default branding
	return s.CreateBranding(ctx, &CreateBrandingRequest{TenantID: tenantID})
}

// UpdateBrandingRequest represents a request to update branding.
type UpdateBrandingRequest struct {
	CompanyName        *string                      `json:"company_name,omitempty"`
	Tagline            *string                      `json:"tagline,omitempty"`
	PrimaryColor       *string                      `json:"primary_color,omitempty"`
	SecondaryColor     *string                      `json:"secondary_color,omitempty"`
	AccentColor        *string                      `json:"accent_color,omitempty"`
	FontFamily         *string                      `json:"font_family,omitempty"`
	FontFamilyURL      *string                      `json:"font_family_url,omitempty"`
	HeadingFont        *string                      `json:"heading_font,omitempty"`
	HeadingFontURL     *string                      `json:"heading_font_url,omitempty"`
	BaseFontSize       *int                         `json:"base_font_size,omitempty"`
	LogoURL            *string                      `json:"logo_url,omitempty"`
	LogoURLDark        *string                      `json:"logo_url_dark,omitempty"`
	FaviconURL         *string                      `json:"favicon_url,omitempty"`
	LogoWidth          *int                         `json:"logo_width,omitempty"`
	LogoHeight         *int                         `json:"logo_height,omitempty"`
	BackgroundColor    *string                      `json:"background_color,omitempty"`
	BackgroundURL      *string                      `json:"background_url,omitempty"`
	BackgroundPosition *string                      `json:"background_position,omitempty"`
	BackgroundSize     *string                      `json:"background_size,omitempty"`
	CardBackground     *string                      `json:"card_background,omitempty"`
	CardBorderRadius   *int                         `json:"card_border_radius,omitempty"`
	CardShadow         *string                      `json:"card_shadow,omitempty"`
	InputBorderRadius  *int                         `json:"input_border_radius,omitempty"`
	InputBorderColor   *string                      `json:"input_border_color,omitempty"`
	InputFocusColor    *string                      `json:"input_focus_color,omitempty"`
	ButtonBorderRadius *int                         `json:"button_border_radius,omitempty"`
	ButtonStyle        *string                      `json:"button_style,omitempty"`
	LinkColor          *string                      `json:"link_color,omitempty"`
	LinkHoverColor     *string                      `json:"link_hover_color,omitempty"`
	FooterText         *string                      `json:"footer_text,omitempty"`
	FooterLinks        []storage.BrandingFooterLink `json:"footer_links,omitempty"`
	ShowPoweredBy      *bool                        `json:"show_powered_by,omitempty"`
	CustomCSS          *string                      `json:"custom_css,omitempty"`
	CustomJS           *string                      `json:"custom_js,omitempty"`
	ThemeMode          *string                      `json:"theme_mode,omitempty"`
	EnableDarkMode     *bool                        `json:"enable_dark_mode,omitempty"`
}

// UpdateBranding updates tenant branding.
func (s *Service) UpdateBranding(ctx context.Context, tenantID uuid.UUID, req *UpdateBrandingRequest) (*storage.TenantBranding, error) {
	branding, err := s.storage.GetTenantBranding(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if branding == nil {
		return nil, ErrBrandingNotFound
	}

	// Update fields
	if req.CompanyName != nil {
		branding.CompanyName = *req.CompanyName
	}
	if req.Tagline != nil {
		branding.Tagline = req.Tagline
	}
	if req.PrimaryColor != nil {
		branding.PrimaryColor = *req.PrimaryColor
	}
	if req.SecondaryColor != nil {
		branding.SecondaryColor = *req.SecondaryColor
	}
	if req.AccentColor != nil {
		branding.AccentColor = *req.AccentColor
	}
	if req.FontFamily != nil {
		branding.FontFamily = *req.FontFamily
	}
	if req.FontFamilyURL != nil {
		branding.FontFamilyURL = req.FontFamilyURL
	}
	if req.HeadingFont != nil {
		branding.HeadingFont = req.HeadingFont
	}
	if req.HeadingFontURL != nil {
		branding.HeadingFontURL = req.HeadingFontURL
	}
	if req.BaseFontSize != nil {
		branding.BaseFontSize = *req.BaseFontSize
	}
	if req.LogoURL != nil {
		branding.LogoURL = req.LogoURL
	}
	if req.LogoURLDark != nil {
		branding.LogoURLDark = req.LogoURLDark
	}
	if req.FaviconURL != nil {
		branding.FaviconURL = req.FaviconURL
	}
	if req.LogoWidth != nil {
		branding.LogoWidth = *req.LogoWidth
	}
	if req.LogoHeight != nil {
		branding.LogoHeight = *req.LogoHeight
	}
	if req.BackgroundColor != nil {
		branding.BackgroundColor = *req.BackgroundColor
	}
	if req.BackgroundURL != nil {
		branding.BackgroundURL = req.BackgroundURL
	}
	if req.BackgroundPosition != nil {
		branding.BackgroundPosition = *req.BackgroundPosition
	}
	if req.BackgroundSize != nil {
		branding.BackgroundSize = *req.BackgroundSize
	}
	if req.CardBackground != nil {
		branding.CardBackground = *req.CardBackground
	}
	if req.CardBorderRadius != nil {
		branding.CardBorderRadius = *req.CardBorderRadius
	}
	if req.CardShadow != nil {
		branding.CardShadow = *req.CardShadow
	}
	if req.InputBorderRadius != nil {
		branding.InputBorderRadius = *req.InputBorderRadius
	}
	if req.InputBorderColor != nil {
		branding.InputBorderColor = *req.InputBorderColor
	}
	if req.InputFocusColor != nil {
		branding.InputFocusColor = *req.InputFocusColor
	}
	if req.ButtonBorderRadius != nil {
		branding.ButtonBorderRadius = *req.ButtonBorderRadius
	}
	if req.ButtonStyle != nil {
		branding.ButtonStyle = *req.ButtonStyle
	}
	if req.LinkColor != nil {
		branding.LinkColor = *req.LinkColor
	}
	if req.LinkHoverColor != nil {
		branding.LinkHoverColor = *req.LinkHoverColor
	}
	if req.FooterText != nil {
		branding.FooterText = req.FooterText
	}
	if req.FooterLinks != nil {
		branding.FooterLinks = req.FooterLinks
	}
	if req.ShowPoweredBy != nil {
		branding.ShowPoweredBy = *req.ShowPoweredBy
	}
	if req.CustomCSS != nil {
		branding.CustomCSS = req.CustomCSS
	}
	if req.CustomJS != nil {
		branding.CustomJS = req.CustomJS
	}
	if req.ThemeMode != nil {
		branding.ThemeMode = *req.ThemeMode
	}
	if req.EnableDarkMode != nil {
		branding.EnableDarkMode = *req.EnableDarkMode
	}

	branding.UpdatedAt = time.Now()

	if err := s.storage.UpdateTenantBranding(ctx, branding); err != nil {
		return nil, err
	}

	s.logger.Info("Branding updated", "tenant_id", tenantID)
	return branding, nil
}

// DeleteBranding deletes tenant branding.
func (s *Service) DeleteBranding(ctx context.Context, tenantID uuid.UUID) error {
	if err := s.storage.DeleteTenantBranding(ctx, tenantID); err != nil {
		return err
	}
	s.logger.Info("Branding deleted", "tenant_id", tenantID)
	return nil
}

// ============================================================================
// Branding Assets
// ============================================================================

// CreateAssetRequest represents a request to create a branding asset.
type CreateAssetRequest struct {
	TenantID   uuid.UUID              `json:"tenant_id"`
	BrandingID uuid.UUID              `json:"branding_id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	FileURL    string                 `json:"file_url"`
	FileSize   *int                   `json:"file_size,omitempty"`
	MimeType   *string                `json:"mime_type,omitempty"`
	Width      *int                   `json:"width,omitempty"`
	Height     *int                   `json:"height,omitempty"`
	AltText    *string                `json:"alt_text,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	CreatedBy  *uuid.UUID             `json:"created_by,omitempty"`
}

// CreateAsset creates a branding asset.
func (s *Service) CreateAsset(ctx context.Context, req *CreateAssetRequest) (*storage.BrandingAsset, error) {
	now := time.Now()

	asset := &storage.BrandingAsset{
		ID:         uuid.New(),
		TenantID:   req.TenantID,
		BrandingID: req.BrandingID,
		Name:       req.Name,
		Type:       req.Type,
		FileURL:    req.FileURL,
		FileSize:   req.FileSize,
		MimeType:   req.MimeType,
		Width:      req.Width,
		Height:     req.Height,
		AltText:    req.AltText,
		IsActive:   true,
		Metadata:   req.Metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
		CreatedBy:  req.CreatedBy,
	}

	if err := s.storage.CreateBrandingAsset(ctx, asset); err != nil {
		return nil, err
	}

	s.logger.Info("Branding asset created", "asset_id", asset.ID, "type", req.Type)
	return asset, nil
}

// GetAsset retrieves a branding asset by ID.
func (s *Service) GetAsset(ctx context.Context, id uuid.UUID) (*storage.BrandingAsset, error) {
	asset, err := s.storage.GetBrandingAssetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if asset == nil {
		return nil, ErrAssetNotFound
	}
	return asset, nil
}

// ListAssets lists branding assets for a tenant.
func (s *Service) ListAssets(ctx context.Context, tenantID uuid.UUID, assetType string, activeOnly bool, limit, offset int) ([]*storage.BrandingAsset, error) {
	if limit <= 0 {
		limit = 50
	}

	opts := &storage.BrandingListOptions{
		TenantID: tenantID,
		Type:     assetType,
		Limit:    limit,
		Offset:   offset,
	}

	if activeOnly {
		active := true
		opts.Active = &active
	}

	return s.storage.ListBrandingAssets(ctx, opts)
}

// DeleteAsset deletes a branding asset.
func (s *Service) DeleteAsset(ctx context.Context, id uuid.UUID) error {
	if err := s.storage.DeleteBrandingAsset(ctx, id); err != nil {
		return err
	}
	s.logger.Info("Branding asset deleted", "asset_id", id)
	return nil
}

// ============================================================================
// Branding Themes
// ============================================================================

// ListThemes lists available branding themes.
func (s *Service) ListThemes(ctx context.Context, category string, activeOnly bool) ([]*storage.BrandingTheme, error) {
	return s.storage.ListBrandingThemes(ctx, category, activeOnly)
}

// GetThemeBySlug retrieves a theme by slug.
func (s *Service) GetThemeBySlug(ctx context.Context, slug string) (*storage.BrandingTheme, error) {
	theme, err := s.storage.GetBrandingThemeBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if theme == nil {
		return nil, ErrThemeNotFound
	}
	return theme, nil
}

// ApplyTheme applies a theme to tenant branding.
func (s *Service) ApplyTheme(ctx context.Context, tenantID uuid.UUID, themeSlug string) (*storage.TenantBranding, error) {
	theme, err := s.storage.GetBrandingThemeBySlug(ctx, themeSlug)
	if err != nil {
		return nil, err
	}
	if theme == nil {
		return nil, ErrThemeNotFound
	}

	_, err = s.GetOrCreateBranding(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Apply theme colors
	req := &UpdateBrandingRequest{
		PrimaryColor:     &theme.PrimaryColor,
		SecondaryColor:   &theme.SecondaryColor,
		AccentColor:      &theme.AccentColor,
		BackgroundColor:  &theme.BackgroundColor,
		FontFamily:       &theme.FontFamily,
		FontFamilyURL:    theme.FontFamilyURL,
		ButtonStyle:      &theme.ButtonStyle,
	}

	if theme.BorderRadius > 0 {
		req.CardBorderRadius = &theme.BorderRadius
		req.InputBorderRadius = &theme.BorderRadius
		req.ButtonBorderRadius = &theme.BorderRadius
	}

	return s.UpdateBranding(ctx, tenantID, req)
}

// ============================================================================
// Branding Pages
// ============================================================================

// CreatePageRequest represents a request to create a branding page.
type CreatePageRequest struct {
	TenantID             uuid.UUID              `json:"tenant_id"`
	BrandingID           uuid.UUID              `json:"branding_id"`
	PageType             string                 `json:"page_type"`
	Title                string                 `json:"title,omitempty"`
	Subtitle             *string                `json:"subtitle,omitempty"`
	Headline             *string                `json:"headline,omitempty"`
	Description          *string                `json:"description,omitempty"`
	BackgroundURL        *string                `json:"background_url,omitempty"`
	BackgroundColor      *string                `json:"background_color,omitempty"`
	HideLogo             *bool                  `json:"hide_logo,omitempty"`
	HideBackground       *bool                  `json:"hide_background,omitempty"`
	ShowSocialLogins     *bool                  `json:"show_social_logins,omitempty"`
	SocialLoginPosition  string                 `json:"social_login_position,omitempty"`
	ShowRememberMe       *bool                  `json:"show_remember_me,omitempty"`
	ShowForgotPassword   *bool                  `json:"show_forgot_password,omitempty"`
	ShowSignupLink       *bool                  `json:"show_signup_link,omitempty"`
	CustomHTML           *string                `json:"custom_html,omitempty"`
	CustomCSS            *string                `json:"custom_css,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

// CreatePage creates a branding page configuration.
func (s *Service) CreatePage(ctx context.Context, req *CreatePageRequest) (*storage.BrandingPage, error) {
	now := time.Now()

	// Set defaults
	hideLogo := false
	if req.HideLogo != nil {
		hideLogo = *req.HideLogo
	}
	hideBackground := false
	if req.HideBackground != nil {
		hideBackground = *req.HideBackground
	}
	showSocialLogins := true
	if req.ShowSocialLogins != nil {
		showSocialLogins = *req.ShowSocialLogins
	}
	showRememberMe := true
	if req.ShowRememberMe != nil {
		showRememberMe = *req.ShowRememberMe
	}
	showForgotPassword := true
	if req.ShowForgotPassword != nil {
		showForgotPassword = *req.ShowForgotPassword
	}
	showSignupLink := true
	if req.ShowSignupLink != nil {
		showSignupLink = *req.ShowSignupLink
	}

	page := &storage.BrandingPage{
		ID:                  uuid.New(),
		TenantID:            req.TenantID,
		BrandingID:          req.BrandingID,
		PageType:            req.PageType,
		Title:               req.Title,
		Subtitle:            req.Subtitle,
		Headline:            req.Headline,
		Description:         req.Description,
		BackgroundURL:       req.BackgroundURL,
		BackgroundColor:     req.BackgroundColor,
		HideLogo:            hideLogo,
		HideBackground:      hideBackground,
		ShowSocialLogins:    showSocialLogins,
		SocialLoginPosition: defaultValue(req.SocialLoginPosition, "top"),
		ShowRememberMe:      showRememberMe,
		ShowForgotPassword:  showForgotPassword,
		ShowSignupLink:      showSignupLink,
		CustomHTML:          req.CustomHTML,
		CustomCSS:           req.CustomCSS,
		Metadata:            req.Metadata,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if err := s.storage.CreateBrandingPage(ctx, page); err != nil {
		return nil, err
	}

	s.logger.Info("Branding page created", "tenant_id", req.TenantID, "page_type", req.PageType)
	return page, nil
}

// GetPage retrieves a branding page by type.
func (s *Service) GetPage(ctx context.Context, tenantID uuid.UUID, pageType string) (*storage.BrandingPage, error) {
	page, err := s.storage.GetBrandingPage(ctx, tenantID, pageType)
	if err != nil {
		return nil, err
	}
	if page == nil {
		return nil, ErrPageNotFound
	}
	return page, nil
}

// ListPages lists all branding pages for a tenant.
func (s *Service) ListPages(ctx context.Context, tenantID uuid.UUID) ([]*storage.BrandingPage, error) {
	return s.storage.ListBrandingPages(ctx, tenantID)
}

// UpdatePageRequest represents a request to update a branding page.
type UpdatePageRequest struct {
	Title               *string                `json:"title,omitempty"`
	Subtitle            *string                `json:"subtitle,omitempty"`
	Headline            *string                `json:"headline,omitempty"`
	Description         *string                `json:"description,omitempty"`
	BackgroundURL       *string                `json:"background_url,omitempty"`
	BackgroundColor     *string                `json:"background_color,omitempty"`
	HideLogo            *bool                  `json:"hide_logo,omitempty"`
	HideBackground      *bool                  `json:"hide_background,omitempty"`
	ShowSocialLogins    *bool                  `json:"show_social_logins,omitempty"`
	SocialLoginPosition *string                `json:"social_login_position,omitempty"`
	ShowRememberMe      *bool                  `json:"show_remember_me,omitempty"`
	ShowForgotPassword  *bool                  `json:"show_forgot_password,omitempty"`
	ShowSignupLink      *bool                  `json:"show_signup_link,omitempty"`
	CustomHTML          *string                `json:"custom_html,omitempty"`
	CustomCSS           *string                `json:"custom_css,omitempty"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

// UpdatePage updates a branding page.
func (s *Service) UpdatePage(ctx context.Context, tenantID uuid.UUID, pageType string, req *UpdatePageRequest) (*storage.BrandingPage, error) {
	page, err := s.storage.GetBrandingPage(ctx, tenantID, pageType)
	if err != nil {
		return nil, err
	}
	if page == nil {
		return nil, ErrPageNotFound
	}

	// Update fields
	if req.Title != nil {
		page.Title = *req.Title
	}
	if req.Subtitle != nil {
		page.Subtitle = req.Subtitle
	}
	if req.Headline != nil {
		page.Headline = req.Headline
	}
	if req.Description != nil {
		page.Description = req.Description
	}
	if req.BackgroundURL != nil {
		page.BackgroundURL = req.BackgroundURL
	}
	if req.BackgroundColor != nil {
		page.BackgroundColor = req.BackgroundColor
	}
	if req.HideLogo != nil {
		page.HideLogo = *req.HideLogo
	}
	if req.HideBackground != nil {
		page.HideBackground = *req.HideBackground
	}
	if req.ShowSocialLogins != nil {
		page.ShowSocialLogins = *req.ShowSocialLogins
	}
	if req.SocialLoginPosition != nil {
		page.SocialLoginPosition = *req.SocialLoginPosition
	}
	if req.ShowRememberMe != nil {
		page.ShowRememberMe = *req.ShowRememberMe
	}
	if req.ShowForgotPassword != nil {
		page.ShowForgotPassword = *req.ShowForgotPassword
	}
	if req.ShowSignupLink != nil {
		page.ShowSignupLink = *req.ShowSignupLink
	}
	if req.CustomHTML != nil {
		page.CustomHTML = req.CustomHTML
	}
	if req.CustomCSS != nil {
		page.CustomCSS = req.CustomCSS
	}
	if req.Metadata != nil {
		page.Metadata = req.Metadata
	}

	page.UpdatedAt = time.Now()

	if err := s.storage.UpdateBrandingPage(ctx, page); err != nil {
		return nil, err
	}

	s.logger.Info("Branding page updated", "tenant_id", tenantID, "page_type", pageType)
	return page, nil
}

// DeletePage deletes a branding page.
func (s *Service) DeletePage(ctx context.Context, id uuid.UUID) error {
	if err := s.storage.DeleteBrandingPage(ctx, id); err != nil {
		return err
	}
	s.logger.Info("Branding page deleted", "page_id", id)
	return nil
}

// ============================================================================
// Custom Domains
// ============================================================================

// CreateDomainRequest represents a request to create a custom domain.
type CreateDomainRequest struct {
	TenantID  uuid.UUID  `json:"tenant_id"`
	Domain    string     `json:"domain"`
	IsPrimary *bool      `json:"is_primary,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
}

// CreateDomainResult contains the created domain and verification details.
type CreateDomainResult struct {
	Domain           *storage.CustomDomain `json:"domain"`
	VerificationDNS  string                `json:"verification_dns"`  // DNS TXT record name
	VerificationValue string               `json:"verification_value"` // DNS TXT record value
}

// CreateDomain creates a custom domain for a tenant.
func (s *Service) CreateDomain(ctx context.Context, req *CreateDomainRequest) (*CreateDomainResult, error) {
	// Check if domain already exists
	existing, err := s.storage.GetCustomDomainByName(ctx, req.Domain)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrDomainAlreadyExists
	}

	now := time.Now()
	verificationToken := generateVerificationToken()

	isPrimary := false
	if req.IsPrimary != nil {
		isPrimary = *req.IsPrimary
	}

	domain := &storage.CustomDomain{
		ID:                uuid.New(),
		TenantID:          req.TenantID,
		Domain:            req.Domain,
		IsPrimary:         isPrimary,
		VerificationToken: verificationToken,
		VerificationMethod: "dns",
		SSLStatus:         "pending",
		Status:            "pending",
		CreatedAt:         now,
		UpdatedAt:         now,
		CreatedBy:         req.CreatedBy,
	}

	if err := s.storage.CreateCustomDomain(ctx, domain); err != nil {
		return nil, err
	}

	s.logger.Info("Custom domain created", "domain", req.Domain, "tenant_id", req.TenantID)

	return &CreateDomainResult{
		Domain:            domain,
		VerificationDNS:   "_modernauth-verify." + req.Domain,
		VerificationValue: "modernauth-verify=" + verificationToken,
	}, nil
}

// GetDomain retrieves a custom domain by ID.
func (s *Service) GetDomain(ctx context.Context, id uuid.UUID) (*storage.CustomDomain, error) {
	domain, err := s.storage.GetCustomDomainByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if domain == nil {
		return nil, ErrDomainNotFound
	}
	return domain, nil
}

// GetDomainByName retrieves a custom domain by name.
func (s *Service) GetDomainByName(ctx context.Context, domain string) (*storage.CustomDomain, error) {
	d, err := s.storage.GetCustomDomainByName(ctx, domain)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, ErrDomainNotFound
	}
	return d, nil
}

// ListDomains lists all custom domains for a tenant.
func (s *Service) ListDomains(ctx context.Context, tenantID uuid.UUID) ([]*storage.CustomDomain, error) {
	return s.storage.ListCustomDomains(ctx, tenantID)
}

// VerifyDomain verifies a custom domain by checking DNS TXT records.
func (s *Service) VerifyDomain(ctx context.Context, id uuid.UUID) (*storage.CustomDomain, error) {
	domain, err := s.storage.GetCustomDomainByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if domain == nil {
		return nil, ErrDomainNotFound
	}

	// Check if verification token exists
	if domain.VerificationToken == "" {
		return nil, fmt.Errorf("verification token not generated for domain")
	}

	// Perform actual DNS TXT record verification
	verified, verifyErr := s.verifyDomainDNS(domain.Domain, domain.VerificationToken)
	if verifyErr != nil {
		s.logger.Warn("DNS verification lookup failed", 
			"domain", domain.Domain, 
			"error", verifyErr,
		)
		// Don't fail completely - might be DNS propagation delay
	}

	if !verified {
		s.logger.Info("Domain verification failed - TXT record not found", 
			"domain", domain.Domain,
			"expected_token", domain.VerificationToken,
		)
		return nil, ErrDomainVerificationFailed
	}

	now := time.Now()
	domain.VerifiedAt = &now
	domain.Status = "active"
	domain.SSLStatus = "provisioning" // SSL will be provisioned next
	domain.UpdatedAt = now

	if err := s.storage.UpdateCustomDomain(ctx, domain); err != nil {
		return nil, err
	}

	s.logger.Info("Custom domain verified", "domain", domain.Domain)
	return domain, nil
}

// verifyDomainDNS checks if the verification TXT record exists in DNS.
// The expected TXT record format is: modernauth-verification=<token>
func (s *Service) verifyDomainDNS(domainName, verificationToken string) (bool, error) {
	// Look up TXT records for the domain
	// Users should add: _modernauth.example.com TXT "modernauth-verification=<token>"
	txtRecordName := "_modernauth." + domainName
	
	records, err := net.LookupTXT(txtRecordName)
	if err != nil {
		// Also try the root domain as fallback
		records, err = net.LookupTXT(domainName)
		if err != nil {
			return false, fmt.Errorf("DNS lookup failed: %w", err)
		}
	}

	expectedValue := "modernauth-verification=" + verificationToken
	
	for _, record := range records {
		// Normalize the record (remove whitespace)
		normalizedRecord := strings.TrimSpace(record)
		if normalizedRecord == expectedValue {
			return true, nil
		}
	}

	return false, nil
}

// SetPrimaryDomain sets a domain as the primary domain for a tenant.
func (s *Service) SetPrimaryDomain(ctx context.Context, tenantID, domainID uuid.UUID) error {
	domain, err := s.storage.GetCustomDomainByID(ctx, domainID)
	if err != nil {
		return err
	}
	if domain == nil {
		return ErrDomainNotFound
	}
	if domain.TenantID != tenantID {
		return ErrDomainNotFound
	}
	if domain.Status != "active" {
		return ErrDomainNotVerified
	}

	if err := s.storage.SetPrimaryDomain(ctx, tenantID, domainID); err != nil {
		return err
	}

	s.logger.Info("Primary domain set", "domain_id", domainID, "tenant_id", tenantID)
	return nil
}

// DeleteDomain deletes a custom domain.
func (s *Service) DeleteDomain(ctx context.Context, id uuid.UUID) error {
	if err := s.storage.DeleteCustomDomain(ctx, id); err != nil {
		return err
	}
	s.logger.Info("Custom domain deleted", "domain_id", id)
	return nil
}

// ============================================================================
// Dark Mode
// ============================================================================

// CreateDarkModeRequest represents a request to create dark mode settings.
type CreateDarkModeRequest struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	BrandingID        uuid.UUID `json:"branding_id"`
	PrimaryColor      string    `json:"primary_color,omitempty"`
	SecondaryColor    string    `json:"secondary_color,omitempty"`
	AccentColor       string    `json:"accent_color,omitempty"`
	BackgroundColor   string    `json:"background_color,omitempty"`
	CardBackground    string    `json:"card_background,omitempty"`
	SurfaceColor      string    `json:"surface_color,omitempty"`
	TextPrimary       string    `json:"text_primary,omitempty"`
	TextSecondary     string    `json:"text_secondary,omitempty"`
	TextMuted         string    `json:"text_muted,omitempty"`
	InputBackground   string    `json:"input_background,omitempty"`
	InputBorderColor  string    `json:"input_border_color,omitempty"`
	LogoURL           *string   `json:"logo_url,omitempty"`
	CustomCSS         *string   `json:"custom_css,omitempty"`
}

// CreateDarkMode creates dark mode settings for a tenant.
func (s *Service) CreateDarkMode(ctx context.Context, req *CreateDarkModeRequest) (*storage.BrandingDarkMode, error) {
	now := time.Now()

	darkMode := &storage.BrandingDarkMode{
		ID:               uuid.New(),
		TenantID:         req.TenantID,
		BrandingID:       req.BrandingID,
		PrimaryColor:     defaultValue(req.PrimaryColor, "#3B82F6"),
		SecondaryColor:   defaultValue(req.SecondaryColor, "#60A5FA"),
		AccentColor:      defaultValue(req.AccentColor, "#818CF8"),
		BackgroundColor:  defaultValue(req.BackgroundColor, "#111827"),
		CardBackground:   defaultValue(req.CardBackground, "#1F2937"),
		SurfaceColor:     defaultValue(req.SurfaceColor, "#374151"),
		TextPrimary:      defaultValue(req.TextPrimary, "#F9FAFB"),
		TextSecondary:    defaultValue(req.TextSecondary, "#D1D5DB"),
		TextMuted:        defaultValue(req.TextMuted, "#9CA3AF"),
		InputBackground:  defaultValue(req.InputBackground, "#374151"),
		InputBorderColor: defaultValue(req.InputBorderColor, "#4B5563"),
		LogoURL:          req.LogoURL,
		CustomCSS:        req.CustomCSS,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.storage.CreateBrandingDarkMode(ctx, darkMode); err != nil {
		return nil, err
	}

	s.logger.Info("Dark mode settings created", "tenant_id", req.TenantID)
	return darkMode, nil
}

// GetDarkMode retrieves dark mode settings for a tenant.
func (s *Service) GetDarkMode(ctx context.Context, tenantID uuid.UUID) (*storage.BrandingDarkMode, error) {
	darkMode, err := s.storage.GetBrandingDarkMode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if darkMode == nil {
		return nil, ErrDarkModeNotFound
	}
	return darkMode, nil
}

// GetOrCreateDarkMode retrieves or creates dark mode settings for a tenant.
func (s *Service) GetOrCreateDarkMode(ctx context.Context, tenantID uuid.UUID, brandingID uuid.UUID) (*storage.BrandingDarkMode, error) {
	darkMode, err := s.storage.GetBrandingDarkMode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if darkMode != nil {
		return darkMode, nil
	}

	return s.CreateDarkMode(ctx, &CreateDarkModeRequest{
		TenantID:   tenantID,
		BrandingID: brandingID,
	})
}

// UpdateDarkModeRequest represents a request to update dark mode settings.
type UpdateDarkModeRequest struct {
	PrimaryColor     *string `json:"primary_color,omitempty"`
	SecondaryColor   *string `json:"secondary_color,omitempty"`
	AccentColor      *string `json:"accent_color,omitempty"`
	BackgroundColor  *string `json:"background_color,omitempty"`
	CardBackground   *string `json:"card_background,omitempty"`
	SurfaceColor     *string `json:"surface_color,omitempty"`
	TextPrimary      *string `json:"text_primary,omitempty"`
	TextSecondary    *string `json:"text_secondary,omitempty"`
	TextMuted        *string `json:"text_muted,omitempty"`
	InputBackground  *string `json:"input_background,omitempty"`
	InputBorderColor *string `json:"input_border_color,omitempty"`
	LogoURL          *string `json:"logo_url,omitempty"`
	CustomCSS        *string `json:"custom_css,omitempty"`
}

// UpdateDarkMode updates dark mode settings for a tenant.
func (s *Service) UpdateDarkMode(ctx context.Context, tenantID uuid.UUID, req *UpdateDarkModeRequest) (*storage.BrandingDarkMode, error) {
	darkMode, err := s.storage.GetBrandingDarkMode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if darkMode == nil {
		return nil, ErrDarkModeNotFound
	}

	// Update fields
	if req.PrimaryColor != nil {
		darkMode.PrimaryColor = *req.PrimaryColor
	}
	if req.SecondaryColor != nil {
		darkMode.SecondaryColor = *req.SecondaryColor
	}
	if req.AccentColor != nil {
		darkMode.AccentColor = *req.AccentColor
	}
	if req.BackgroundColor != nil {
		darkMode.BackgroundColor = *req.BackgroundColor
	}
	if req.CardBackground != nil {
		darkMode.CardBackground = *req.CardBackground
	}
	if req.SurfaceColor != nil {
		darkMode.SurfaceColor = *req.SurfaceColor
	}
	if req.TextPrimary != nil {
		darkMode.TextPrimary = *req.TextPrimary
	}
	if req.TextSecondary != nil {
		darkMode.TextSecondary = *req.TextSecondary
	}
	if req.TextMuted != nil {
		darkMode.TextMuted = *req.TextMuted
	}
	if req.InputBackground != nil {
		darkMode.InputBackground = *req.InputBackground
	}
	if req.InputBorderColor != nil {
		darkMode.InputBorderColor = *req.InputBorderColor
	}
	if req.LogoURL != nil {
		darkMode.LogoURL = req.LogoURL
	}
	if req.CustomCSS != nil {
		darkMode.CustomCSS = req.CustomCSS
	}

	darkMode.UpdatedAt = time.Now()

	if err := s.storage.UpdateBrandingDarkMode(ctx, darkMode); err != nil {
		return nil, err
	}

	s.logger.Info("Dark mode settings updated", "tenant_id", tenantID)
	return darkMode, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateVerificationToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func defaultValue(value, defaultVal string) string {
	if value == "" {
		return defaultVal
	}
	return value
}

func defaultInt(value, defaultVal int) int {
	if value == 0 {
		return defaultVal
	}
	return value
}

// Helper to marshal to JSON
func marshalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}
