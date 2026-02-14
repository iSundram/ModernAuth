// Package email provides HTML email templates for ModernAuth.
package email

import (
	"embed"
)

//go:embed defaults/*.html defaults/*.txt
var DefaultTemplatesFS embed.FS

// Default theme colors - can be overridden via branding settings
const (
	DefaultPrimaryColor    = "#2B2B2B" // Dark - headers, buttons
	DefaultSecondaryColor  = "#B3B3B3" // Medium gray - accents
	DefaultBackgroundColor = "#FFFFFF" // White - content background
	DefaultBorderColor     = "#D4D4D4" // Light gray - borders
	DefaultTextPrimary     = "#2B2B2B" // Dark - primary text
	DefaultTextSecondary   = "#B3B3B3" // Medium gray - secondary text
	DefaultTextMuted       = "#D4D4D4" // Light gray - footer text
)

const TrackingPixel = `<img src="{{.BaseURL}}/v1/email/track/open/{{.PixelID}}" width="1" height="1" alt="" style="display:none;" />`
