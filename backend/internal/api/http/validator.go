// Package http provides HTTP handlers for ModernAuth API.
package http

import (
	"net/mail"
	"sync"

	"github.com/go-playground/validator/v10"
)

var (
	validate     *validator.Validate
	validateOnce sync.Once
)

// GetValidator returns a singleton validator instance.
func GetValidator() *validator.Validate {
	validateOnce.Do(func() {
		validate = validator.New()
		
		// Register custom email validation that's more lenient
		validate.RegisterValidation("custom_email", validateEmail)
	})
	return validate
}

// validateEmail performs email validation using net/mail.
func validateEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	_, err := mail.ParseAddress(email)
	return err == nil
}

// ValidationError represents a field validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidateStruct validates a struct and returns user-friendly error messages.
func ValidateStruct(s interface{}) []ValidationError {
	var errors []ValidationError
	
	err := GetValidator().Struct(s)
	if err == nil {
		return nil
	}

	for _, err := range err.(validator.ValidationErrors) {
		var message string
		switch err.Tag() {
		case "required":
			message = err.Field() + " is required"
		case "email", "custom_email":
			message = err.Field() + " must be a valid email address"
		case "min":
			message = err.Field() + " must be at least " + err.Param() + " characters"
		case "max":
			message = err.Field() + " must be at most " + err.Param() + " characters"
		case "uuid":
			message = err.Field() + " must be a valid UUID"
		case "len":
			message = err.Field() + " must be exactly " + err.Param() + " characters"
		default:
			message = err.Field() + " is invalid"
		}
		errors = append(errors, ValidationError{
			Field:   err.Field(),
			Message: message,
		})
	}
	
	return errors
}
