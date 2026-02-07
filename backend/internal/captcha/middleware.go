package captcha

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// Middleware returns a chi-compatible middleware that verifies CAPTCHA tokens.
//
// Token resolution order:
//  1. X-Captcha-Token header
//  2. "captcha_token" field in the JSON request body (body is re-buffered so
//     downstream handlers can still read it)
//
// If the captcha service is disabled (NoopService), the middleware passes
// through without checking anything.
func Middleware(svc Service) func(http.Handler) http.Handler {
	logger := slog.Default().With("component", "captcha_middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip verification when captcha is not enabled.
			if !svc.IsEnabled() {
				next.ServeHTTP(w, r)
				return
			}

			token := r.Header.Get("X-Captcha-Token")

			// If no header, try to extract from JSON body.
			if token == "" && r.Body != nil {
				bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				if err == nil {
					// Re-buffer body so downstream handlers can read it.
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

					var bodyMap map[string]json.RawMessage
					if json.Unmarshal(bodyBytes, &bodyMap) == nil {
						if raw, ok := bodyMap["captcha_token"]; ok {
							var t string
							if json.Unmarshal(raw, &t) == nil {
								token = t
							}
						}
					}
				}
			}

			if token == "" {
				logger.Warn("CAPTCHA token missing", "remote_addr", r.RemoteAddr, "path", r.URL.Path)
				writeJSONError(w, http.StatusForbidden, "CAPTCHA verification required")
				return
			}

			// Use X-Forwarded-For / X-Real-IP if available (chi middleware.RealIP sets RemoteAddr).
			remoteIP := r.RemoteAddr

			result, err := svc.Verify(r.Context(), token, remoteIP)
			if err != nil {
				logger.Error("CAPTCHA verification error", "error", err, "remote_addr", remoteIP)
				writeJSONError(w, http.StatusInternalServerError, "CAPTCHA verification failed")
				return
			}

			if !result.Success {
				logger.Warn("CAPTCHA verification failed",
					"remote_addr", remoteIP,
					"error_codes", result.ErrorCodes,
					"score", result.Score,
					"path", r.URL.Path,
				)
				writeJSONError(w, http.StatusForbidden, "CAPTCHA verification failed")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// writeJSONError writes a JSON error response matching the project's ErrorResponse format.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   http.StatusText(status),
		"message": message,
	})
}
