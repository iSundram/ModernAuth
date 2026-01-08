package http

import (
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimit middleware limits the number of requests from a single IP.
func (h *Handler) RateLimit(limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			// Handle cases where RemoteAddr includes port
			if lastColon := len(ip) - 1; lastColon >= 0 {
				for i := lastColon; i >= 0; i-- {
					if ip[i] == ':' {
						ip = ip[:i]
						break
					}
				}
			}

			key := fmt.Sprintf("ratelimit:%s:%s", r.URL.Path, ip)
			ctx := r.Context()

			count, err := h.rdb.Incr(ctx, key).Result()
			if err != nil {
				h.logger.Error("Rate limit error", "error", err)
				next.ServeHTTP(w, r)
				return
			}

			if count == 1 {
				h.rdb.Expire(ctx, key, window)
			}

			if count > int64(limit) {
				h.logger.Warn("Rate limit exceeded", "ip", ip, "path", r.URL.Path)
				h.writeError(w, http.StatusTooManyRequests, "Rate limit exceeded", nil)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
