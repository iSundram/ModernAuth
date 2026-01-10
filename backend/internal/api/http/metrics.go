package http

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "modernauth_http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"path", "method", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "modernauth_http_request_duration_seconds",
			Help: "Duration of HTTP requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path", "method"},
	)

	authSuccessTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "modernauth_auth_success_total",
			Help: "Total number of successful authentications.",
		},
		[]string{"type"}, // register, login, refresh
	)

	authFailureTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "modernauth_auth_failure_total",
			Help: "Total number of failed authentications.",
		},
		[]string{"type", "reason"},
	)

	activeSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "modernauth_active_sessions",
			Help: "Current number of active sessions.",
		},
	)
)
