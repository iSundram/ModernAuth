// Package main provides the entry point for the ModernAuth server.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	httpapi "github.com/iSundram/ModernAuth/internal/api/http"
	"github.com/iSundram/ModernAuth/internal/auth"
	"github.com/iSundram/ModernAuth/internal/config"
	"github.com/iSundram/ModernAuth/internal/storage/pg"
)

func main() {
	// Initialize structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create database connection pool
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Verify database connection
	if err := pool.Ping(ctx); err != nil {
		slog.Error("Failed to ping database", "error", err)
		os.Exit(1)
	}
	slog.Info("Connected to database")

	// Initialize Redis client
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		slog.Error("Failed to parse REDIS_URL", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		slog.Error("Failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	defer rdb.Close()
	slog.Info("Connected to Redis")

	// Initialize storage
	storage := pg.NewPostgresStorage(pool)

	// Initialize token service
	tokenConfig := &auth.TokenConfig{
		Issuer:          cfg.Auth.Issuer,
		AccessTokenTTL:  cfg.Auth.AccessTokenTTL,
		RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
		SigningKey:      []byte(cfg.Auth.JWTSecret),
		SigningMethod:   auth.DefaultTokenConfig().SigningMethod,
	}
	tokenService := auth.NewTokenService(tokenConfig)

	// Initialize account lockout
	lockoutConfig := &auth.LockoutConfig{
		MaxAttempts:     cfg.Lockout.MaxAttempts,
		LockoutWindow:   cfg.Lockout.LockoutWindow,
		LockoutDuration: cfg.Lockout.LockoutDuration,
	}
	accountLockout := auth.NewAccountLockout(rdb, lockoutConfig)

	// Initialize token blacklist
	tokenBlacklist := auth.NewTokenBlacklist(rdb)

	// Initialize auth service
	authService := auth.NewAuthService(storage, tokenService, cfg.Auth.SessionTTL)

	// Initialize HTTP handler
	handler := httpapi.NewHandler(authService, tokenService, rdb, accountLockout, tokenBlacklist)
	router := handler.Router()

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.App.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		slog.Info("Starting server", "port", cfg.App.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server stopped")
}
