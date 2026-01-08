<p align="center">
  <img src="docs/assets/logo.svg" alt="ModernAuth Logo" width="200">
</p>

# ModernAuth

A modern, Go-native authentication & identity core.

## Overview

ModernAuth  is a Go-native authentication and identity core intended to be embedded into products (SaaS, control panels, developer platforms) or run as a standalone auth service.

## Features

- **Go-Native**: Built with Go 1.23+ and minimal dependencies.
- **Secure Token Management**: Stateless JWT access tokens and stateful opaque refresh tokens.
- **Session Security**: Built-in token reuse detection to prevent token theft.
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints.
- **Structured Logging**: Production-ready JSON logging using `slog`.
- **Audit Trails**: Comprehensive database-backed audit logging for all auth events.
- **Docker Ready**: Easy deployment with Docker and Docker Compose.

## Quick Start

### Prerequisites

- Go 1.21+
- Docker & Docker Compose
- Make (optional)

### Running with Docker Compose

```bash
# Start all services (Postgres, Redis, Auth server)
docker-compose up -d

# View logs
docker-compose logs -f auth-server

# Stop all services
docker-compose down
```

### Running Locally

```bash
# Install dependencies
go mod download

# Set environment variables
export DATABASE_URL="postgres://modernauth:modernauth@localhost:5432/modernauth?sslmode=disable"
export REDIS_URL="redis://localhost:6379"
export JWT_SECRET="your-secret-key-at-least-32-chars"

# Run the server
go run ./cmd/auth-server

# Server starts on http://localhost:8080
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./internal/auth/...
```

## License

MIT License

