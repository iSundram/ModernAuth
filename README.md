<p align="center">
  <img src="docs/assets/logo.svg" alt="ModernAuth Logo" width="200">
</p>

# ModernAuth

A modern, Go-native authentication & identity core.

## Overview

ModernAuth  is a Go-native authentication and identity core intended to be embedded into products (SaaS, control panels, developer platforms) or run as a standalone auth service.

## Features

- **Go-Native**: Built with Go 1.23+ following Clean Architecture.
- **Config Management**: Centralized configuration via environment variables and `.env` files using `cleanenv`.
- **MFA (TOTP)**: Built-in support for Time-based One-Time Passwords.
- **Observability**: 
    - **Prometheus Metrics**: Request latency, counts, and authentication success/failure rates.
    - **Structured Logging**: Production-ready JSON logging using `slog`.
- **Secure Token Management**: Stateless JWT access tokens and stateful opaque refresh tokens.
- **Session Security**: Built-in token reuse detection to prevent token theft.
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints.
- **Audit Trails**: Comprehensive database-backed audit logging for all auth events.
- **Docker Ready**: Easy deployment with Docker and Docker Compose.

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- Make

### Using the Makefile

The project includes a `Makefile` for common development tasks:

```bash
# Setup environment (manual step)
cp .env.example .env

# Start database and redis
make docker-up

# Build and run the server
make run

# Run tests
make test
```

### Metrics

Metrics are exposed at `/metrics` in Prometheus format.

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

