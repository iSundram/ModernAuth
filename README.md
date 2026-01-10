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
- **Email Verification**: Token-based email verification flow.
- **Password Reset**: Secure password reset with time-limited tokens.
- **Account Lockout**: Protection against brute-force attacks with configurable lockout policies.
- **Token Blacklisting**: Redis-backed JWT access token blacklisting for immediate revocation.
- **Observability**: 
    - **Prometheus Metrics**: Request latency, counts, and authentication success/failure rates.
    - **Structured Logging**: Production-ready JSON logging using `slog`.
    - **Health Checks**: Service health endpoints with Redis connectivity status.
- **Secure Token Management**: Stateless JWT access tokens and stateful opaque refresh tokens.
- **Session Security**: Built-in token reuse detection to prevent token theft.
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints.
- **Audit Trails**: Comprehensive database-backed audit logging for all auth events.
- **Input Validation**: Request validation using go-playground/validator.
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

## API Endpoints

### Authentication
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/register` | POST | Register a new user |
| `/v1/auth/login` | POST | Login with email/password |
| `/v1/auth/login/mfa` | POST | Complete MFA verification |
| `/v1/auth/refresh` | POST | Refresh access token |
| `/v1/auth/logout` | POST | Logout (requires auth) |

### Email & Password
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/send-verification` | POST | Send email verification (requires auth) |
| `/v1/auth/verify-email` | POST | Verify email with token |
| `/v1/auth/forgot-password` | POST | Request password reset |
| `/v1/auth/reset-password` | POST | Reset password with token |

### Session Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/revoke-all-sessions` | POST | Revoke all user sessions (requires auth) |

### MFA
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/mfa/setup` | POST | Setup TOTP MFA (requires auth) |
| `/v1/auth/mfa/enable` | POST | Enable TOTP MFA (requires auth) |

### Health & Metrics
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with service status |
| `/metrics` | GET | Prometheus metrics |

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `PORT` | Server port | `8080` |
| `APP_ENV` | Environment (development/production) | `development` |
| `DATABASE_URL` | PostgreSQL connection URL | (required) |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `JWT_SECRET` | JWT signing secret | (required) |
| `JWT_ISSUER` | JWT issuer claim | `modernauth` |
| `ACCESS_TOKEN_TTL` | Access token TTL | `15m` |
| `REFRESH_TOKEN_TTL` | Refresh token TTL | `168h` |
| `SESSION_TTL` | Session TTL | `168h` |
| `LOCKOUT_MAX_ATTEMPTS` | Max failed login attempts | `5` |
| `LOCKOUT_WINDOW` | Window for counting attempts | `15m` |
| `LOCKOUT_DURATION` | Lockout duration | `30m` |

## License

MIT License

