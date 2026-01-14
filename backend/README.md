<p align="center">
  <img src="docs/assets/logo.svg" alt="ModernAuth Logo" width="200">
</p>

# ModernAuth

A modern, Go-native authentication & identity core.

## Overview

ModernAuth  is a Go-native authentication and identity core intended to be embedded into products (SaaS, control panels, developer platforms) or run as a standalone auth service.

## Features

- **Go-Native**: Built with Go 1.23+ following Clean Architecture.
- **Multi-tenancy**: Built-in support for isolated tenants (organizations) with custom settings and domains.
- **RBAC**: Role-Based Access Control with roles, permissions, and middleware.
- **Config Management**: Centralized configuration via environment variables and `.env` files using `cleanenv`.
- **MFA (TOTP)**: Built-in support for Time-based One-Time Passwords with backup codes.
- **OAuth2 Social Login**: Google, GitHub, and Microsoft authentication providers.
- **SMTP Email Service**: Production-ready email with TLS support and HTML templates.
- **Password Strength Validation**: Configurable policies with common password blocking.
- **Email Verification**: Token-based email verification flow.
- **Password Management**: Secure password reset and change flows.
- **Account Lockout**: Protection against brute-force attacks with configurable lockout policies.
- **Token Blacklisting**: Redis-backed JWT access token blacklisting for immediate revocation.
- **Observability**: 
    - **Prometheus Metrics**: Request latency, counts, and authentication success/failure rates.
    - **Structured Logging**: Production-ready JSON logging using `slog`.
    - **Health Checks**: Service health endpoints with Redis connectivity status.
- **Secure Token Management**: Stateless JWT access tokens and stateful opaque refresh tokens.
- **Session Security**: Built-in token reuse detection to prevent token theft.
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints.
- **Audit Trails**: Comprehensive database-backed audit logging for all auth events with configurable retention policy and automatic cleanup.
- **Input Validation**: Request validation using go-playground/validator.
- **Docker Ready**: Easy deployment with Docker and Docker Compose.

## Quick Start

### Prerequisites

- Go 1.23+
- Docker & Docker Compose
- Make
- PostgreSQL client (psql) for migrations

### Using the Makefile

The project includes a `Makefile` for common development tasks:

```bash
# Setup environment (manual step)
cp .env.example .env

# Start database and redis
make docker-up

# Run migrations
./scripts/migrate.sh up

# Create admin account (interactive)
./scripts/seed_admin.sh

# Build and run the server
make run

# Run tests
make test
```

### Database Migrations

The `migrate.sh` script manages database schema migrations:

```bash
# Apply all pending migrations
./scripts/migrate.sh up

# Rollback last migration
./scripts/migrate.sh down

# Check migration status
./scripts/migrate.sh status

# Reset database (rollback all migrations)
./scripts/migrate.sh reset
```

The script automatically reads database credentials from:
1. `.env` file (if exists)
2. `docker-compose.yml` (fallback)

### Creating Admin Account

Use the interactive seed script to create your first admin user:

```bash
./scripts/seed_admin.sh
```

This will:
- Read database credentials from `.env` or `docker-compose.yml`
- Prompt for admin email and password
- Hash the password using Argon2id
- Create the user with admin role assigned

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
| `/v1/auth/me` | GET | Get current user profile (requires auth) |

### Email & Password
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/send-verification` | POST | Send email verification (requires auth) |
| `/v1/auth/verify-email` | POST | Verify email with token |
| `/v1/auth/forgot-password` | POST | Request password reset |
| `/v1/auth/reset-password` | POST | Reset password with token |
| `/v1/auth/change-password` | POST | Change password (requires auth) |

### Session Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/revoke-all-sessions` | POST | Revoke all user sessions (requires auth) |

### MFA
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/mfa/setup` | POST | Setup TOTP MFA (requires auth) |
| `/v1/auth/mfa/enable` | POST | Enable TOTP MFA (requires auth) |
| `/v1/auth/mfa/disable` | POST | Disable MFA (requires auth) |
| `/v1/auth/mfa/backup-codes` | POST | Generate new backup codes (requires auth) |
| `/v1/auth/mfa/backup-codes` | GET | Get backup code count (requires auth) |
| `/v1/auth/login/backup-code` | POST | Login with backup code |

### OAuth2 Social Login
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/oauth/{provider}/authorize` | GET | Get OAuth authorization URL |
| `/v1/oauth/{provider}/callback` | POST | Handle OAuth callback |

Supported providers: `google`, `github`, `microsoft`

### User Management (requires `users:*` permissions)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/users` | GET | List all users (supports `?limit=&offset=`) |
| `/v1/users` | POST | Create a new user |
| `/v1/users/{id}` | GET | Get user by ID |
| `/v1/users/{id}` | PUT | Update user |
| `/v1/users/{id}` | DELETE | Delete user |

### Audit Logs (requires `audit:read` permission)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/audit/logs` | GET | List audit logs (supports pagination) |

### Admin (requires `admin` role)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/admin/stats` | GET | Get system statistics |
| `/v1/admin/services` | GET | Get service health status |
| `/v1/admin/settings` | GET | List system settings |
| `/v1/admin/settings/{key}` | PATCH | Update system setting |
| `/v1/admin/roles` | GET | List all roles |
| `/v1/admin/roles` | POST | Create a new role |
| `/v1/admin/roles/{id}` | GET | Get role by ID |
| `/v1/admin/roles/{id}` | PUT | Update role |
| `/v1/admin/roles/{id}` | DELETE | Delete role |
| `/v1/admin/roles/{id}/permissions` | GET | Get permissions for a role |
| `/v1/admin/roles/{id}/permissions` | POST | Assign permission to role |
| `/v1/admin/roles/{id}/permissions/{permissionId}` | DELETE | Remove permission from role |
| `/v1/admin/permissions` | GET | List all available permissions |
| `/v1/admin/users/{id}/roles` | POST | Assign role to user |
| `/v1/admin/users/{id}/roles/{roleId}` | DELETE | Remove role from user |

### Tenant Management (requires `admin` role)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/tenants` | GET | List all tenants |
| `/v1/tenants` | POST | Create a new tenant |
| `/v1/tenants/{id}` | GET | Get tenant details |
| `/v1/tenants/{id}` | PUT | Update tenant |
| `/v1/tenants/{id}` | DELETE | Delete tenant |
| `/v1/tenants/{id}/stats` | GET | Get tenant statistics |
| `/v1/tenants/{id}/users` | GET | List users in a tenant |
| `/v1/tenants/{id}/users/{userId}` | POST | Assign user to tenant |
| `/v1/tenants/{id}/users/{userId}` | DELETE | Remove user from tenant |

### Health & Metrics
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with service status |
| `/metrics` | GET | Prometheus metrics |

## Role-Based Access Control (RBAC)

ModernAuth includes a comprehensive RBAC system with full CRUD operations:

### Default Roles
| Role | Description |
|------|-------------|
| `admin` | Full system access with all permissions (system role, cannot be modified) |
| `user` | Standard user with basic read permissions (system role, cannot be modified) |

### Default Permissions
| Permission | Description |
|------------|-------------|
| `users:read` | View user information |
| `users:write` | Create and update users |
| `users:delete` | Delete users |
| `audit:read` | View audit logs |
| `admin:access` | Access admin endpoints |
| `roles:manage` | Manage roles and permissions |

### Role Management
- **Create Custom Roles**: Create tenant-specific or global roles with custom permissions
- **Update Roles**: Modify role descriptions and permissions (system roles are protected)
- **Delete Roles**: Remove custom roles (system roles cannot be deleted)
- **Permission Assignment**: Assign or remove permissions from roles dynamically
- **System Role Protection**: System roles (`admin`, `user`) cannot be modified or deleted

## Configuration

### Core Settings
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
| `AUDIT_RETENTION_PERIOD` | Audit log retention period | `8760h` (1 year) |
| `AUDIT_CLEANUP_INTERVAL` | Audit log cleanup interval | `24h` (daily) |

### Email (SMTP)
| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | - |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USERNAME` | SMTP username | - |
| `SMTP_PASSWORD` | SMTP password | - |
| `SMTP_FROM_EMAIL` | Sender email address | - |
| `SMTP_FROM_NAME` | Sender display name | `ModernAuth` |

### OAuth2 Providers
| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `OAUTH_GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `OAUTH_GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `OAUTH_GOOGLE_REDIRECT_URL` | Google OAuth redirect URL | - |
| `OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `OAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | - |
| `OAUTH_GITHUB_REDIRECT_URL` | GitHub OAuth redirect URL | - |
| `OAUTH_MICROSOFT_CLIENT_ID` | Microsoft OAuth client ID | - |
| `OAUTH_MICROSOFT_CLIENT_SECRET` | Microsoft OAuth client secret | - |
| `OAUTH_MICROSOFT_REDIRECT_URL` | Microsoft OAuth redirect URL | - |

## License

MIT License

