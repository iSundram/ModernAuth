## Project Structure
```
/cmd/auth-server              # Main application entrypoint
/internal
  /api/http                   # HTTP handlers and middleware
    handlers_auth.go          # Auth (login, register, MFA)
    handlers_users.go         # User management
    handlers_tenant.go        # Multi-tenancy
    handlers_admin.go         # Admin & roles
    router.go                 # Chi router configuration
    middleware.go             # Auth, RBAC, rate limiting middleware
    metrics.go                # Prometheus metrics
    types.go                  # API request/response types
    validator.go              # Request validation
  /auth                       # Core authentication logic
    auth.go                   # AuthService (register, login, RBAC, etc.)
    tokens.go                 # TokenService (JWT generation/validation)
    blacklist.go              # Token blacklisting via Redis
    lockout.go                # Account lockout logic
  /tenant                     # Multi-tenancy logic
    tenant.go                 # Tenant service
  /config                     # Configuration loading
  /storage                    # Storage interfaces
    storage.go                # Interface definitions
    /pg                       # PostgreSQL implementation
      postgres.go             # Storage implementation
  /utils                      # Utilities
    crypto.go                 # Password hashing, token generation
/docs                         # Documentation
/scripts/migrations           # Database migrations
  000001_init.up.sql          # Initial schema
  000002_add_mfa.up.sql       # MFA tables
  000003_add_verification_tokens.up.sql  # Verification tokens
  000004_add_rbac.up.sql      # RBAC tables
  000005_add_tenants.up.sql    # Multi-tenancy tables
```

## Key Files

| File | Description |
|------|-------------|
| `cmd/auth-server/main.go` | Application bootstrap and dependency wiring |
| `internal/auth/auth.go` | Core auth flows (register, login, MFA, password, RBAC) |
| `internal/auth/tokens.go` | JWT access token and refresh token handling |
| `internal/auth/lockout.go` | Account lockout after failed attempts |
| `internal/auth/blacklist.go` | Token/session blacklisting |
| `internal/api/http/handlers.go` | HTTP endpoint implementations |
| `internal/api/http/middleware.go` | Auth, RequireRole, RequirePermission middleware |
| `internal/api/http/validator.go` | Request validation logic |
| `internal/storage/storage.go` | Storage interface definitions (incl. RBACStorage) |
| `internal/storage/pg/postgres.go` | PostgreSQL storage implementation |
| `internal/utils/crypto.go` | Argon2id hashing, token utilities |

## Database Tables

| Table | Description |
|-------|-------------|
| `users` | User accounts |
| `sessions` | Authentication sessions |
| `refresh_tokens` | Refresh token hashes with rotation tracking |
| `audit_logs` | Security event audit trail |
| `user_mfa_settings` | MFA configuration per user |
| `verification_tokens` | Email verification and password reset tokens |
| `roles` | RBAC roles (admin, user) |
| `permissions` | RBAC permissions |
| `role_permissions` | Role-permission assignments |
| `user_roles` | User-role assignments |
