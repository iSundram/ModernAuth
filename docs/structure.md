## Project Structure
```
/cmd/auth-server              # Main application entrypoint
/internal
  /api/http                   # HTTP handlers and middleware
    handlers.go               # REST endpoint handlers
    middleware.go             # Auth, rate limiting middleware
    metrics.go                # Prometheus metrics
    validator.go              # Request validation
  /auth                       # Core authentication logic
    auth.go                   # AuthService (register, login, etc.)
    tokens.go                 # TokenService (JWT generation/validation)
    blacklist.go              # Token blacklisting via Redis
    lockout.go                # Account lockout logic
  /config                     # Configuration loading
  /storage                    # Storage interfaces
    storage.go                # Interface definitions
    /pg                       # PostgreSQL implementation
      postgres.go             # User, session, token storage
  /utils                      # Utilities
    crypto.go                 # Password hashing, token generation
/docs                         # Documentation
/scripts/migrations           # Database migrations
  000001_init.up.sql          # Initial schema
  000002_add_mfa.up.sql       # MFA tables
  000003_add_verification_tokens.up.sql  # Verification tokens
```

## Key Files

| File | Description |
|------|-------------|
| `cmd/auth-server/main.go` | Application bootstrap and dependency wiring |
| `internal/auth/auth.go` | Core auth flows (register, login, MFA, password reset) |
| `internal/auth/tokens.go` | JWT access token and refresh token handling |
| `internal/auth/lockout.go` | Account lockout after failed attempts |
| `internal/auth/blacklist.go` | Token/session blacklisting |
| `internal/api/http/handlers.go` | HTTP endpoint implementations |
| `internal/api/http/validator.go` | Request validation logic |
| `internal/storage/storage.go` | Storage interface definitions |
| `internal/storage/pg/postgres.go` | PostgreSQL storage implementation |
| `internal/utils/crypto.go` | Argon2id hashing, token utilities |
