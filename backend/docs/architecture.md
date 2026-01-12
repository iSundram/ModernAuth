## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                     API Gateway / Load Balancer                  │
│               (TLS termination, WAF rules, rate limiting)        │
└─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Stateless Auth API Servers (Go)                │
│        (Business logic, token issuance, validation, RBAC)        │
└─────────────────────────────────────────────────────────────────┘
                    │                           │
                    ▼                           ▼
    ┌───────────────────────┐       ┌───────────────────────┐
    │      PostgreSQL       │       │         Redis         │
    │   (Primary datastore) │       │ (Sessions, caches,    │
    │                       │       │  rate limits, lockout │
    │                       │       │  token blacklist)     │
    └───────────────────────┘       └───────────────────────┘
```

## Component Overview

### API Layer (`/internal/api/http`)
- **Handlers**: REST endpoints for auth operations
- **Middleware**: Authentication, authorization (RBAC), rate limiting, metrics
- **Validation**: Request validation using go-playground/validator

### Auth Service (`/internal/auth`)
- **AuthService**: Core authentication logic (register, login, logout, MFA, password management)
- **TokenService**: JWT access token and refresh token generation/validation
- **AccountLockout**: Brute-force protection with configurable policies
- **TokenBlacklist**: Immediate token revocation via Redis
- **RBAC**: Role and permission management

### Tenant Service (`/internal/tenant`)
- **Service**: Core multi-tenancy logic (tenant creation, isolation, settings)
- **Middleware**: Tenant identification from domain or headers

### Webhook Engine (`/internal/webhook`)
- **Delivery**: Asynchronous delivery system using a worker pool.
- **Retries**: Exponential backoff retry strategy for failed deliveries.
- **History**: Detailed logs for every delivery attempt.

### API Key Service (`/internal/apikey`)
- **Validation**: High-performance key validation with optional caching.
- **Rotation**: Secure key rotation without service interruption.

### Storage Layer (`/internal/storage`)
- **Interfaces**: Clean separation between business logic and data access
- **PostgreSQL**: Users, sessions, refresh tokens, audit logs, MFA settings, verification tokens, roles, permissions
- **Redis**: Rate limiting, session blacklist, token blacklist, account lockout

### Security Features
- Argon2id password hashing
- JWT with HMAC-SHA256 signing
- Refresh token rotation with reuse detection
- TOTP-based MFA
- Email verification and password reset flows
- Account lockout after failed attempts
- Role-Based Access Control (RBAC)
