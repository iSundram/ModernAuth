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
│        (Business logic, token issuance, validation, admin)       │
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
- **Middleware**: Authentication, rate limiting, metrics
- **Validation**: Request validation using go-playground/validator

### Auth Service (`/internal/auth`)
- **AuthService**: Core authentication logic (register, login, logout, MFA)
- **TokenService**: JWT access token and refresh token generation/validation
- **AccountLockout**: Brute-force protection with configurable policies
- **TokenBlacklist**: Immediate token revocation via Redis

### Storage Layer (`/internal/storage`)
- **Interfaces**: Clean separation between business logic and data access
- **PostgreSQL**: Users, sessions, refresh tokens, audit logs, MFA settings, verification tokens
- **Redis**: Rate limiting, session blacklist, token blacklist, account lockout

### Security Features
- Argon2id password hashing
- JWT with HMAC-SHA256 signing
- Refresh token rotation with reuse detection
- TOTP-based MFA
- Email verification and password reset flows
- Account lockout after failed attempts
