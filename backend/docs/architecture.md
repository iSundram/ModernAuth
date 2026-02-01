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
- **MagicLink**: Passwordless authentication via time-limited secure email links
- **Impersonation**: Secure admin impersonation of users for support with full audit logging
- **SessionLimits**: Enforce maximum concurrent sessions per user
- **PasswordHistory**: Prevent reuse of recent passwords (default last 5)
- **RiskAssessment**: Risk-based authentication (unusual IP, location, device, or velocity)
- **AccountLockout**: Brute-force protection with configurable policies
- **TokenBlacklist**: Immediate token revocation via Redis
- **RBAC**: Role and permission management
- **BackupCodes**: MFA backup code generation and verification

### OAuth Service (`/internal/oauth`)
- **Providers**: Google, GitHub, Microsoft social login support
- **User Linking**: Link multiple OAuth providers to a single user account
- **CSRF Protection**: Database-backed state tokens prevent cross-site request forgery
- **PKCE Support**: Proof Key for Code Exchange for enhanced security

### Invitation Service (`/internal/invitation`)
- **User Invitations**: Token-based invitation system with email delivery
- **Role Assignment**: Automatic role assignment from invitation on acceptance
- **Expiration**: Configurable invitation expiry with automatic cleanup

### Email Service (`/internal/email`)
- **Providers**: SMTP, SendGrid, and Console (development) email providers
- **SMTP**: Production-ready SMTP with TLS support (STARTTLS and implicit TLS)
- **SendGrid**: SendGrid API v3 integration (no SDK dependency)
- **Redis Streams Queue**: Persistent async email delivery with consumer groups and dead letter handling
- **Retry Logic**: Exponential backoff retry (1min → 5min → 15min) with configurable max retries
- **Rate Limiting**: Per-user rate limits (3 verification/hr, 5 password reset/hr, 3 magic link/hr)
- **Templates**: HTML email templates for verification, reset, magic link, welcome, alerts
- **Queue Monitoring**: Statistics endpoint for queue depth, pending messages, and dead letters

### Tenant Service (`/internal/tenant`)
- **Service**: Core multi-tenancy logic (tenant creation, isolation, settings)
- **Middleware**: Tenant identification from domain or headers
- **Authorization Middleware**: Tenant access and ownership validation
- **Tenant-Scoped Queries**: All data access is filtered by tenant_id for isolation
- **Membership Validation**: IsUserTenantMember and IsUserTenantAdmin checks

### Audit Service (`/internal/audit`)
- **Admin Audit Logging**: Comprehensive tracking of administrative actions
- **20+ Action Types**: User CRUD, role changes, tenant operations, security settings
- **Context Capture**: Admin ID, target user, IP, user agent, metadata, success/failure

### Webhook Engine (`/internal/webhook`)
- **Delivery**: Asynchronous delivery system using a worker pool.
- **Retries**: Exponential backoff retry strategy for failed deliveries.
- **History**: Detailed logs for every delivery attempt.

### API Key Service (`/internal/apikey`)
- **Validation**: High-performance key validation with optional caching.
- **Rotation**: Secure key rotation without service interruption.

### Storage Layer (`/internal/storage`)
- **Interfaces**: Clean separation between business logic and data access
- **PostgreSQL**: Users, sessions, refresh tokens, audit logs, MFA settings, verification tokens, roles, permissions, password history, magic links, impersonation sessions, risk assessments
- **Redis**: Rate limiting, session blacklist, token blacklist, account lockout

### Security Features
- Argon2id password hashing
- JWT with HMAC-SHA256 signing
- Refresh token rotation with reuse detection
- TOTP-based MFA with replay protection
- Email MFA as alternative authentication factor
- WebAuthn/Passkeys (FIDO2) support
- Email verification and password reset flows
- **Passwordless Magic Links**
- **Admin Impersonation** (audited)
- **Risk-based Authentication**
- **Password History Enforcement**
- **Concurrent Session Limits**
- Account lockout after failed attempts
- Role-Based Access Control (RBAC)
- OAuth state validation (CSRF protection)
- PKCE support for OAuth flows
- **Response-based Rate Limiting** with standard headers
- **Tenant Isolation** with scoped queries
- **Admin Audit Logging** for all administrative actions

### Analytics Service (`/internal/api/http/analytics_service.go`)
- **Overview Stats**: Total users, active users, login counts, security metrics
- **User Analytics**: DAU, MAU, new registrations, active sessions
- **Auth Analytics**: Login success/failure rates, MFA adoption, method breakdown
- **Security Analytics**: Failed logins, locked accounts, suspicious activity
- **Time-series Data**: Hourly/daily aggregation for charts and trends
