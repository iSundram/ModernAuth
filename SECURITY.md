# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to the maintainers privately
3. Include as much detail as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Updates**: We will provide status updates as we investigate
- **Resolution**: We aim to resolve critical issues within 7 days
- **Credit**: We will credit reporters in release notes (unless anonymity is requested)

---

## Security Features

### Password Security
- **Password Hashing**: Argon2id with secure parameters (64MB memory, 3 iterations, parallelism 2)
- **Password Requirements**: Minimum 8 characters, maximum 128 characters
- **Password Strength Validation**: Configurable policies with common password blocking
- **Password History**: Prevents reuse of recent passwords (default last 5)
- **Password Change**: Authenticated endpoint requiring current password verification

### OAuth2 Social Login
- **Providers**: Google, GitHub, Microsoft with easy extensibility
- **Account Linking**: Link multiple social providers to a single user account
- **Secure State**: CSRF protection via state parameter validation
- **PKCE Support**: Proof Key for Code Exchange (S256) for public clients (SPAs, mobile apps)
- **Redirect URI Validation**: OAuth redirect URLs validated against allowed list to prevent open redirect attacks
- **JWT Secret Validation**: Minimum 32 characters required for HS256 signing key

### Token Strategy
- **Access Tokens**: Short-lived JWTs (15 min default), stateless validation
- **Refresh Tokens**: Opaque tokens with rotation, stored as SHA-256 hashes
- **Token Blacklisting**: Redis-backed blacklist for immediate access token revocation

### Session Security
- **Token Reuse Detection**: Automatic session revocation on refresh token reuse (potential theft indicator)
- **Session Revocation**: Revoke individual sessions or all sessions at once
- **Concurrent Session Limits**: Configurable limit on active sessions per user (default 5)
- **User Impersonation**: Secure admin impersonation for support with full audit logging

### Role-Based Access Control (RBAC)
- **Roles**: Predefined roles (admin, user) with extensible role system
- **Permissions**: Granular permissions (users:read, users:write, users:delete, audit:read, admin:access, roles:manage)
- **Middleware**: `RequireRole` and `RequirePermission` middleware for endpoint protection
- **Role Assignment**: Admin-only endpoints for assigning/removing roles

### Account Protection
- **Account Lockout**: Configurable brute-force protection
  - Default: 5 failed attempts within 15 minutes triggers 30-minute lockout
  - Configurable via `LOCKOUT_MAX_ATTEMPTS`, `LOCKOUT_WINDOW`, `LOCKOUT_DURATION`
- **MFA Lockout**: Separate brute-force protection for MFA attempts
  - 5 failed TOTP/backup code attempts triggers 5-minute lockout
  - Prevents brute-forcing of 6-digit TOTP codes
- **Risk Assessment**: Adaptive authentication based on IP, location, device, and velocity
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints
  - Registration: 5 requests/hour
  - Login: 10 requests/15 minutes
  - Magic Link: 3 requests/hour
  - Token refresh: 100 requests/15 minutes
  - Password reset: 5 requests/hour
- **Rate Limit Headers**: Responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After`
- **Request Size Limits**: Maximum 1MB request body to prevent DoS attacks

### MFA (Multi-Factor Authentication)
- **TOTP Support**: Time-based One-Time Passwords (RFC 6238)
- **Secure Storage**: TOTP secrets stored in database
- **Backup Codes**: Single-use recovery codes generated on demand, stored as SHA-256 hashes

### API Key Security
- **Secure Storage**: API keys are hashed with SHA-256 before storage; the raw key is only shown once upon creation
- **Prefixes**: Keys use a standard prefix (e.g., `mk_live_`) for easier identification in logs and code
- **IP Allowlisting**: Configurable IP/CIDR restrictions per API key
- **Scoped Access**: Granular permission scopes for each key

### Webhook Security
- **HMAC Signatures**: Every payload is signed with a SHA-256 HMAC using the webhook's secret
- **Verification**: Clients should verify the `X-Signature` header to ensure authenticity
- **TLS Enforcement**: Webhooks should ideally target HTTPS endpoints

### Device & Session Tracking
- **Fingerprinting**: Unique device identification to detect logins from new devices
- **Trusted Devices**: Users can mark specific devices as trusted to reduce MFA friction
- **Login History**: Full audit trail of IPs, locations, and user agents for every login attempt

### Email Verification, Password Reset & Magic Links
- **Verification Tokens**: Secure random tokens (32 bytes), stored as SHA-256 hashes
- **Token Expiry**: Email verification (24h), Password reset (1h), Magic link (15m)
- **Single Use**: Tokens are marked as used after consumption
- **Magic Links**: Passwordless authentication via secure, time-limited email links
- **Email Rate Limiting**: Per-user rate limits prevent abuse
  - Verification emails: 3 per hour per user
  - Password reset emails: 5 per hour per user
  - Magic link emails: 3 per hour per user
- **Async Delivery**: Emails are queued with automatic retry on failure
- **No Enumeration**: Password reset and Magic link requests always return success to prevent email enumeration

### HTTP Security Headers
All responses include security headers to protect against common web vulnerabilities:
- **X-Frame-Options: DENY** - Prevents clickjacking attacks
- **X-Content-Type-Options: nosniff** - Prevents MIME type sniffing
- **X-XSS-Protection: 1; mode=block** - Enables XSS filter in older browsers
- **Strict-Transport-Security** - Enforces HTTPS (1 year, includes subdomains)
- **Referrer-Policy: strict-origin-when-cross-origin** - Limits referrer information leakage
- **Permissions-Policy** - Restricts browser features (geolocation, microphone, camera)

### CORS Configuration
- **Development**: Allows all origins (`*`) by default with a warning logged
- **Production**: Configure `CORS_ORIGINS` environment variable with specific allowed domains
- **Warning**: A log warning is emitted when wildcard CORS is in use to alert operators

---

## Best Practices for Deployment

1. **Use HTTPS**: Always deploy behind TLS/HTTPS
2. **Set CORS properly**: Configure `CORS_ORIGINS` to specific domains (not `*`)
3. **Secure secrets**: Use strong `JWT_SECRET` (min 32 characters)
4. **Database security**: Use SSL for database connections
5. **Redis security**: Use authentication and TLS for Redis
6. **Environment variables**: Never commit secrets to version control
- **Constant-Time Comparison**: Password and token verification use constant-time comparison
- **No User Enumeration**: Password reset returns success regardless of email existence
- **Audit Logging**: All authentication events are logged with IP and user agent
- **Permission-Based Access**: All admin and user management endpoints are protected by RBAC
