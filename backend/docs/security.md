## Security

### Password Security
- **Password Hashing**: Argon2id with secure parameters (64MB memory, 3 iterations, parallelism 2)
- **Password Requirements**: Minimum 8 characters, maximum 128 characters
- **Password Change**: Authenticated endpoint requiring current password verification

### Token Strategy
- **Access Tokens**: Short-lived JWTs (15 min default), stateless validation
- **Refresh Tokens**: Opaque tokens with rotation, stored as SHA-256 hashes
- **Token Blacklisting**: Redis-backed blacklist for immediate access token revocation

### Session Security
- **Token Reuse Detection**: Automatic session revocation on refresh token reuse (potential theft indicator)
- **Session Revocation**: Revoke individual sessions or all sessions at once

### Role-Based Access Control (RBAC)
- **Roles**: Predefined roles (admin, user) with extensible role system
- **Permissions**: Granular permissions (users:read, users:write, users:delete, audit:read, admin:access, roles:manage)
- **Middleware**: `RequireRole` and `RequirePermission` middleware for endpoint protection
- **Role Assignment**: Admin-only endpoints for assigning/removing roles

### Account Protection
- **Account Lockout**: Configurable brute-force protection
  - Default: 5 failed attempts within 15 minutes triggers 30-minute lockout
  - Configurable via `LOCKOUT_MAX_ATTEMPTS`, `LOCKOUT_WINDOW`, `LOCKOUT_DURATION`
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints
  - Registration: 5 requests/hour
  - Login: 10 requests/15 minutes
  - Token refresh: 100 requests/15 minutes
  - Password reset: 5 requests/hour

### MFA (Multi-Factor Authentication)
- **TOTP Support**: Time-based One-Time Passwords (RFC 6238)
- **Secure Storage**: TOTP secrets stored in database
- **Backup Codes**: Single-use recovery codes generated on demand, stored as SHA-256 hashes.

### API Key Security
- **Secure Storage**: API keys are hashed with SHA-256 before storage; the raw key is only shown once upon creation.
- **Prefixes**: Keys use a standard prefix (e.g., `mk_live_`) for easier identification in logs and code.
- **IP Allowlisting**: Configurable IP/CIDR restrictions per API key.
- **Scoped Access**: Granular permission scopes for each key.

### Webhook Security
- **HMAC Signatures**: Every payload is signed with a SHA-256 HMAC using the webhook's secret.
- **Verification**: Clients should verify the `X-Signature` header to ensure authenticity.
- **TLS Enforcement**: Webhooks should ideally target HTTPS endpoints.

### Device & Session Tracking
- **Fingerprinting**: Unique device identification to detect logins from new devices.
- **Trusted Devices**: Users can mark specific devices as trusted to reduce MFA friction.
- **Login History**: Full audit trail of IPs, locations, and user agents for every login attempt.

### Email Verification & Password Reset
- **Verification Tokens**: Secure random tokens (32 bytes), stored as SHA-256 hashes
- **Token Expiry**: Email verification (24 hours), Password reset (1 hour)
- **Single Use**: Tokens are marked as used after consumption

### Best Practices
- **Constant-Time Comparison**: Password and token verification use constant-time comparison
- **No User Enumeration**: Password reset returns success regardless of email existence
- **Audit Logging**: All authentication events are logged with IP and user agent
- **Permission-Based Access**: All admin and user management endpoints are protected by RBAC
