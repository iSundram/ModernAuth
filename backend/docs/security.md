## Security

### Password Security
- **Password Hashing**: Argon2id with secure parameters (64MB memory, 3 iterations, parallelism 2)
- **Password Requirements**: Minimum 8 characters, maximum 128 characters

### Token Strategy
- **Access Tokens**: Short-lived JWTs (15 min default), stateless validation
- **Refresh Tokens**: Opaque tokens with rotation, stored as SHA-256 hashes
- **Token Blacklisting**: Redis-backed blacklist for immediate access token revocation

### Session Security
- **Token Reuse Detection**: Automatic session revocation on refresh token reuse (potential theft indicator)
- **Session Revocation**: Revoke individual sessions or all sessions at once

### Account Protection
- **Account Lockout**: Configurable brute-force protection
  - Default: 5 failed attempts within 15 minutes triggers 30-minute lockout
  - Configurable via `LOCKOUT_MAX_ATTEMPTS`, `LOCKOUT_WINDOW`, `LOCKOUT_DURATION`
- **Rate Limiting**: Redis-backed rate limiting on sensitive endpoints
  - Registration: 5 requests/hour
  - Login: 10 requests/15 minutes
  - Token refresh: 100 requests/15 minutes

### MFA (Multi-Factor Authentication)
- **TOTP Support**: Time-based One-Time Passwords (RFC 6238)
- **Secure Storage**: TOTP secrets stored in database

### Email Verification & Password Reset
- **Verification Tokens**: Secure random tokens (32 bytes), stored as SHA-256 hashes
- **Token Expiry**: Email verification (24 hours), Password reset (1 hour)
- **Single Use**: Tokens are marked as used after consumption

### Best Practices
- **Constant-Time Comparison**: Password and token verification use constant-time comparison
- **No User Enumeration**: Password reset returns success regardless of email existence
- **Audit Logging**: All authentication events are logged with IP and user agent
