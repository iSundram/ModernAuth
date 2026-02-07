## API Endpoints

Full documentation is also available at [docs.modernauth.net](https://docs.modernauth.net).

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/register` | Register a new user |
| POST | `/v1/auth/login` | Login with email/password |
| POST | `/v1/auth/login/mfa` | Complete MFA verification |
| POST | `/v1/auth/refresh` | Rotate refresh token |
| POST | `/v1/auth/logout` | Revoke session & tokens (requires auth) |
| GET | `/v1/auth/me` | Get current user profile (requires auth) |
| GET | `/v1/auth/settings` | Get public authentication settings (registration, MFA flags, etc.) |

### Google One Tap
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/google/one-tap` | Authenticate via Google One Tap credential (rate limited) |

### Account Self-Deletion (GDPR)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/delete-account` | Delete own account with password verification (requires auth) |

### Waitlist
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/waitlist` | Join waitlist (rate limited 5/hr) |
| GET | `/v1/auth/waitlist/status` | Check waitlist position by email |

### CAPTCHA Configuration
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/auth/captcha/config` | Get CAPTCHA provider and site key for frontend integration |

### Email Verification
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/send-verification` | Send verification email (requires auth) |
| POST | `/v1/auth/verify-email` | Verify email with token |

### Password Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/forgot-password` | Request password reset email |
| POST | `/v1/auth/reset-password` | Reset password with token |
| POST | `/v1/auth/change-password` | Change password (requires auth) |

### Magic Link Authentication (Passwordless)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/magic-link/send` | Request a magic link email for passwordless login |
| POST | `/v1/auth/magic-link/verify` | Verify magic link token and create session |

### Session Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/revoke-all-sessions` | Revoke all user sessions (requires auth) |

### Impersonation (requires auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/auth/impersonation/status` | Check if current session is an impersonation session |
| POST | `/v1/auth/impersonation/end` | End the current impersonation session |

### MFA (Multi-Factor Authentication)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/auth/mfa/status` | Get MFA status and enabled methods (requires auth) |
| POST | `/v1/auth/mfa/setup` | Setup TOTP MFA (requires auth) |
| POST | `/v1/auth/mfa/enable` | Enable TOTP MFA (requires auth) |
| POST | `/v1/auth/mfa/disable` | Disable TOTP MFA (requires auth) |
| POST | `/v1/auth/mfa/backup-codes` | Generate new backup codes (requires auth) |
| GET | `/v1/auth/mfa/backup-codes/count` | Get remaining backup code count (requires auth) |
| POST | `/v1/auth/mfa/preferred` | Set preferred MFA method (requires auth) |
| POST | `/v1/auth/login/mfa` | Complete login with TOTP code |
| POST | `/v1/auth/login/mfa/backup` | Login using a backup code |

### Email MFA
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/mfa/email/enable` | Enable email-based MFA (requires auth) |
| POST | `/v1/auth/mfa/email/disable` | Disable email-based MFA (requires auth) |
| POST | `/v1/auth/login/mfa/email/send` | Send MFA code to user's email |
| POST | `/v1/auth/login/mfa/email` | Complete login with email MFA code |

### SMS MFA
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/mfa/sms/enable` | Enable SMS-based MFA (requires auth, needs phone number) |
| POST | `/v1/auth/mfa/sms/disable` | Disable SMS-based MFA (requires auth) |
| POST | `/v1/auth/login/mfa/sms/send` | Send MFA code via SMS to user's phone |
| POST | `/v1/auth/login/mfa/sms` | Complete login with SMS MFA code |

### WebAuthn/Passkeys (FIDO2)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/mfa/webauthn/register/begin` | Begin WebAuthn credential registration (requires auth) |
| POST | `/v1/auth/mfa/webauthn/register/finish` | Complete WebAuthn credential registration (requires auth) |
| GET | `/v1/auth/mfa/webauthn/credentials` | List registered WebAuthn credentials (requires auth) |
| DELETE | `/v1/auth/mfa/webauthn/credentials` | Delete a WebAuthn credential (requires auth) |
| POST | `/v1/auth/login/mfa/webauthn/begin` | Begin WebAuthn login |
| POST | `/v1/auth/login/mfa/webauthn/finish` | Complete WebAuthn login |

### Device MFA Trust
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/mfa/trust-device` | Trust device for MFA (skip MFA for N days) (requires auth) |
| POST | `/v1/auth/mfa/revoke-trust` | Revoke MFA trust from a device (requires auth) |

### Device & Session Management (requires auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/devices` | List all registered devices |
| GET | `/v1/devices/{id}` | Get device details |
| DELETE | `/v1/devices/{id}` | Remove/Logout a device |
| POST | `/v1/devices/{id}/trust` | Mark device as trusted |
| DELETE | `/v1/devices/{id}/trust` | Remove trust from device |
| GET | `/v1/sessions` | List active sessions for the current user |
| GET | `/v1/sessions/history` | Get login history for current user |

### API Key Management (requires auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/api-keys` | List user's API keys |
| POST | `/v1/api-keys` | Create a new API key (shows raw key once) |
| GET | `/v1/api-keys/{id}` | Get API key metadata |
| DELETE | `/v1/api-keys/{id}` | Revoke an API key |
| POST | `/v1/api-keys/{id}/rotate` | Rotate API key (revokes old, creates new) |

### Webhook Management (requires auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/webhooks` | List configured webhooks |
| POST | `/v1/webhooks` | Create a new webhook subscription |
| GET | `/v1/webhooks/{id}` | Get webhook details |
| PUT | `/v1/webhooks/{id}` | Update webhook configuration |
| DELETE | `/v1/webhooks/{id}` | Delete a webhook |
| GET | `/v1/webhooks/{id}/deliveries` | Get webhook delivery history |

### Invitation Management (requires auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/invitations` | List all invitations |
| POST | `/v1/invitations` | Create and send a new invitation |
| GET | `/v1/invitations/{id}` | Get invitation details |
| DELETE | `/v1/invitations/{id}` | Revoke an invitation |
| POST | `/v1/invitations/{id}/resend` | Resend invitation email |
| POST | `/v1/invitations/public/validate` | Validate invitation token (public) |
| POST | `/v1/invitations/public/accept` | Accept invitation & create account (public) |

### OAuth2 Social Login
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/oauth/providers` | List available social providers |
| GET | `/v1/oauth/{provider}/authorize` | Get authorization URL for provider |
| GET | `/v1/oauth/{provider}/callback` | OAuth callback endpoint (supports GET and POST) |

Supported providers: `google`, `github`, `microsoft`, `apple`, `facebook`, `linkedin`, `discord`, `twitter`, `gitlab`, `slack`, `spotify`

### User Group Management (requires auth)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/groups` | List all groups |
| POST | `/v1/groups` | Create a new group |
| GET | `/v1/groups/{id}` | Get group details |
| PUT | `/v1/groups/{id}` | Update group |
| DELETE | `/v1/groups/{id}` | Delete group |
| GET | `/v1/groups/{id}/members` | List group members |
| POST | `/v1/groups/{id}/members` | Add user to group |
| DELETE | `/v1/groups/{id}/members/{userId}` | Remove user from group |

### User Management (requires permissions)
| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/v1/users` | `users:read` | List all users |
| POST | `/v1/users` | `users:write` | Create a new user |
| GET | `/v1/users/{id}` | `users:read` | Get user by ID |
| PUT | `/v1/users/{id}` | `users:write` | Update user |
| DELETE | `/v1/users/{id}` | `users:delete` | Delete user |

### Audit Logs (requires permissions)
| Method | Endpoint | Permission | Description |
|--------|----------|------------|-------------|
| GET | `/v1/audit/logs` | `audit:read` | List audit logs with pagination |

Query parameters for `/v1/audit/logs`:
- `limit` - Number of results (default: 50, max: 100)
- `offset` - Pagination offset (default: 0)
- `user_id` - Filter by user ID (optional)

### Admin (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/stats` | Get system statistics |
| GET | `/v1/admin/services` | Get service health status |
| GET | `/v1/admin/settings` | List system settings |
| PATCH | `/v1/admin/settings/{key}` | Update system setting |

### Role Management (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/roles` | List all available roles |
| POST | `/v1/admin/roles` | Create a new role |
| GET | `/v1/admin/roles/{id}` | Get role by ID |
| PUT | `/v1/admin/roles/{id}` | Update role (system roles cannot be modified) |
| DELETE | `/v1/admin/roles/{id}` | Delete role (system roles cannot be deleted) |
| GET | `/v1/admin/roles/{id}/permissions` | Get permissions assigned to a role |
| POST | `/v1/admin/roles/{id}/permissions` | Assign a permission to a role |
| DELETE | `/v1/admin/roles/{id}/permissions/{permissionId}` | Remove a permission from a role |

### Permission Management (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/permissions` | List all available permissions |

### User Role Assignment (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/admin/users/{id}/roles` | Assign role to user |
| DELETE | `/v1/admin/users/{id}/roles/{roleId}` | Remove role from user |

### User Impersonation (requires `admin` role + `users:impersonate` permission)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/admin/users/{id}/impersonate` | Start impersonation session as another user |
| GET | `/v1/admin/impersonation-sessions` | List impersonation sessions (for audit) |

### Bulk User Operations (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/admin/users/import` | Import users from JSON |
| POST | `/v1/admin/users/import/csv` | Import users from CSV file |
| GET | `/v1/admin/users/export` | Export users (supports `?format=csv` or `?format=json`) |

### Tenant Management (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/tenants` | List all tenants |
| POST | `/v1/tenants` | Create a new tenant |
| GET | `/v1/tenants/{id}` | Get tenant details |
| PUT | `/v1/tenants/{id}` | Update tenant settings |
| DELETE | `/v1/tenants/{id}` | Delete a tenant |
| GET | `/v1/tenants/{id}/stats` | Get tenant statistics |
| GET | `/v1/tenants/{id}/users` | List users in a tenant (supports `?limit=&offset=`) |
| POST | `/v1/tenants/{id}/users/{userId}` | Assign user to tenant |
| DELETE | `/v1/tenants/{id}/users/{userId}` | Remove user from tenant |

### Health & Metrics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check with service status |
| GET | `/metrics` | Prometheus metrics |

---

### Example: Register a User
```bash
curl -X POST http://localhost:8080/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

### Example: Login
```bash
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```
Response:
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "is_email_verified": false,
    "created_at": "2026-01-10T00:00:00Z"
  },
  "tokens": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "rt_abc123...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

### Example: Login with MFA
If MFA is enabled, login returns:
```json
{
  "mfa_required": true,
  "user_id": "uuid"
}
```
Complete with:
```bash
curl -X POST http://localhost:8080/v1/auth/login/mfa \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "uuid",
    "code": "123456"
  }'
```

### Example: Login with SMS MFA
```bash
# Send SMS code
curl -X POST http://localhost:8080/v1/auth/login/mfa/sms/send \
  -H "Content-Type: application/json" \
  -d '{"user_id": "uuid"}'

# Verify SMS code
curl -X POST http://localhost:8080/v1/auth/login/mfa/sms \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "uuid",
    "code": "123456"
  }'
```

### Example: Google One Tap Login
```bash
curl -X POST http://localhost:8080/v1/auth/google/one-tap \
  -H "Content-Type: application/json" \
  -d '{"credential": "<google-jwt-credential>"}'
```

### Example: Delete Own Account (GDPR)
```bash
curl -X POST http://localhost:8080/v1/auth/delete-account \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"password": "YourPassword123!"}'
```

### Example: Join Waitlist
```bash
curl -X POST http://localhost:8080/v1/auth/waitlist \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

### Example: Create a Group
```bash
curl -X POST http://localhost:8080/v1/groups \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Engineering",
    "description": "Engineering team"
  }'
```

### Example: Change Password
```bash
curl -X POST http://localhost:8080/v1/auth/change-password \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "OldPassword123!",
    "new_password": "NewSecurePassword123!"
  }'
```

### Example: Refresh Token
```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_abc123..."
  }'
```

### Example: Forgot Password
```bash
curl -X POST http://localhost:8080/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### Example: Reset Password
```bash
curl -X POST http://localhost:8080/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "NewSecurePassword123!"
  }'
```

### Example: Setup MFA
```bash
curl -X POST http://localhost:8080/v1/auth/mfa/setup \
  -H "Authorization: Bearer <access_token>"
```
Response:
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "url": "otpauth://totp/ModernAuth:user@example.com?secret=..."
}
```

### Example: Enable MFA
```bash
curl -X POST http://localhost:8080/v1/auth/mfa/enable \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "123456"
  }'
```

### Example: Create Role (Admin only)
```bash
curl -X POST http://localhost:8080/v1/admin/roles \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "manager",
    "description": "Team manager with elevated permissions",
    "tenant_id": "optional-tenant-uuid"
  }'
```

### Example: Update Role (Admin only)
```bash
curl -X PUT http://localhost:8080/v1/admin/roles/{role_id} \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description"
  }'
```

### Example: Assign Permission to Role (Admin only)
```bash
curl -X POST http://localhost:8080/v1/admin/roles/{role_id}/permissions \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "permission_id": "permission-uuid"
  }'
```

### Example: List Permissions (Admin only)
```bash
curl -X GET http://localhost:8080/v1/admin/permissions \
  -H "Authorization: Bearer <admin_access_token>"
```

### Example: Assign Role to User (Admin only)
```bash
curl -X POST http://localhost:8080/v1/admin/users/{user_id}/roles \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "00000000-0000-0000-0000-000000000001"
  }'
```

### Example: Assign User to Tenant (Admin only)
```bash
curl -X POST http://localhost:8080/v1/tenants/{tenant_id}/users/{user_id} \
  -H "Authorization: Bearer <admin_access_token>"
```

### Example: List Tenant Users (Admin only)
```bash
curl -X GET "http://localhost:8080/v1/tenants/{tenant_id}/users?limit=20&offset=0" \
  -H "Authorization: Bearer <admin_access_token>"
```

### Example: Get Audit Logs (with pagination)
```bash
curl -X GET "http://localhost:8080/v1/audit/logs?limit=20&offset=0" \
  -H "Authorization: Bearer <access_token>"
```
Response:
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "event_type": "login.success",
      "ip": "192.168.1.1",
      "created_at": "2026-01-10T12:00:00Z"
    }
  ],
  "limit": 20,
  "offset": 0,
  "count": 1
}
```

---

## Rate Limiting

The API implements rate limiting on authentication endpoints. Rate limit information is provided in response headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum number of requests allowed in the time window |
| `X-RateLimit-Remaining` | Number of requests remaining in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the rate limit window resets |
| `Retry-After` | Seconds to wait before retrying (only on 429 responses) |

### Rate Limits by Endpoint
| Endpoint | Limit | Window |
|----------|-------|--------|
| `/v1/auth/register` | 5 | 1 hour |
| `/v1/auth/login` | 10 | 15 minutes |
| `/v1/auth/magic-link/send` | 3 | 1 hour |
| `/v1/auth/forgot-password` | 5 | 1 hour |
| `/v1/auth/refresh` | 100 | 15 minutes |
| `/v1/auth/google/one-tap` | 10 | 15 minutes |
| `/v1/auth/waitlist` | 5 | 1 hour |
| `/v1/auth/login/mfa/sms/send` | 5 | 15 minutes |
| `/v1/auth/login/mfa/sms` | 10 | 15 minutes |

---

## CAPTCHA/Bot Protection

Registration and login endpoints support CAPTCHA verification. When enabled, include the `X-Captcha-Token` header with the CAPTCHA response token.

Supported providers:
- **reCAPTCHA v2** — checkbox widget
- **reCAPTCHA v3** — invisible, score-based
- **Cloudflare Turnstile** — privacy-focused alternative

Get the active CAPTCHA configuration via `GET /v1/auth/captcha/config`.

---

## New Features

### Magic Link Authentication
Passwordless login via email. Users receive a secure, time-limited link that logs them in without a password.

```bash
# Request magic link
curl -X POST http://localhost:8080/v1/auth/magic-link/send \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Verify magic link
curl -X POST http://localhost:8080/v1/auth/magic-link/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "<magic_link_token>", "allow_registration": false}'
```

### User Impersonation
Administrators can impersonate users for support purposes. All impersonation sessions are logged.

```bash
# Start impersonation (requires admin role + users:impersonate permission)
curl -X POST http://localhost:8080/v1/admin/users/{user_id}/impersonate \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Support ticket #12345"}'

# End impersonation
curl -X POST http://localhost:8080/v1/auth/impersonation/end \
  -H "Authorization: Bearer <impersonation_access_token>"
```

### Bulk User Operations
Import and export users in bulk.

```bash
# Export users as CSV
curl -X GET "http://localhost:8080/v1/admin/users/export?format=csv" \
  -H "Authorization: Bearer <admin_access_token>" \
  -o users.csv

# Import users from JSON
curl -X POST http://localhost:8080/v1/admin/users/import \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "users": [
      {"email": "user1@example.com", "first_name": "User", "last_name": "One"},
      {"email": "user2@example.com", "first_name": "User", "last_name": "Two"}
    ],
    "send_welcome": true,
    "skip_existing": true
  }'
```

---

## Analytics Endpoints (requires `admin` role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/analytics/overview` | Get overall system analytics (users, logins, security) |
| GET | `/v1/analytics/users` | Get user analytics (DAU, MAU, registrations) |
| GET | `/v1/analytics/auth` | Get authentication analytics (success rates, MFA adoption) |
| GET | `/v1/analytics/security` | Get security analytics (failed logins, locked accounts) |
| GET | `/v1/analytics/timeseries` | Get time-series data for charts |

Query parameters for analytics endpoints:
- `period` - Time period: `day`, `week`, `month` (default: `week`)
- `tenant_id` - Filter by tenant ID (optional)

### Example: Get Analytics Overview
```bash
curl -X GET "http://localhost:8080/v1/analytics/overview?period=week" \
  -H "Authorization: Bearer <admin_access_token>"
```
Response:
```json
{
  "total_users": 1250,
  "active_users_24h": 340,
  "active_users_7d": 890,
  "logins_24h": 520,
  "failed_logins_24h": 15,
  "mfa_enabled_users": 780,
  "locked_accounts": 3
}
```
