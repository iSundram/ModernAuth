## API Endpoints

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
