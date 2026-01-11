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

### Session Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/revoke-all-sessions` | Revoke all user sessions (requires auth) |

### MFA (Multi-Factor Authentication)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/mfa/setup` | Setup TOTP MFA (requires auth) |
| POST | `/v1/auth/mfa/enable` | Enable TOTP MFA (requires auth) |

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
| GET | `/v1/admin/roles` | List all available roles |
| POST | `/v1/admin/users/{id}/roles` | Assign role to user |
| DELETE | `/v1/admin/users/{id}/roles/{roleId}` | Remove role from user |

### Tenant Management (requires `admin` role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/tenants` | List all tenants |
| POST | `/v1/tenants` | Create a new tenant |
| GET | `/v1/tenants/{id}` | Get tenant details |
| PUT | `/v1/tenants/{id}` | Update tenant settings |
| DELETE | `/v1/tenants/{id}` | Delete a tenant |
| GET | `/v1/tenants/{id}/users` | List users in a tenant |

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

### Example: Assign Role to User (Admin only)
```bash
curl -X POST http://localhost:8080/v1/admin/users/{user_id}/roles \
  -H "Authorization: Bearer <admin_access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "00000000-0000-0000-0000-000000000001"
  }'
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
