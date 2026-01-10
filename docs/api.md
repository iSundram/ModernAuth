## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/register` | Register a new user |
| POST | `/v1/auth/login` | Login with email/password |
| POST | `/v1/auth/login/mfa` | Complete MFA verification |
| POST | `/v1/auth/refresh` | Rotate refresh token |
| POST | `/v1/auth/logout` | Revoke session & tokens (requires auth) |

### Email Verification
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/send-verification` | Send verification email (requires auth) |
| POST | `/v1/auth/verify-email` | Verify email with token |

### Password Reset
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/forgot-password` | Request password reset email |
| POST | `/v1/auth/reset-password` | Reset password with token |

### Session Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/revoke-all-sessions` | Revoke all user sessions (requires auth) |

### MFA (Multi-Factor Authentication)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/mfa/setup` | Setup TOTP MFA (requires auth) |
| POST | `/v1/auth/mfa/enable` | Enable TOTP MFA (requires auth) |

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
