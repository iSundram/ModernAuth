## API Endpoints
### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/auth/register` | Register a new user |
| POST | `/v1/auth/login` | Login with username/password |
| POST | `/v1/auth/refresh` | Rotate refresh token |
| POST | `/v1/auth/logout` | Revoke session & tokens |
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
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "rt_abc123...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### Example: Refresh Token
```bash
curl -X POST http://localhost:8080/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "rt_abc123..."
  }'
```
