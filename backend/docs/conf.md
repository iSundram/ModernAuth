## Configuration

Environment variables:

### Application
| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `APP_NAME` | Application name | `ModernAuth` |
| `APP_ENV` | Environment (development/production) | `development` |
| `CORS_ORIGINS` | Comma-separated list of allowed CORS origins | `*` (all origins - not recommended for production) |

### Database & Cache
| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |

### Authentication
| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret (min 32 chars) | Required |
| `JWT_ISSUER` | JWT issuer claim | `modernauth` |
| `ACCESS_TOKEN_TTL` | Access token lifetime | `15m` |
| `REFRESH_TOKEN_TTL` | Refresh token lifetime | `168h` (7 days) |
| `SESSION_TTL` | Session lifetime | `168h` (7 days) |

### Account Lockout
| Variable | Description | Default |
|----------|-------------|---------|
| `LOCKOUT_MAX_ATTEMPTS` | Failed attempts before lockout | `5` |
| `LOCKOUT_WINDOW` | Time window for counting attempts | `15m` |
| `LOCKOUT_DURATION` | How long account stays locked | `30m` |

### Email / SMTP
| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_PROVIDER` | Email provider: `console` (logs to stdout), `smtp` (SMTP server), or `sendgrid` (SendGrid API) | `console` |
| `SMTP_HOST` | SMTP server hostname (required when `EMAIL_PROVIDER=smtp`) | - |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USERNAME` | SMTP authentication username | - |
| `SMTP_PASSWORD` | SMTP authentication password | - |
| `EMAIL_FROM` | Sender email address (required when `EMAIL_PROVIDER=smtp` or `sendgrid`) | `noreply@modernauth.local` |
| `EMAIL_FROM_NAME` | Sender display name | `ModernAuth` |

### SendGrid
| Variable | Description | Default |
|----------|-------------|---------|
| `SENDGRID_API_KEY` | SendGrid API key (required when `EMAIL_PROVIDER=sendgrid`) | - |

### Email Queue
| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_QUEUE_ENABLED` | Enable async email queue with retry logic | `true` |
| `EMAIL_QUEUE_SIZE` | Maximum number of emails in queue | `1000` |

### Email Rate Limiting
| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_RATE_LIMIT_ENABLED` | Enable per-user email rate limiting | `true` |
| `EMAIL_VERIFICATION_RATE_LIMIT` | Max verification emails per user per hour | `3` |
| `EMAIL_PASSWORD_RESET_RATE_LIMIT` | Max password reset emails per user per hour | `5` |

### OAuth2 Providers
| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH_GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `OAUTH_GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `OAUTH_GOOGLE_REDIRECT_URL` | Google OAuth redirect URL | - |
| `OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `OAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | - |
| `OAUTH_GITHUB_REDIRECT_URL` | GitHub OAuth redirect URL | - |
| `OAUTH_MICROSOFT_CLIENT_ID` | Microsoft OAuth client ID | - |
| `OAUTH_MICROSOFT_CLIENT_SECRET` | Microsoft OAuth client secret | - |
| `OAUTH_MICROSOFT_REDIRECT_URL` | Microsoft OAuth redirect URL | - |
| `OAUTH_ALLOWED_REDIRECT_URLS` | Comma-separated list of allowed OAuth redirect URLs (security) | - |

### Example `.env` file
```bash
# Application
PORT=8080
APP_ENV=development
CORS_ORIGINS=https://app.example.com,https://admin.example.com

# Database
DATABASE_URL=postgres://user:password@localhost:5432/modernauth?sslmode=disable

# Redis
REDIS_URL=redis://localhost:6379

# Authentication
JWT_SECRET=your-super-secret-key-at-least-32-characters
JWT_ISSUER=modernauth
ACCESS_TOKEN_TTL=15m
REFRESH_TOKEN_TTL=168h
SESSION_TTL=168h

# Account Lockout
LOCKOUT_MAX_ATTEMPTS=5
LOCKOUT_WINDOW=15m
LOCKOUT_DURATION=30m

# Email (SMTP)
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
EMAIL_FROM=noreply@example.com
EMAIL_FROM_NAME=ModernAuth

# Email (SendGrid alternative)
# EMAIL_PROVIDER=sendgrid
# SENDGRID_API_KEY=your-sendgrid-api-key
# EMAIL_FROM=noreply@example.com
# EMAIL_FROM_NAME=ModernAuth

# Email Queue & Rate Limiting
EMAIL_QUEUE_ENABLED=true
EMAIL_QUEUE_SIZE=1000
EMAIL_RATE_LIMIT_ENABLED=true
EMAIL_VERIFICATION_RATE_LIMIT=3
EMAIL_PASSWORD_RESET_RATE_LIMIT=5

# OAuth2 Providers (optional)
OAUTH_GOOGLE_CLIENT_ID=your-google-client-id
OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret
OAUTH_GOOGLE_REDIRECT_URL=http://localhost:8080/v1/oauth/google/callback

OAUTH_GITHUB_CLIENT_ID=your-github-client-id
OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_GITHUB_REDIRECT_URL=http://localhost:8080/v1/oauth/github/callback

OAUTH_MICROSOFT_CLIENT_ID=your-microsoft-client-id
OAUTH_MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
OAUTH_MICROSOFT_REDIRECT_URL=http://localhost:8080/v1/oauth/microsoft/callback
```
