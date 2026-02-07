## Configuration

Full documentation is also available at [docs.modernauth.net](https://docs.modernauth.net).

Environment variables:

### Application
| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `APP_NAME` | Application name | `ModernAuth` |
| `APP_ENV` | Environment (development/production) | `development` |
| `CORS_ORIGINS` | Comma-separated list of allowed CORS origins | `*` (all origins - not recommended for production) |
| `APP_BASE_URL` | Base URL for the application (used in OAuth redirect URLs) | - |

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

### Email Queue (Redis Streams)
| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_QUEUE_ENABLED` | Enable async email queue with retry logic | `true` |
| `EMAIL_QUEUE_SIZE` | Maximum number of emails in queue | `1000` |
| `EMAIL_QUEUE_REDIS` | Use Redis Streams for persistent queue (recommended for production) | `false` |
| `EMAIL_QUEUE_WORKERS` | Number of concurrent email worker consumers | `3` |
| `EMAIL_QUEUE_MAX_RETRIES` | Maximum retry attempts before dead letter | `3` |

### Email Rate Limiting
| Variable | Description | Default |
|----------|-------------|---------|
| `EMAIL_RATE_LIMIT_ENABLED` | Enable per-user email rate limiting | `true` |
| `EMAIL_VERIFICATION_RATE_LIMIT` | Max verification emails per user per hour | `3` |
| `EMAIL_PASSWORD_RESET_RATE_LIMIT` | Max password reset emails per user per hour | `5` |

### SMS / Twilio
| Variable | Description | Default |
|----------|-------------|---------|
| `SMS_PROVIDER` | SMS provider: `console` (logs to stdout) or `twilio` | `console` |
| `TWILIO_ACCOUNT_SID` | Twilio Account SID (required when `SMS_PROVIDER=twilio`) | - |
| `TWILIO_AUTH_TOKEN` | Twilio Auth Token (required when `SMS_PROVIDER=twilio`) | - |
| `TWILIO_PHONE_NUMBER` | Twilio phone number for sending SMS (required when `SMS_PROVIDER=twilio`) | - |

### CAPTCHA / Bot Protection
| Variable | Description | Default |
|----------|-------------|---------|
| `CAPTCHA_PROVIDER` | CAPTCHA provider: `none` (disabled), `recaptcha_v2`, `recaptcha_v3`, or `turnstile` | `none` |
| `CAPTCHA_SITE_KEY` | CAPTCHA site/public key (shown in frontend widget) | - |
| `CAPTCHA_SECRET_KEY` | CAPTCHA secret key (used for server-side verification) | - |
| `CAPTCHA_MIN_SCORE` | Minimum score threshold for reCAPTCHA v3 (0.0 to 1.0) | `0.5` |

### Breached Password Detection (Have I Been Pwned)
| Variable | Description | Default |
|----------|-------------|---------|
| `HIBP_ENABLED` | Enable breached password checking via HIBP k-Anonymity API | `false` |
| `HIBP_API_KEY` | HIBP API key (optional, for higher rate limits) | - |
| `HIBP_CACHE_TTL` | Redis cache TTL for HIBP prefix results | `24h` |

### Audit Logging
| Variable | Description | Default |
|----------|-------------|---------|
| `AUDIT_RETENTION_DAYS` | Number of days to retain audit logs | `90` |
| `AUDIT_CLEANUP_INTERVAL` | Interval for automatic audit log cleanup | `24h` |

### OAuth2 Providers

All OAuth providers are optional. Configure the client ID and client secret for each provider you want to enable.

| Variable | Description | Default |
|----------|-------------|---------|
| `OAUTH_GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `OAUTH_GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `OAUTH_GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `OAUTH_GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | - |
| `OAUTH_MICROSOFT_CLIENT_ID` | Microsoft OAuth client ID | - |
| `OAUTH_MICROSOFT_CLIENT_SECRET` | Microsoft OAuth client secret | - |
| `OAUTH_APPLE_CLIENT_ID` | Apple OAuth client ID (Services ID) | - |
| `OAUTH_APPLE_CLIENT_SECRET` | Apple OAuth client secret (JWT) | - |
| `OAUTH_APPLE_TEAM_ID` | Apple Developer Team ID | - |
| `OAUTH_APPLE_KEY_ID` | Apple Sign In key ID | - |
| `OAUTH_FACEBOOK_CLIENT_ID` | Facebook OAuth App ID | - |
| `OAUTH_FACEBOOK_CLIENT_SECRET` | Facebook OAuth App Secret | - |
| `OAUTH_LINKEDIN_CLIENT_ID` | LinkedIn OAuth client ID | - |
| `OAUTH_LINKEDIN_CLIENT_SECRET` | LinkedIn OAuth client secret | - |
| `OAUTH_DISCORD_CLIENT_ID` | Discord OAuth client ID | - |
| `OAUTH_DISCORD_CLIENT_SECRET` | Discord OAuth client secret | - |
| `OAUTH_TWITTER_CLIENT_ID` | Twitter/X OAuth 2.0 client ID | - |
| `OAUTH_TWITTER_CLIENT_SECRET` | Twitter/X OAuth 2.0 client secret | - |
| `OAUTH_GITLAB_CLIENT_ID` | GitLab OAuth client ID | - |
| `OAUTH_GITLAB_CLIENT_SECRET` | GitLab OAuth client secret | - |
| `OAUTH_SLACK_CLIENT_ID` | Slack OAuth client ID | - |
| `OAUTH_SLACK_CLIENT_SECRET` | Slack OAuth client secret | - |
| `OAUTH_SPOTIFY_CLIENT_ID` | Spotify OAuth client ID | - |
| `OAUTH_SPOTIFY_CLIENT_SECRET` | Spotify OAuth client secret | - |
| `OAUTH_REDIRECT_BASE_URL` | Base URL for OAuth redirect callbacks | - |
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

# SMS (Twilio)
SMS_PROVIDER=console
# SMS_PROVIDER=twilio
# TWILIO_ACCOUNT_SID=your-twilio-account-sid
# TWILIO_AUTH_TOKEN=your-twilio-auth-token
# TWILIO_PHONE_NUMBER=+15551234567

# CAPTCHA (optional)
CAPTCHA_PROVIDER=none
# CAPTCHA_PROVIDER=recaptcha_v3
# CAPTCHA_SITE_KEY=your-site-key
# CAPTCHA_SECRET_KEY=your-secret-key
# CAPTCHA_MIN_SCORE=0.5

# Breached Password Detection (optional)
HIBP_ENABLED=false
# HIBP_API_KEY=your-hibp-api-key
# HIBP_CACHE_TTL=24h

# OAuth2 Providers (optional — configure as needed)
OAUTH_GOOGLE_CLIENT_ID=your-google-client-id
OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret

OAUTH_GITHUB_CLIENT_ID=your-github-client-id
OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret

OAUTH_MICROSOFT_CLIENT_ID=your-microsoft-client-id
OAUTH_MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

# Additional OAuth providers (all optional)
# OAUTH_APPLE_CLIENT_ID=...
# OAUTH_APPLE_CLIENT_SECRET=...
# OAUTH_APPLE_TEAM_ID=...
# OAUTH_APPLE_KEY_ID=...
# OAUTH_FACEBOOK_CLIENT_ID=...
# OAUTH_FACEBOOK_CLIENT_SECRET=...
# OAUTH_LINKEDIN_CLIENT_ID=...
# OAUTH_LINKEDIN_CLIENT_SECRET=...
# OAUTH_DISCORD_CLIENT_ID=...
# OAUTH_DISCORD_CLIENT_SECRET=...
# OAUTH_TWITTER_CLIENT_ID=...
# OAUTH_TWITTER_CLIENT_SECRET=...
# OAUTH_GITLAB_CLIENT_ID=...
# OAUTH_GITLAB_CLIENT_SECRET=...
# OAUTH_SLACK_CLIENT_ID=...
# OAUTH_SLACK_CLIENT_SECRET=...
# OAUTH_SPOTIFY_CLIENT_ID=...
# OAUTH_SPOTIFY_CLIENT_SECRET=...

OAUTH_REDIRECT_BASE_URL=http://localhost:8080
OAUTH_ALLOWED_REDIRECT_URLS=http://localhost:3000/auth/callback
```
