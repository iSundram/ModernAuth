## Configuration

Environment variables:

### Application
| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `8080` |
| `APP_NAME` | Application name | `ModernAuth` |
| `APP_ENV` | Environment (development/production) | `development` |

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

### Example `.env` file
```bash
# Application
PORT=8080
APP_ENV=development

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
```
