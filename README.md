## ModernAuth

ModernAuth is a modern authentication and identity core built in Go with a TypeScript/React frontend.

### Backend

- **Code**: `backend/`
- **Docs**: see `backend/docs/`:
  - `api.md` – REST API reference (endpoints, requests, responses, examples)
  - `conf.md` – configuration and environment variables
  - `architecture.md` – high-level architecture
- **Security**: see `SECURITY.md` in the root directory
- **Backend quick start**: see `backend/README.md`.

### Frontend

- **Code**: `frontend/`
- Vite + React + TypeScript admin/user console for managing ModernAuth.
- **Key Features**:
  - Tenant and User Management
  - RBAC (Roles & Permissions)
  - API Key & Webhook Management
  - **Passwordless Magic Link Login**
  - **Admin User Impersonation**
  - **Bulk User Import/Export (CSV/JSON)**
  - Security dashboard with session & device management
  - Multi-factor Authentication (TOTP, Email MFA, WebAuthn/Passkeys)
  - **Real-time Analytics Dashboard** (DAU, MAU, login stats, security metrics)
  - **Dark Mode Support**
  - Onboarding wizard for new users
- For local development and feature overview, see `frontend/README.md`.

### Recent Enhancements

- **Analytics Dashboard**: Real-time metrics for user activity, authentication patterns, and security events
- **Redis Streams Email Queue**: Persistent email delivery with automatic retries and dead letter handling
- **Tenant Security Improvements**: Tenant-scoped queries, authorization middleware, membership validation
- **Admin Audit Logging**: Comprehensive logging of administrative actions with 20+ event types
- **MFA Improvements**: TOTP replay protection, preferred MFA method selection, countdown timers
- **WebAuthn/Passkeys**: Full FIDO2 support for hardware security keys and passkeys
- **Email MFA**: Alternative MFA via email verification codes

