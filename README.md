## ModernAuth

**Homepage**: [modernauth.net](https://modernauth.net) | **Docs**: [docs.modernauth.net](https://docs.modernauth.net)

ModernAuth is a modern authentication and identity platform built in Go with a TypeScript/React frontend.

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
  - Multi-factor Authentication (TOTP, Email MFA, SMS MFA, WebAuthn/Passkeys)
  - **Real-time Analytics Dashboard** (DAU, MAU, login stats, security metrics)
  - **OAuth Social Login** (Google, GitHub, Microsoft, Apple, Facebook, LinkedIn, Discord, Twitter/X, GitLab, Slack, Spotify)
  - **Google One Tap** sign-in
  - **CAPTCHA/Bot Protection** (reCAPTCHA v2/v3, Cloudflare Turnstile)
  - **Breached Password Detection** (Have I Been Pwned integration)
  - **User Groups** management
  - **Account Self-Deletion** (GDPR compliance)
  - **Waitlist Mode** for controlled launches
  - Onboarding wizard for new users
- For local development and feature overview, see `frontend/README.md`.

### Recent Enhancements

- **8 New OAuth Providers**: Apple, Facebook, LinkedIn, Discord, Twitter/X, GitLab, Slack, Spotify (in addition to Google, GitHub, Microsoft)
- **SMS MFA**: Twilio-powered SMS-based multi-factor authentication
- **CAPTCHA/Bot Protection**: reCAPTCHA v2, reCAPTCHA v3, and Cloudflare Turnstile support on registration and login
- **Breached Password Detection**: Have I Been Pwned k-Anonymity API integration with Redis caching
- **User Groups**: Full CRUD group management with membership APIs
- **Account Self-Deletion**: GDPR-compliant user self-deletion with password verification
- **Google One Tap**: One-click sign-in via Google One Tap credential flow
- **Waitlist Mode**: Redis-backed waitlist for controlled launch sign-ups
- **CI/CD**: GitHub Actions workflows for CI, releases, and dependency review with Dependabot
- **Email A/B Testing**: A/B testing for email templates with analytics and tracking
- **Advanced Email Branding**: Per-tenant email template customization
- **Analytics Dashboard**: Real-time metrics for user activity, authentication patterns, and security events
- **Redis Streams Email Queue**: Persistent email delivery with automatic retries and dead letter handling
- **Tenant Security Improvements**: Tenant-scoped RBAC, rate limiting, extensible features, onboarding
- **Admin Audit Logging**: Comprehensive logging of administrative actions with 20+ event types
- **MFA Improvements**: TOTP replay protection, preferred MFA method selection, countdown timers
- **WebAuthn/Passkeys**: Full FIDO2 support for hardware security keys and passkeys
- **Email MFA**: Alternative MFA via email verification codes
