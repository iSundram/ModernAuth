## ModernAuth Frontend

**Homepage**: [modernauth.net](https://modernauth.net) | **Docs**: [docs.modernauth.net](https://docs.modernauth.net)

ModernAuth includes a modern React + TypeScript + Vite frontend for managing authentication, users, tenants, and advanced security features.

### Tech Stack

- **Framework**: React 19 + TypeScript
- **Bundler**: Vite 7
- **Styling**: Tailwind CSS
- **Routing**: `react-router-dom`
- **Data fetching**: `@tanstack/react-query`

### Key Features

- **Auth & Onboarding**
  - Login with email/password and MFA (TOTP, Email, SMS, WebAuthn/Passkeys)
  - OAuth social login (Google, GitHub, Microsoft, Apple, Facebook, LinkedIn, Discord, Twitter/X, GitLab, Slack, Spotify)
  - Google One Tap sign-in
  - Registration and email verification flows
  - Password reset and change password
  - Passwordless magic link authentication
  - Breached password detection (Have I Been Pwned integration)
  - CAPTCHA/bot protection (reCAPTCHA v2/v3, Cloudflare Turnstile)
  - Onboarding wizard for new users
  - Waitlist mode for controlled launches
- **User Area (`/user`)**
  - Dashboard with security overview and recent activity
  - Security page: MFA setup (TOTP, Email, SMS, Passkeys), devices, sessions, login history
  - Settings page: basic profile/account settings
  - Account self-deletion (GDPR compliance)
  - Linked social accounts management
- **Admin Area (`/admin`)**
  - Dashboard with system stats, health, and security charts
  - **Real-time Analytics**: DAU, MAU, login stats, security metrics with auto-refresh
  - Users: list, search, create, edit, deactivate/delete, impersonation
  - Bulk operations: import/export users (CSV/JSON)
  - Roles & permissions management
  - User groups management
  - Audit logs browsing with filters
  - Tenants management (create, edit, suspend, domain verification, tenant-scoped RBAC)
  - OAuth provider configuration
- **Advanced Management**
  - API keys (create, revoke, rotate)
  - Webhooks (configure endpoints, view deliveries)
  - Invitations (invite users, track status)
  - Email templates, branding customization, and A/B testing
- **UI Features**
  - Responsive design
  - Toast notifications
  - Global loading progress bar
  - Loading states and error handling

### Getting Started

From the repo root:

```bash
cd frontend
cp .env.example .env   # update API base URL and settings
npm install
npm run dev
```

By default the app expects the backend ModernAuth API to be available (see `src/api/client.ts` for base URL configuration).

### Scripts

```bash
npm run dev      # start Vite dev server
npm run build    # type-check then build for production
npm run preview  # preview production build
npm run lint     # run ESLint
```

### Project Structure (frontend)

- `src/main.tsx` – app bootstrap
- `src/App.tsx` – routes and top-level layout
- `src/context/AuthContext.tsx` – auth state and current user
- `src/api/` – HTTP client and API services
- `src/components/layout/` – shared layouts (admin/user, sidebars, header)
- `src/components/ui/` – reusable UI components (cards, tables, modals, toasts, loaders, etc.)
- `src/components/security/` – MFA setup components (TOTP, Email, SMS, WebAuthn, CAPTCHA, password strength)
- `src/pages/` – user and admin pages (dashboard, security, settings, API keys, webhooks, invitations, tenants, users, audit, etc.)
- `src/types/` – shared TypeScript types for API responses and entities
