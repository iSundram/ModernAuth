## ModernAuth Frontend

ModernAuth includes a modern React + TypeScript + Vite frontend for managing authentication, users, tenants, and advanced security features.

### Tech Stack

- **Framework**: React + TypeScript
- **Bundler**: Vite
- **Styling**: Tailwind CSS
- **Routing**: `react-router-dom`
- **Data fetching**: `@tanstack/react-query`

### Key Features

- **Auth & Onboarding**
  - Login with email/password and MFA
  - Registration and email verification flows
  - Password reset and change password
- **User Area (`/user`)**
  - Dashboard with security overview and recent activity
  - Security page: MFA setup, devices, sessions, login history
  - Settings page: basic profile/account settings
- **Admin Area (`/admin`)**
  - Dashboard with system stats and health
  - Users: list, search, create, edit, deactivate/delete
  - Roles & permissions management
  - Audit logs browsing with filters
  - Tenants management (if enabled in backend)
- **Advanced Management**
  - API keys (create, revoke, rotate)
  - Webhooks (configure endpoints, view deliveries)
  - Invitations (invite users, track status)

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
- `src/pages/` – user and admin pages (dashboard, security, settings, API keys, webhooks, invitations, tenants, users, audit, etc.)
- `src/types/` – shared TypeScript types for API responses and entities

