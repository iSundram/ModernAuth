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
  - Multi-factor Authentication (TOTP)
- For local development and feature overview, see `frontend/README.md`.

