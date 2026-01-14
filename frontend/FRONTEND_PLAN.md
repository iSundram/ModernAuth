# ModernAuth Frontend - Implementation Plan

## Overview
Transform the basic OweHost frontend into a comprehensive ModernAuth authentication and identity management interface.

## Core Features to Implement

### 1. Authentication & Onboarding
- ✅ Login (email/password) - Already exists
- ✅ MFA Login Flow - Already exists
- ✅ Registration - Already exists
- ✅ Email Verification - Already exists
- ✅ Password Reset Flow - Already exists
- ⚠️ Update branding from OweHost to ModernAuth

### 2. User Dashboard (`/user`)
- **Dashboard** - Security overview, recent activity, account stats
- **Security** - MFA management, device management, active sessions, password change
- **Settings** - Profile settings, email, timezone, locale
- **Audit Logs** - Personal activity history

### 3. Admin Dashboard (`/admin`)
- **Dashboard** - System statistics, user counts, service health
- **Users** - User management (CRUD), role assignment, bulk actions
- **Roles & Permissions** - View roles, assign/remove roles from users
- **Audit Logs** - System-wide audit logs with filtering
- **Tenants** - Multi-tenant management (if enabled)
- **Settings** - System configuration

### 4. Advanced Features (Backend Supported)
- **API Keys** - Create, manage, revoke API keys
- **Webhooks** - Configure webhook endpoints, view delivery logs
- **Invitations** - Send user invitations, track acceptance

### 5. Security Features
- **Device Management** - View/trust/remove devices
- **Session Management** - View active sessions, revoke sessions
- **MFA Setup** - TOTP QR code, backup codes
- **Login History** - View login attempts and locations

## Implementation Order

### Phase 1: Cleanup & Foundation
1. Remove OweHost branding → ModernAuth
2. Clean up types (remove DNS, SSL, FTP, etc.)
3. Update API services to match backend
4. Fix type definitions

### Phase 2: User Features
1. User Dashboard - Real data from backend
2. User Security Page - MFA, devices, sessions
3. User Settings Page - Profile management
4. User Audit Logs - Personal activity

### Phase 3: Admin Features
1. Admin Dashboard - System stats
2. Admin Users Page - Full CRUD + role management
3. Admin Audit Logs - System-wide with filters
4. Admin Settings - System config

### Phase 4: Advanced Features
1. API Keys Management
2. Webhooks Management
3. Invitations Management
4. Tenant Management (if needed)

## Technical Details

### API Integration
- All endpoints match backend `/v1/*` structure
- Proper error handling
- Token refresh on 401
- Loading states

### UI/UX
- Modern, clean design
- Responsive layout
- Toast notifications
- Loading indicators
- Form validation

### State Management
- React Query for server state
- AuthContext for authentication
- Local state for forms

## Files to Update/Create

### Update Existing
- `src/App.tsx` - Routes
- `src/types/index.ts` - Clean up types
- `src/api/services.ts` - Update API calls
- All page components - Real implementations

### Create New
- Device management components
- Session management components
- API key components
- Webhook components
- Invitation components
