import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider, LoadingBar, GlobalProgressBar } from './components/ui';
import { useAuth } from './hooks/useAuth';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

import { AdminLayout, UserLayout } from './components/layout';
import {
  EmailLoginPage,
  PasswordLoginPage,
  MagicLinkLoginPage,
  MagicLinkVerifyPage,
  RegisterPage,
  DashboardPage,
  AdminDashboardPage,
  AdminAuditPage,
  AdminSecurityPage,
  AdminSettingsPage,
  AdminUsersPage,
  AdminRolesPage,
  AdminOAuthPage,
  ForgotPasswordPage,
  ResetPasswordPage,
  VerifyEmailPage,
  UserAuditPage,
  ApiKeysPage,
  WebhooksPage,
  InvitationsPage,
  AdminTenantsPage,
  AdminEmailTemplatesPage,
  AdminEmailBrandingPage,
} from './pages';
import AdminAnalyticsPage from './pages/admin/AdminAnalyticsPage';
import { TenantDetailPage } from './pages/admin/TenantDetailPage';
import { AdminImpersonationPage } from './pages/admin/AdminImpersonationPage';
import { OAuthCallbackPage } from './pages/OAuthCallbackPage';
import { UserSecurityPage } from './pages/user/UserSecurityPage';
import { UserSettingsPage } from './pages/user/UserSettingsPage';
import { UserConnectedAccountsPage } from './pages/user/UserConnectedAccountsPage';
import { InvitationAcceptPage } from './pages/InvitationAcceptPage';
import type { UserRole } from './types';

// Protected Route wrapper
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[var(--color-background)] flex items-center justify-center">
        <LoadingBar isLoading={true} message="Authenticating..." />
        <p className="text-[var(--color-text-secondary)]">Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

// Role-based Protected Route
function RoleProtectedRoute({ 
  children, 
  allowedRoles 
}: { 
  children: React.ReactNode;
  allowedRoles: UserRole[];
}) {
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--color-background)]">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#B3B3B3] to-[#D4D4D4] flex items-center justify-center animate-pulse">
            <span className="text-xl font-bold text-white">O</span>
          </div>
          <p className="text-[var(--color-text-secondary)]">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user || !allowedRoles.includes(user.role || 'user')) {
    const dashboardRoute = user?.role === 'admin' ? '/admin' : '/user';
    return <Navigate to={dashboardRoute} replace />;
  }

  return <>{children}</>;
}

function getDashboardRoute(role?: UserRole): string {
  switch (role) {
    case 'admin':
      return '/admin';
    case 'user':
    default:
      return '/user';
  }
}

function AppRoutes() {
  const { user, settings } = useAuth();

  // Handle dynamic branding
  useEffect(() => {
    if (settings['site.name']) {
      document.title = settings['site.name'];
    }
  }, [settings]);

  return (
    <Routes>
      <Route path="/login" element={<EmailLoginPage />} />
      <Route path="/login/password" element={<PasswordLoginPage />} />
      <Route path="/login/magic-link" element={<MagicLinkLoginPage />} />
      <Route path="/auth/magic-link" element={<MagicLinkVerifyPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route path="/forgot-password" element={<ForgotPasswordPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/verify-email" element={<VerifyEmailPage />} />
      <Route path="/oauth/callback" element={<OAuthCallbackPage />} />
      <Route path="/invitation/accept" element={<InvitationAcceptPage />} />
      
      <Route
        path="/admin/*"
        element={
          <ProtectedRoute>
            <RoleProtectedRoute allowedRoles={['admin']}>
              <AdminLayout />
            </RoleProtectedRoute>
          </ProtectedRoute>
        }
      >
        <Route index element={<AdminDashboardPage />} />
        <Route path="users" element={<AdminUsersPage />} />
        <Route path="roles" element={<AdminRolesPage />} />
        <Route path="oauth" element={<AdminOAuthPage />} />
        <Route path="security" element={<AdminSecurityPage />} />
        <Route path="settings" element={<AdminSettingsPage />} />
        <Route path="audit" element={<AdminAuditPage />} />
        <Route path="analytics" element={<AdminAnalyticsPage />} />
        <Route path="impersonation" element={<AdminImpersonationPage />} />
        <Route path="invitations" element={<InvitationsPage />} />
        <Route path="tenants" element={<AdminTenantsPage />} />
        <Route path="tenants/:id" element={<TenantDetailPage />} />
        <Route path="email-templates" element={<AdminEmailTemplatesPage />} />
        <Route path="email-branding" element={<AdminEmailBrandingPage />} />
      </Route>

      <Route
        path="/user/*"
        element={
          <ProtectedRoute>
            <RoleProtectedRoute allowedRoles={['admin', 'user']}>
              <UserLayout />
            </RoleProtectedRoute>
          </ProtectedRoute>
        }
      >
        <Route index element={<DashboardPage />} />
        <Route path="security" element={<UserSecurityPage />} />
        <Route path="settings" element={<UserSettingsPage />} />
        <Route path="connected-accounts" element={<UserConnectedAccountsPage />} />
        <Route path="audit" element={<UserAuditPage />} />
        <Route path="api-keys" element={<ApiKeysPage />} />
        <Route path="webhooks" element={<WebhooksPage />} />
        <Route path="invitations" element={<InvitationsPage />} />
      </Route>

      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Navigate to={getDashboardRoute(user?.role)} replace />
          </ProtectedRoute>
        }
      />
      
      <Route path="*" element={<Navigate to={getDashboardRoute(user?.role)} replace />} />
    </Routes>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <GlobalProgressBar />
            <AppRoutes />
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;