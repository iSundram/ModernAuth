import { useState, useEffect } from 'react';
import type { FormEvent } from 'react';
import { Navigate, Link, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useAuth } from '../hooks/useAuth';
import { Button, Input, LoadingBar } from '../components/ui';
import { Lock, Mail, Eye, EyeOff, ShieldCheck, Github, Chrome } from 'lucide-react';
import { authService } from '../api/services';
import type { UserRole } from '../types';

function getDashboardRoute(role?: UserRole): string {
  switch (role) {
    case 'admin':
      return '/admin';
    case 'user':
    default:
      return '/user';
  }
}

export function LoginPage() {
  const { login, loginMfa, isAuthenticated, isLoading, user, settings } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [searchParams] = useSearchParams();
  
  // MFA State
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaUserId, setMfaUserId] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  // Fetch OAuth providers
  const { data: oauthData } = useQuery({
    queryKey: ['oauth-providers'],
    queryFn: () => authService.getOAuthProviders(),
  });
  const oauthProviders = oauthData?.providers || [];

  // Handle OAuth callback (if redirected back from provider)
  useEffect(() => {
    const oauthError = searchParams.get('error');

    if (oauthError) {
      setError(`OAuth error: ${oauthError}`);
    }
    // Note: OAuth callback is typically handled server-side
    // The backend callback endpoint should redirect back to frontend with tokens
  }, [searchParams]);

  const handleOAuthLogin = async (provider: string) => {
    try {
      const response = await authService.getOAuthAuthorizationURL(provider);
      // Redirect to OAuth provider
      window.location.href = response.authorization_url;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to initiate OAuth login';
      setError(errorMessage);
    }
  };

  if (isAuthenticated && user) {
    return <Navigate to={getDashboardRoute(user.role)} replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!email || !password) {
      setError('Please enter both email and password');
      return;
    }

    try {
      const result = await login({ email, password });
      if (result && result.mfa_required) {
        setMfaRequired(true);
        setMfaUserId(result.user_id);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid email or password';
      setError(errorMessage);
    }
  };

  const handleMfaSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');

    if (!mfaCode || mfaCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    try {
      await loginMfa(mfaUserId, mfaCode);
    } catch (err) {
       const errorMessage = err instanceof Error ? err.message : 'Invalid MFA code';
       setError(errorMessage);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      {/* Loading Overlay */}
      <LoadingBar isLoading={isLoading} message={mfaRequired ? "Verifying code..." : "Signing in..."} showOverlay={true} />
      
      {/* Background Pattern */}
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white shadow-2xl mb-4 overflow-hidden p-2">
              <img src="/logo.svg" alt="ModernAuth Logo" className="w-full h-full object-contain" />
          </div>
          <h1 className="text-3xl font-bold text-[var(--color-text-primary)]">ModernAuth</h1>
          <p className="text-[var(--color-text-secondary)] mt-2">Authentication & Identity</p>
        </div>

        {/* Login Card */}
        <div className="bg-[var(--color-surface)] rounded-2xl p-8 shadow-2xl border border-[var(--color-border-light)]">
          <h2 className="text-xl font-semibold text-[var(--color-text-primary)] mb-6">
            {mfaRequired ? 'Two-Factor Authentication' : 'Sign in to your account'}
          </h2>

          {error && (
            <div className="mb-4 p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
              {error}
            </div>
          )}

          {!mfaRequired ? (
            <form onSubmit={handleSubmit} className="space-y-5">
              <Input
                label="Email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                leftIcon={<Mail size={18} />}
                autoComplete="email"
              />

              <Input
                label="Password"
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                leftIcon={<Lock size={18} />}
                rightIcon={
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="hover:text-[var(--color-text-primary)] transition-colors"
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                }
                autoComplete="current-password"
              />

              <div className="flex items-center justify-between text-sm">
                <label className="flex items-center gap-2 text-[var(--color-text-secondary)]">
                  <input
                    type="checkbox"
                    className="w-4 h-4 rounded border-[var(--color-border)] bg-white text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
                  />
                  Remember me
                </label>
                <Link
                  to="/forgot-password"
                  className="text-[var(--color-info)] hover:text-[var(--color-info-dark)]"
                >
                  Forgot password?
                </Link>
              </div>

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full"
                isLoading={isLoading}
              >
                Sign in
              </Button>

              {/* OAuth Providers */}
              {oauthProviders.length > 0 && (
                <>
                  <div className="relative my-6">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-[var(--color-border-light)]"></div>
                    </div>
                    <div className="relative flex justify-center text-sm">
                      <span className="px-2 bg-[var(--color-surface)] text-[var(--color-text-muted)]">
                        Or continue with
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    {oauthProviders.includes('google') && (
                      <Button
                        type="button"
                        variant="outline"
                        className="flex-1"
                        onClick={() => handleOAuthLogin('google')}
                      >
                        <Chrome size={18} className="mr-2" />
                        Google
                      </Button>
                    )}
                    {oauthProviders.includes('github') && (
                      <Button
                        type="button"
                        variant="outline"
                        className="flex-1"
                        onClick={() => handleOAuthLogin('github')}
                      >
                        <Github size={18} className="mr-2" />
                        GitHub
                      </Button>
                    )}
                    {oauthProviders.includes('microsoft') && (
                      <Button
                        type="button"
                        variant="outline"
                        className="flex-1"
                        onClick={() => handleOAuthLogin('microsoft')}
                      >
                        <Chrome size={18} className="mr-2" />
                        Microsoft
                      </Button>
                    )}
                  </div>
                </>
              )}
            </form>
          ) : (
            <form onSubmit={handleMfaSubmit} className="space-y-5">
              <div className="text-sm text-[var(--color-text-secondary)] mb-4">
                Please enter the 6-digit code from your authenticator app.
              </div>
              
              <Input
                label="Authentication Code"
                type="text"
                placeholder="000000"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                leftIcon={<ShieldCheck size={18} />}
                autoComplete="one-time-code"
                className="text-center tracking-widest text-lg"
              />

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full"
                isLoading={isLoading}
              >
                Verify Code
              </Button>
              
              <button 
                type="button"
                onClick={() => setMfaRequired(false)}
                className="w-full text-center text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
              >
                Back to Login
              </button>
            </form>
          )}

          {!mfaRequired && settings['auth.allow_registration'] !== false && (
            <div className="mt-6 text-center">
              <p className="text-sm text-[var(--color-text-muted)]">
                Don't have an account?{' '}
                <Link to="/register" className="text-[var(--color-info)] hover:text-[var(--color-info-dark)] font-medium">
                  Sign up
                </Link>
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center mt-8 text-sm text-[var(--color-text-muted)]">
          © 2024 ModernAuth. All rights reserved.
        </p>
        </div>
      </div>
    </div>
  );
}