import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Input, LoadingBar } from '../components/ui';
import { Lock, ArrowLeft, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/Toast';

export function PasswordLoginPage() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  
  // MFA State
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaUserId, setMfaUserId] = useState('');
  const [mfaCode, setMfaCode] = useState('');

  const { login, loginMfa, isAuthenticated } = useAuth();
  const { showToast } = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/');
      return;
    }

    // Retrieve email from session storage
    const storedEmail = sessionStorage.getItem('loginEmail');
    if (!storedEmail) {
      // If no email, redirect back to email login
      navigate('/login');
      return;
    }
    setEmail(storedEmail);
  }, [navigate, isAuthenticated]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!password) {
      setError('Please enter your password');
      return;
    }

    setIsLoading(true);
    
    try {
      const result = await login({ email, password });
      
      if (result && result.mfa_required) {
        setMfaRequired(true);
        setMfaUserId(result.user_id);
        setIsLoading(false);
        return;
      }
      
      // Clear session storage
      sessionStorage.removeItem('loginEmail');
      
      showToast({ title: 'Success', message: 'Successfully logged in!', type: 'success' });
      
      // Navigate to dashboard
      navigate('/');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid password';
      setError(errorMessage);
      showToast({ title: 'Login Failed', message: errorMessage, type: 'error' });
    } finally {
      if (!mfaRequired) {
        setIsLoading(false);
      }
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!mfaCode || mfaCode.length !== 6) {
      setError('Please enter a valid 6-digit code');
      return;
    }

    setIsLoading(true);

    try {
      await loginMfa(mfaUserId, mfaCode);
      
      // Clear session storage
      sessionStorage.removeItem('loginEmail');
      
      showToast({ title: 'Success', message: 'Successfully logged in!', type: 'success' });
      navigate('/');
    } catch (err) {
       const errorMessage = err instanceof Error ? err.message : 'Invalid MFA code';
       setError(errorMessage);
       showToast({ title: 'MFA Failed', message: errorMessage, type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  const handleBack = () => {
    // Clear session storage and go back
    sessionStorage.removeItem('loginEmail');
    navigate('/login');
  };

  const maskEmail = (email: string) => {
    const [username, domain] = email.split('@');
    if (username.length <= 3) return email;
    
    const masked = username.substring(0, 3) + '*'.repeat(username.length - 3);
    return `${masked}@${domain}`;
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      {/* Progress Bar - Only top bar, no overlay */}
      <LoadingBar isLoading={isLoading} message={mfaRequired ? "Verifying..." : "Signing in..."} />

      {/* Background Pattern */}
      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          {/* Login Box */}
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
          {/* Logo inside box */}
          <div className="flex flex-col items-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white shadow-2xl mb-4 overflow-hidden p-2">
              <img src="/logo.svg" alt="ModernAuth Logo" className="w-full h-full object-contain" />
            </div>
            <h2 className="text-3xl font-bold text-[var(--color-text-primary)] text-center font-poppins">
              {mfaRequired ? 'Two-Factor Authentication' : 'Sign In'}
            </h2>
            <p className="text-base text-[var(--color-text-secondary)] text-center mt-4">
              {mfaRequired ? 'Enter verification code' : 'Welcome back'}
            </p>
            <p className="text-sm text-[var(--color-text-muted)] text-center">
              {email && maskEmail(email)}
            </p>
          </div>

            {error && (
              <div className="mb-6 p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
                {error}
              </div>
            )}

            {!mfaRequired ? (
              <form onSubmit={handleSubmit} className="space-y-6">
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
                  autoFocus
                />

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={handleBack}
                    className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
                  >
                    <ArrowLeft size={16} />
                    Back
                  </button>
                  
                  <Link
                    to="/forgot-password"
                    className="text-sm text-[var(--color-info)] hover:text-[var(--color-info-dark)] transition-colors"
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
              </form>
            ) : (
              <form onSubmit={handleMfaSubmit} className="space-y-6">
                 <Input
                    label="Authentication Code"
                    type="text"
                    placeholder="000000"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    leftIcon={<ShieldCheck size={18} />}
                    autoComplete="one-time-code"
                    className="text-center tracking-widest text-lg"
                    autoFocus
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
                    onClick={() => {
                      setMfaRequired(false);
                      setIsLoading(false);
                    }}
                    className="w-full text-center text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
                  >
                    Back to Password
                  </button>
              </form>
            )}
           </div>

           {/* Additional footer */}
           <p className="text-center mt-6 text-sm text-[var(--color-text-muted)]">
             © 2024 ModernAuth. All rights reserved.
           </p>
         </div>
       </div>
     </div>
   );
}
