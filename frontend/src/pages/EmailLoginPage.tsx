import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Input, LoadingBar } from '../components/ui';
import { Mail, ChevronRight } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import { useToast } from '../components/ui/Toast';

export function EmailLoginPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const { showToast } = useToast();
  const { isAuthenticated } = useAuth();
  const navigate = useNavigate();

  if (isAuthenticated) {
    navigate('/');
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!email) {
      setError('Please enter your email address');
      return;
    }

    // Basic email validation
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
    if (!emailRegex.test(email)) {
      setError('Please enter a valid email address');
      return;
    }

    setIsLoading(true);

    try {
      // Store email for next step
      sessionStorage.setItem('loginEmail', email);

      // Simulate checking if email exists
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Navigate to password page
      navigate('/login/password');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred';
      setError(errorMessage);
      showToast({ title: 'Error', message: errorMessage, type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      {/* Progress Bar - Only top bar, no overlay */}
      <LoadingBar isLoading={isLoading} message="Checking email..." />

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
              Sign In
            </h2>
            <p className="text-base text-[var(--color-text-secondary)] text-center mt-4">
              Use your ModernAuth Account
            </p>
          </div>

            {error && (
              <div className="mb-6 p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <Input
                label="Email"
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                leftIcon={<Mail size={18} />}
                autoComplete="email"
                autoFocus
              />

              <div className="flex items-center justify-between">
                <Link
                  to="/forgot-password"
                  className="text-sm text-[var(--color-info)] hover:text-[var(--color-info-dark)] transition-colors"
                >
                  Forgot password?
                </Link>

                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  isLoading={isLoading}
                  rightIcon={<ChevronRight size={18} />}
                >
                  Continue
                </Button>
              </div>
            </form>
            
            <div className="mt-6 text-center border-t border-[var(--color-border-light)] pt-6">
              <p className="text-sm text-[var(--color-text-secondary)]">
                Don't have an account?{' '}
                <Link to="/register" className="text-[var(--color-primary)] font-medium hover:underline">
                  Sign up
                </Link>
              </p>
              <p className="text-sm text-[var(--color-text-secondary)] mt-2">
                <Link to="/login/magic-link" className="text-[var(--color-info)] hover:underline">
                  Sign in with Magic Link
                </Link>
              </p>
            </div>
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
