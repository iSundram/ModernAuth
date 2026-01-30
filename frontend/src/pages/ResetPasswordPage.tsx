import { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { ArrowLeft, Lock, Eye, EyeOff, CheckCircle } from 'lucide-react';
import { Button, Input, LoadingBar } from '../components/ui';
import { authService } from '../api/services';
import { useToast } from '../components/ui/Toast';
import { PasswordStrength } from '../components/security';

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const { showToast } = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    if (!token) {
      showToast({ 
        title: 'Error', 
        message: 'Invalid or missing reset token', 
        type: 'error' 
      });
      navigate('/login');
    }
  }, [token, navigate, showToast]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password || !token) return;

    if (password !== confirmPassword) {
      showToast({ title: 'Error', message: 'Passwords do not match', type: 'error' });
      return;
    }

    if (password.length < 8) {
      showToast({ title: 'Error', message: 'Password must be at least 8 characters', type: 'error' });
      return;
    }

    setIsLoading(true);
    try {
      await authService.resetPassword({ token, new_password: password });
      setIsSuccess(true);
      showToast({ 
        title: 'Success', 
        message: 'Password has been reset successfully', 
        type: 'success' 
      });
    } catch (error) {
      showToast({ 
        title: 'Error', 
        message: error instanceof Error ? error.message : 'Failed to reset password', 
        type: 'error' 
      });
    } finally {
      setIsLoading(false);
    }
  };

  if (!token) return null;

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      <LoadingBar isLoading={isLoading} message="Updating password..." />

      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
            <div className="flex flex-col items-center mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-background-secondary)] mb-4">
                {isSuccess ? (
                  <CheckCircle size={32} className="text-[var(--color-success)]" />
                ) : (
                  <Lock size={32} className="text-[var(--color-primary)]" />
                )}
              </div>
              <h2 className="text-2xl font-bold text-[var(--color-text-primary)] text-center">
                {isSuccess ? 'Password Reset' : 'New Password'}
              </h2>
              <p className="text-base text-[var(--color-text-secondary)] text-center mt-2">
                {isSuccess ? 'Your password has been updated successfully.' : 'Create a new secure password'}
              </p>
            </div>

            {!isSuccess ? (
              <form onSubmit={handleSubmit} className="space-y-6">
                <Input
                  label="New Password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Minimum 8 characters"
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
                  required
                />

                {password && (
                  <PasswordStrength password={password} />
                )}

                <Input
                  label="Confirm Password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Re-enter password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  leftIcon={<Lock size={18} />}
                  required
                />

                <Button
                  type="submit"
                  variant="primary"
                  size="lg"
                  className="w-full"
                  isLoading={isLoading}
                >
                  Reset Password
                </Button>
              </form>
            ) : (
              <div className="space-y-6">
                <Button
                  variant="primary"
                  size="lg"
                  className="w-full"
                  onClick={() => navigate('/login')}
                >
                  Sign in with new password
                </Button>
              </div>
            )}

            {!isSuccess && (
              <div className="mt-8 text-center">
                <Link
                  to="/login"
                  className="inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
                >
                  <ArrowLeft size={16} />
                  Back to Login
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
