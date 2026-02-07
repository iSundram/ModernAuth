import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Button, Input, LoadingBar } from '../components/ui';
import { Mail, Lock, User, ArrowRight } from 'lucide-react';
import { useToast } from '../components/ui/Toast';
import { authService } from '../api/services';
import { useAuth } from '../hooks/useAuth';
import { PasswordStrength, CaptchaWidget } from '../components/security';

export function RegisterPage() {
  const { settings } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [captchaToken, setCaptchaToken] = useState('');
  
  const { showToast } = useToast();
  const navigate = useNavigate();

  // Check if registration is allowed
  useEffect(() => {
    if (settings['auth.allow_registration'] === false) {
      showToast({
        title: 'Registration Disabled',
        message: 'Public registration is currently disabled by the administrator.',
        type: 'error'
      });
      navigate('/login');
    }
  }, [settings, navigate, showToast]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validation
    if (!formData.email || !formData.password || !formData.username) {
      setError('Please fill in all required fields');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long');
      return;
    }

    setIsLoading(true);

    try {
      await authService.register({
        email: formData.email,
        username: formData.username,
        password: formData.password,
        captcha_token: captchaToken,
      });

      showToast({ 
        title: 'Registration Successful', 
        message: 'Your account has been created. Please sign in.', 
        type: 'success' 
      });

      // Navigate to login page
      navigate('/login');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Registration failed';
      setError(errorMessage);
      showToast({ title: 'Error', message: errorMessage, type: 'error' });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)]">
      <LoadingBar isLoading={isLoading} message="Creating account..." />

      <div className="min-h-screen flex items-center justify-center p-4">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-80 h-80 bg-[var(--color-secondary)] rounded-full opacity-10 blur-3xl"></div>
          <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-[var(--color-light)] rounded-full opacity-10 blur-3xl"></div>
        </div>

        <div className="w-full max-w-md relative z-10">
          <div className="bg-white rounded-2xl p-8 shadow-xl border border-[var(--color-border)]">
            <div className="flex flex-col items-center mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-white shadow-2xl mb-4 overflow-hidden p-2">
                <img src="/logo.svg" alt="ModernAuth Logo" className="w-full h-full object-contain" />
              </div>
              <h2 className="text-3xl font-bold text-[var(--color-text-primary)] text-center font-poppins">
                Create Account
              </h2>
              <p className="text-base text-[var(--color-text-secondary)] text-center mt-4">
                Join ModernAuth today
              </p>
            </div>

            {error && (
              <div className="mb-6 p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <Input
                label="Email"
                name="email"
                type="email"
                placeholder="john@example.com"
                value={formData.email}
                onChange={handleChange}
                leftIcon={<Mail size={18} />}
                autoComplete="email"
                required
              />

              <Input
                label="Username"
                name="username"
                type="text"
                placeholder="johndoe"
                value={formData.username}
                onChange={handleChange}
                leftIcon={<User size={18} />}
                autoComplete="username"
                required
              />

              <Input
                label="Password"
                name="password"
                type="password"
                placeholder="••••••••"
                value={formData.password}
                onChange={handleChange}
                leftIcon={<Lock size={18} />}
                autoComplete="new-password"
                required
              />

              {formData.password && (
                <PasswordStrength password={formData.password} />
              )}

              <Input
                label="Confirm Password"
                name="confirmPassword"
                type="password"
                placeholder="••••••••"
                value={formData.confirmPassword}
                onChange={handleChange}
                leftIcon={<Lock size={18} />}
                autoComplete="new-password"
                required
              />

              <CaptchaWidget onToken={setCaptchaToken} action="register" />

              <Button
                type="submit"
                variant="primary"
                size="lg"
                className="w-full mt-6"
                isLoading={isLoading}
                rightIcon={<ArrowRight size={18} />}
              >
                Sign Up
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-[var(--color-text-secondary)]">
                Already have an account?{' '}
                <Link to="/login" className="text-[var(--color-primary)] font-medium hover:underline">
                  Sign in
                </Link>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
