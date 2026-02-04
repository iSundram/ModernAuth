import { useState, useEffect, useRef } from 'react';
import { useSearchParams, Link, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Button, Input, LoadingBar } from '../components/ui';
import { invitationService } from '../api/services';
import { Lock, Mail } from 'lucide-react';

export function InvitationAcceptPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token') || '';

  const [isLoading, setIsLoading] = useState(false);
  const [email, setEmail] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string>('');
  const [successMessage, setSuccessMessage] = useState<string>('');
  const validationAttempted = useRef(false);

  useEffect(() => {
    const validate = async () => {
      if (!token) {
        setError('Missing invitation token.');
        return;
      }

      // Prevent double validation in React Strict Mode
      if (validationAttempted.current) {
        return;
      }
      validationAttempted.current = true;

      setIsLoading(true);
      try {
        const res = await invitationService.validate(token);
        setEmail(res.email);
        const fullName = [res.first_name, res.last_name].filter(Boolean).join(' ');
        setName(fullName || res.email);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'Invalid or expired invitation link.';
        setError(msg);
      } finally {
        setIsLoading(false);
      }
    };
    validate();
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!password || password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setIsLoading(true);
    try {
      await invitationService.accept(token, {
        password,
        username: undefined,
      });
      setSuccessMessage('Your account has been created. You can now sign in.');
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to accept invitation.';
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[var(--color-background)] flex items-center justify-center p-4">
      <LoadingBar isLoading={isLoading} message="Processing invitation..." />
      <div className="w-full max-w-md">
        <Card>
          <CardHeader>
            <CardTitle>Accept Invitation</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {error && (
              <div className="p-3 rounded-lg bg-[var(--color-error)]/10 border border-[var(--color-error)]/20 text-[var(--color-error)] text-sm">
                {error}
              </div>
            )}
            {successMessage ? (
              <div className="space-y-4">
                <p className="text-sm text-[var(--color-text-secondary)]">{successMessage}</p>
                <Button className="w-full" onClick={() => navigate('/login')}>
                  Go to Login
                </Button>
              </div>
            ) : (
              <>
                <p className="text-sm text-[var(--color-text-secondary)]">
                  {name ? `You have been invited as ${name}.` : 'You have been invited to join this workspace.'}
                </p>
                <div className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)]">
                  <Mail size={16} />
                  <span>{email || 'Verifying invitation...'}</span>
                </div>
                <form onSubmit={handleSubmit} className="space-y-4 mt-2">
                  <Input
                    label="Password"
                    type="password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    leftIcon={<Lock size={16} />}
                    required
                  />
                  <Input
                    label="Confirm Password"
                    type="password"
                    value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    leftIcon={<Lock size={16} />}
                    required
                  />
                  <Button type="submit" className="w-full">
                    Create Account
                  </Button>
                </form>
                <p className="text-xs text-[var(--color-text-muted)] text-center">
                  Already have an account?{' '}
                  <Link to="/login" className="text-[var(--color-info)] hover:text-[var(--color-info-dark)]">
                    Sign in
                  </Link>
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

