import { useState, useEffect } from 'react';
import { UserMinus, AlertTriangle, X } from 'lucide-react';
import { Button } from '../ui';
import { authService } from '../../api/services';
import { useToast } from '../ui/Toast';
import type { ImpersonationStatus } from '../../types';

export function ImpersonationBanner() {
  const [status, setStatus] = useState<ImpersonationStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isEnding, setIsEnding] = useState(false);
  const { showToast } = useToast();

  useEffect(() => {
    const checkImpersonation = async () => {
      try {
        const result = await authService.getImpersonationStatus();
        setStatus(result);
      } catch {
        // Not an impersonation session or endpoint not available
        setStatus(null);
      } finally {
        setIsLoading(false);
      }
    };

    checkImpersonation();
  }, []);

  const handleEndImpersonation = async () => {
    setIsEnding(true);
    try {
      await authService.endImpersonation();
      showToast({
        title: 'Impersonation Ended',
        message: 'You have returned to your admin session',
        type: 'success'
      });
      // Redirect to admin dashboard
      window.location.href = '/admin';
    } catch (_err) {
      showToast({
        title: 'Error',
        message: 'Failed to end impersonation session',
        type: 'error'
      });
    } finally {
      setIsEnding(false);
    }
  };

  if (isLoading || !status?.is_impersonation) {
    return null;
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 bg-gradient-to-r from-amber-500 to-orange-500 text-white shadow-lg">
      <div className="max-w-7xl mx-auto px-4 py-2 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-3">
            <div className="flex-shrink-0">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div className="flex items-center gap-2 text-sm font-medium">
              <UserMinus className="h-4 w-4" />
              <span>
                You are impersonating a user
                {status.admin_user_email && (
                  <span className="ml-1 opacity-80">
                    (Admin: {status.admin_user_email})
                  </span>
                )}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={handleEndImpersonation}
              isLoading={isEnding}
              className="bg-white/10 border-white/20 text-white hover:bg-white/20"
              leftIcon={<X size={16} />}
            >
              End Impersonation
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
