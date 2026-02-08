/* eslint-disable react-refresh/only-export-components */
import { useState, useEffect } from 'react';
import { AlertCircle, Clock } from 'lucide-react';

export interface RateLimitInfo {
  limit: number;
  remaining: number;
  reset: number; // Unix timestamp
  retryAfter?: number; // Seconds
}

interface RateLimitNoticeProps {
  rateLimitInfo?: RateLimitInfo | null;
  className?: string;
}

export function RateLimitNotice({ rateLimitInfo, className = '' }: RateLimitNoticeProps) {
  const [countdown, setCountdown] = useState<number | null>(null);

  useEffect(() => {
    if (!rateLimitInfo) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Sync countdown with rate limit info
      setCountdown(null);
      return;
    }

    // If rate limited (remaining is 0 or we have retryAfter)
    if (rateLimitInfo.remaining === 0 || rateLimitInfo.retryAfter) {
      const initialSeconds = rateLimitInfo.retryAfter || 
        Math.max(0, Math.ceil((rateLimitInfo.reset * 1000 - Date.now()) / 1000));
      
      setCountdown(initialSeconds);

      const timer = setInterval(() => {
        setCountdown(prev => {
          if (prev === null || prev <= 1) {
            clearInterval(timer);
            return null;
          }
          return prev - 1;
        });
      }, 1000);

      return () => clearInterval(timer);
    } else {
      // Not rate limited - reset countdown
      setCountdown(null);
    }
  }, [rateLimitInfo]);

  if (!rateLimitInfo) return null;

  // Show rate limit warning when getting low
  const isLow = rateLimitInfo.remaining <= Math.ceil(rateLimitInfo.limit * 0.2);
  const isExhausted = rateLimitInfo.remaining === 0;

  if (!isLow && !isExhausted) return null;

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    if (mins > 0) {
      return `${mins}m ${secs}s`;
    }
    return `${secs}s`;
  };

  return (
    <div 
      className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
        isExhausted 
          ? 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20' 
          : 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border border-yellow-500/20'
      } ${className}`}
    >
      {isExhausted ? (
        <>
          <Clock size={16} className="flex-shrink-0" />
          <span>
            Rate limited. {countdown !== null && countdown > 0 
              ? `Try again in ${formatTime(countdown)}`
              : 'Please wait...'}
          </span>
        </>
      ) : (
        <>
          <AlertCircle size={16} className="flex-shrink-0" />
          <span>
            {rateLimitInfo.remaining} of {rateLimitInfo.limit} requests remaining
          </span>
        </>
      )}
    </div>
  );
}

// Hook to extract rate limit info from API responses
export function useRateLimitInfo() {
  const [rateLimitInfo, setRateLimitInfo] = useState<RateLimitInfo | null>(null);

  const updateFromHeaders = (headers: Headers) => {
    const limitStr = headers.get('X-RateLimit-Limit');
    const remainingStr = headers.get('X-RateLimit-Remaining');
    const resetStr = headers.get('X-RateLimit-Reset');
    const retryAfterStr = headers.get('Retry-After');

    if (limitStr && remainingStr && resetStr) {
      const limit = parseInt(limitStr, 10);
      const remaining = parseInt(remainingStr, 10);
      const reset = parseInt(resetStr, 10);
      const retryAfter = retryAfterStr ? parseInt(retryAfterStr, 10) : undefined;

      // Validate parsed values are valid numbers
      if (!isNaN(limit) && !isNaN(remaining) && !isNaN(reset)) {
        setRateLimitInfo({
          limit,
          remaining,
          reset,
          retryAfter: retryAfter !== undefined && !isNaN(retryAfter) ? retryAfter : undefined,
        });
      }
    }
  };

  const clear = () => setRateLimitInfo(null);

  return {
    rateLimitInfo,
    updateFromHeaders,
    clear,
  };
}
