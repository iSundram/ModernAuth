import { useIsFetching, useIsMutating } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { LoadingBar } from './LoadingBar';
import './LoadingBar.css';

const MIN_LOADING_DURATION = 1500; // 1.5 seconds minimum

/**
 * GlobalProgressBar automatically shows a progress bar at the top of the screen
 * whenever there are any React Query fetches or mutations in progress.
 * Shows for a minimum of 1.5 seconds and adds a subtle blur overlay to content.
 * 
 * Place this component once at the app root level.
 */
export function GlobalProgressBar() {
  const isFetching = useIsFetching();
  const isMutating = useIsMutating();
  const [isVisible, setIsVisible] = useState(false);
  const [loadingStartTime, setLoadingStartTime] = useState<number | null>(null);
  
  const hasActiveRequests = isFetching > 0 || isMutating > 0;

  useEffect(() => {
    if (hasActiveRequests && !isVisible) {
      // Start loading
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Sync visibility with request state
      setIsVisible(true);
      setLoadingStartTime(Date.now());
    } else if (!hasActiveRequests && isVisible && loadingStartTime) {
      // Check if minimum duration has passed
      const elapsed = Date.now() - loadingStartTime;
      const remaining = MIN_LOADING_DURATION - elapsed;
      
      if (remaining > 0) {
        // Wait for remaining time before hiding
        const timer = setTimeout(() => {
          setIsVisible(false);
          setLoadingStartTime(null);
        }, remaining);
        return () => clearTimeout(timer);
      } else {
        // Minimum time passed, hide immediately
        setIsVisible(false);
        setLoadingStartTime(null);
      }
    }
  }, [hasActiveRequests, isVisible, loadingStartTime]);

  if (!isVisible) return null;

  return (
    <>
      {/* Progress Bar at top */}
      <LoadingBar isLoading={true} showOverlay={false} />
      
      {/* Subtle blur overlay for content */}
      <div className="global-loading-overlay" />
    </>
  );
}
