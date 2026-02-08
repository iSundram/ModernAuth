import { useEffect, useState } from 'react';

interface ProgressLoaderProps {
  isLoading: boolean;
  message?: string;
  showOverlay?: boolean;
  overlayOpacity?: number;
}

export function ProgressLoader({ 
  isLoading, 
  message = 'Loading...', 
  showOverlay = true,
  overlayOpacity = 0.8
}: ProgressLoaderProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- Track mount state for SSR
    setMounted(true);
  }, []);

  if (!mounted || !isLoading) return null;

  return (
    <>
      {/* Progress Bar */}
      <div className="owehost-progress-bar-container">
        <div className="owehost-progress-bar-inner" />
      </div>
      
      {/* Loading Overlay */}
      {showOverlay && (
        <div 
          className="owehost-loading-overlay"
          style={{ backgroundColor: `rgba(255, 255, 255, ${overlayOpacity})` }}
        >
          <div className="owehost-loading-content">
            <div className="owehost-spinner" />
            {message && <p className="owehost-loading-message">{message}</p>}
          </div>
        </div>
      )}
    </>
  );
}

export function GlobalProgressLoader({ 
  isLoading, 
  message, 
  showOverlay 
}: { 
  isLoading: boolean; 
  message?: string; 
  showOverlay?: boolean;
}) {
  return <ProgressLoader isLoading={isLoading} message={message} showOverlay={showOverlay} />;
}