import { useEffect, useState } from 'react';
import * as React from 'react';
import './LoadingBar.css';

interface LoadingBarProps {
  isLoading: boolean;
  message?: string;
  showOverlay?: boolean;
  overlayOpacity?: number;
  variant?: 'default' | 'mini';
}

export function LoadingBar({
  isLoading,
  message,
  showOverlay = false,
  overlayOpacity = 0.8,
  variant = 'default'
}: LoadingBarProps) {
  const [show, setShow] = useState(false);

  useEffect(() => {
    if (isLoading) {
      setShow(true);
    } else {
      // Delay hiding to allow animation to complete
      const timer = setTimeout(() => setShow(false), 500);
      return () => clearTimeout(timer);
    }
  }, [isLoading]);

  if (!show) return null;

  return (
    <>
      {/* Progress Bar - Always shows at top when loading */}
      <div
        className={`owehost-progress-bar-container ${variant === 'mini' ? 'owehost-progress-bar-mini' : ''}`}
      >
        <div className="owehost-progress-bar-inner" />
      </div>

      {/* Loading Overlay - Only shows when explicitly requested */}
      {showOverlay && (
        <div
          className="owehost-loading-overlay"
          style={{ backgroundColor: `rgba(255,255, 255, ${overlayOpacity})` }}
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
 
// Hook for global loading state
export function useLoadingBar() {
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('Loading...');

  const showLoading = (msg?: string) => {
    setMessage(msg || 'Loading...');
    setIsLoading(true);
  };

  const hideLoading = () => {
    setIsLoading(false);
  };

  return { isLoading, message, showLoading, hideLoading };
}

// Context Provider for global loading
interface LoadingContextType {
  isLoading: boolean;
  message: string;
  showLoading: (message?: string) => void;
  hideLoading: () => void;
}

export const LoadingContext = React.createContext<LoadingContextType | undefined>(undefined);

export function LoadingProvider({ children }: { children: React.ReactNode }) {
  const { isLoading, message, showLoading, hideLoading } = useLoadingBar();

  return (
    <LoadingContext.Provider value={{ isLoading, message, showLoading, hideLoading }}>
      {children}
      <LoadingBar isLoading={isLoading} />
    </LoadingContext.Provider>
  );
}

export function useGlobalLoading() {
  const context = React.useContext(LoadingContext);
  if (!context) {
    throw new Error('useGlobalLoading must be used within LoadingProvider');
  }
  return context;
}
