/* eslint-disable react-refresh/only-export-components */
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from 'lucide-react';
import { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { ReactNode } from 'react';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  duration?: number;
}

interface ToastContextType {
  toasts: Toast[];
  showToast: (toast: Omit<Toast, 'id'>) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within ToastProvider');
  }
  return context;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).substring(7);
    const newToast: Toast = { ...toast, id, duration: toast.duration || 5000 };
    
    setToasts((prev) => [...prev, newToast]);

    // Auto remove after duration
    setTimeout(() => {
      removeToast(id);
    }, newToast.duration);
  }, [removeToast]);

  return (
    <ToastContext.Provider value={{ toasts, showToast, removeToast }}>
      {children}
      <ToastContainer toasts={toasts} onRemove={removeToast} />
    </ToastContext.Provider>
  );
}

function ToastContainer({ toasts, onRemove }: { toasts: Toast[]; onRemove: (id: string) => void }) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-10 left-1/2 -translate-x-1/2 z-[2147483647] flex flex-col-reverse gap-3 w-full max-w-md px-4 pointer-events-none">
      {toasts.map((toast) => (
        <div key={toast.id} className="pointer-events-auto">
          <ToastItem toast={toast} onRemove={onRemove} />
        </div>
      ))}
    </div>
  );
}

function ToastItem({ toast, onRemove }: { toast: Toast; onRemove: (id: string) => void }) {
  const [progress, setProgress] = useState(100);
  const duration = toast.duration || 5000;

  useEffect(() => {
    const startTime = Date.now();
    const timer = setInterval(() => {
      const elapsed = Date.now() - startTime;
      const remaining = Math.max(0, 100 - (elapsed / duration) * 100);
      setProgress(remaining);
      if (remaining === 0) clearInterval(timer);
    }, 16);

    return () => clearInterval(timer);
  }, [duration]);

  const icons = {
    success: <CheckCircle size={18} />,
    error: <AlertCircle size={18} />,
    warning: <AlertTriangle size={18} />,
    info: <Info size={18} />,
  };

  const accentColors = {
    success: 'bg-green-500',
    error: 'bg-red-500',
    warning: 'bg-amber-500',
    info: 'bg-blue-500',
  };

  const iconColors = {
    success: 'text-green-600',
    error: 'text-red-600',
    warning: 'text-amber-600',
    info: 'text-blue-600',
  };

  return (
    <div
      className="
        relative overflow-hidden
        flex items-stretch min-h-[72px] rounded-xl
        bg-[#FFFFFF]
        border border-[#D4D4D4]
        shadow-[0_4px_12px_rgba(0,0,0,0.05),0_16px_48px_rgba(0,0,0,0.12)]
        animate-toast-in
        transition-all duration-300
        w-full
      "
    >
      {/* Left Accent Bar */}
      <div className={`w-1.5 flex-shrink-0 ${accentColors[toast.type]}`} />

      <div className="flex flex-1 items-start gap-3 p-4">
        <div className={`flex-shrink-0 mt-0.5 ${iconColors[toast.type]}`}>
          {icons[toast.type]}
        </div>
        
        <div className="flex-1 min-w-0 pr-4">
          <p className="font-heading text-[15px] font-bold text-[#2B2B2B] leading-tight">
            {toast.title}
          </p>
          {toast.message && (
            <p className="font-sans text-[13px] text-[#555555] mt-1.5 font-medium leading-relaxed">
              {toast.message}
            </p>
          )}
        </div>

        <button
          onClick={() => onRemove(toast.id)}
          className="flex-shrink-0 text-[#B3B3B3] hover:text-[#2B2B2B] transition-colors p-1 hover:bg-[#F5F5F5] rounded-lg"
        >
          <X size={16} />
        </button>
      </div>

      {/* Thin Bottom Progress Bar */}
      <div className="absolute bottom-0 left-0 w-full h-[2px] bg-[#F0F0F0]">
        <div 
          className={`h-full transition-all duration-[16ms] ease-linear ${accentColors[toast.type]}`}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
}
