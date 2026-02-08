/* eslint-disable react-refresh/only-export-components */
import { X, CheckCircle, AlertCircle, Info, AlertTriangle } from 'lucide-react';
import { createContext, useContext, useState, useCallback } from 'react';
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
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-3 max-w-md">
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onRemove={onRemove} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onRemove }: { toast: Toast; onRemove: (id: string) => void }) {
  const icons = {
    success: <CheckCircle size={20} className="text-[var(--color-success)]" />,
    error: <AlertCircle size={20} className="text-[var(--color-error)]" />,
    warning: <AlertTriangle size={20} className="text-[var(--color-warning)]" />,
    info: <Info size={20} className="text-[var(--color-info)]" />,
  };

  const colors = {
    success: 'border-[var(--color-success)]/50 bg-[var(--color-success)]/10',
    error: 'border-[var(--color-error)]/50 bg-[var(--color-error)]/10',
    warning: 'border-[var(--color-warning)]/50 bg-[var(--color-warning)]/10',
    info: 'border-[var(--color-info)]/50 bg-[var(--color-info)]/10',
  };

  return (
    <div
      className={`
        flex items-start gap-3 p-4 rounded-lg
        bg-[var(--color-surface)] border-l-4
        shadow-xl backdrop-blur-sm
        animate-slide-in-right
        ${colors[toast.type]}
      `}
    >
      <div className="flex-shrink-0 mt-0.5">{icons[toast.type]}</div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-[var(--color-text-primary)]">
          {toast.title}
        </p>
        {toast.message && (
          <p className="text-sm text-[var(--color-text-secondary)] mt-1">
            {toast.message}
          </p>
        )}
      </div>
      <button
        onClick={() => onRemove(toast.id)}
        className="flex-shrink-0 text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] transition-colors"
      >
        <X size={18} />
      </button>
    </div>
  );
}
