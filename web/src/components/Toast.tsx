import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { cx } from '../lib/cx';
import { IconButton } from './Button';
import { Icon } from './Icon';

export type ToastTone = 'info' | 'good' | 'warn' | 'bad';

export interface ToastInput {
  tone?: ToastTone;
  title: string;
  description?: string;
}

interface ToastItem extends Required<Pick<ToastInput, 'tone' | 'title'>> {
  id: number;
  description?: string;
}

interface ToastContextValue {
  notify: (toast: ToastInput) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((items) => items.filter((item) => item.id !== id));
  }, []);

  const notify = useCallback((toast: ToastInput) => {
    const id = nextId;
    nextId += 1;
    setToasts((items) => [
      ...items.slice(-3),
      { id, tone: toast.tone ?? 'info', title: toast.title, description: toast.description },
    ]);
  }, []);

  const value = useMemo(() => ({ notify }), [notify]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toasts" aria-live="polite" aria-relevant="additions">
        {toasts.map((toast) => (
          <ToastView key={toast.id} toast={toast} onDismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

function ToastView({ toast, onDismiss }: { toast: ToastItem; onDismiss: (id: number) => void }) {
  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(toast.id), toast.tone === 'bad' ? 9000 : 5000);
    return () => window.clearTimeout(timer);
  }, [toast.id, toast.tone, onDismiss]);
  const icon = toast.tone === 'good' ? 'check' : toast.tone === 'info' ? 'info' : 'warning';
  return (
    <div className={cx('toast', `toast--${toast.tone}`)} role={toast.tone === 'bad' ? 'alert' : 'status'}>
      <Icon name={icon} className="toast__icon" />
      <div className="toast__body">
        <p className="toast__title">{toast.title}</p>
        {toast.description ? <p className="toast__description">{toast.description}</p> : null}
      </div>
      <IconButton size="sm" icon="close" label="Dismiss notification" onClick={() => onDismiss(toast.id)} />
    </div>
  );
}

export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error('useToast must be used inside <ToastProvider>');
  return value;
}
