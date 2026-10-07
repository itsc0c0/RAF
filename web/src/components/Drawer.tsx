import { useEffect, useId, useRef, type ReactNode } from 'react';
import { cx } from '../lib/cx';
import { IconButton } from './Button';

/**
 * Non-modal side panel (object inspector, finding detail, Oracle). It takes focus when it opens,
 * closes on Escape, and gives focus back to where the user was.
 */
export function Drawer({
  title,
  subtitle,
  onClose,
  children,
  actions,
  footer,
  level = 'base',
  className,
  closeLabel = 'Close panel',
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  actions?: ReactNode;
  footer?: ReactNode;
  /** 'top' stacks above a 'base' drawer (e.g. the inspector over the Oracle panel). */
  level?: 'base' | 'top';
  className?: string;
  closeLabel?: string;
}) {
  const ref = useRef<HTMLElement>(null);
  const titleId = useId();

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    ref.current?.focus({ preventScroll: true });
    return () => {
      if (previous && previous.isConnected) previous.focus({ preventScroll: true });
    };
  }, []);

  return (
    <aside
      ref={ref}
      className={cx('drawer', level === 'top' && 'drawer--top', className)}
      role="dialog"
      aria-labelledby={titleId}
      tabIndex={-1}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.stopPropagation();
          onClose();
        }
      }}
    >
      <header className="drawer__header">
        <div className="drawer__titles">
          <h2 className="drawer__title" id={titleId}>
            {title}
          </h2>
          {subtitle ? <div className="drawer__subtitle">{subtitle}</div> : null}
        </div>
        <div className="drawer__actions">
          {actions}
          <IconButton label={closeLabel} icon="close" onClick={onClose} />
        </div>
      </header>
      <div className="drawer__body">{children}</div>
      {footer ? <footer className="drawer__footer">{footer}</footer> : null}
    </aside>
  );
}
