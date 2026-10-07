import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { cx } from '../lib/cx';
import { Button, IconButton } from './Button';
import { focusableWithin, trapTab } from './focus';

/** Modal dialog: traps focus, closes on Escape / backdrop click, restores focus on close. */
export function Modal({
  title,
  ariaLabel,
  onClose,
  children,
  footer,
  size = 'md',
  className,
  hideHeader = false,
}: {
  title?: ReactNode;
  ariaLabel?: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  hideHeader?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const container = ref.current;
    if (container) {
      const autofocus = container.querySelector<HTMLElement>('[data-autofocus]');
      (autofocus ?? focusableWithin(container)[0] ?? container).focus({ preventScroll: true });
    }
    return () => {
      if (previous && previous.isConnected) previous.focus({ preventScroll: true });
    };
  }, []);

  return createPortal(
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title && !ariaLabel ? titleId : undefined}
        aria-label={ariaLabel}
        className={cx('modal', `modal--${size}`, className)}
        tabIndex={-1}
        onKeyDown={(event) => {
          if (event.key === 'Escape') {
            event.stopPropagation();
            onClose();
            return;
          }
          if (ref.current) trapTab(event, ref.current);
        }}
      >
        {!hideHeader ? (
          <header className="modal__header">
            <h2 className="modal__title" id={titleId}>
              {title}
            </h2>
            <IconButton label="Close dialog" icon="close" onClick={onClose} />
          </header>
        ) : null}
        <div className="modal__body">{children}</div>
        {footer ? <footer className="modal__footer">{footer}</footer> : null}
      </div>
    </div>,
    document.body,
  );
}

/** Confirmation for lifecycle/destructive actions; `requireText` asks the user to type a name. */
export function ConfirmDialog({
  title,
  children,
  confirmLabel = 'Confirm',
  danger = false,
  requireText,
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  requireText?: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState('');
  const inputId = useId();
  const allowed = !requireText || typed.trim() === requireText;
  return (
    <Modal
      title={title}
      onClose={onCancel}
      size="sm"
      footer={
        <>
          <Button onClick={onCancel}>Cancel</Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            disabled={!allowed}
            loading={busy}
            onClick={onConfirm}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="stack">
        <div>{children}</div>
        {requireText ? (
          <div className="field">
            <label className="field__label" htmlFor={inputId}>
              Type <code>{requireText}</code> to confirm
            </label>
            <input
              id={inputId}
              className="input mono"
              value={typed}
              autoComplete="off"
              spellCheck={false}
              data-autofocus
              onChange={(event) => setTyped(event.target.value)}
            />
          </div>
        ) : null}
      </div>
    </Modal>
  );
}
