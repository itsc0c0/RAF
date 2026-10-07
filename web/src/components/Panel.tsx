import type { ReactNode } from 'react';
import { cx } from '../lib/cx';

export function PageHeader({
  title,
  subtitle,
  actions,
  children,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="page-header__main">
        <div className="page-header__titles">
          <h1>{title}</h1>
          {subtitle ? <p className="page-header__subtitle">{subtitle}</p> : null}
        </div>
        {actions ? <div className="page-header__actions">{actions}</div> : null}
      </div>
      {children}
    </header>
  );
}

export function Panel({
  title,
  actions,
  children,
  className,
  flush = false,
  id,
  footer,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /** No body padding (tables, lists that bring their own spacing). */
  flush?: boolean;
  id?: string;
  footer?: ReactNode;
}) {
  return (
    <section className={cx('panel', className)} aria-labelledby={title && id ? `${id}-title` : undefined}>
      {title || actions ? (
        <header className="panel__header">
          {title ? (
            <h2 className="panel__title" id={id ? `${id}-title` : undefined}>
              {title}
            </h2>
          ) : (
            <span />
          )}
          {actions ? <div className="panel__actions">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cx('panel__body', flush && 'panel__body--flush')}>{children}</div>
      {footer ? <footer className="panel__footer">{footer}</footer> : null}
    </section>
  );
}

export function Toolbar({
  children,
  className,
  label,
}: {
  children: ReactNode;
  className?: string;
  label?: string;
}) {
  return (
    <div className={cx('toolbar', className)} role="toolbar" aria-label={label}>
      {children}
    </div>
  );
}

export function Callout({
  tone = 'info',
  children,
  title,
}: {
  tone?: 'info' | 'warn' | 'bad';
  title?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className={cx('callout', `callout--${tone}`)} role={tone === 'info' ? 'note' : 'status'}>
      {title ? <p className="callout__title">{title}</p> : null}
      <div className="callout__body">{children}</div>
    </div>
  );
}
