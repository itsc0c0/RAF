import { useId, type ComponentPropsWithRef, type ReactNode } from 'react';
import { cx } from '../lib/cx';

/** Label + control wrapper. The control is rendered by `children(id)` so labels stay associated. */
export function Field({
  label,
  hint,
  children,
  className,
  inline = false,
}: {
  label: ReactNode;
  hint?: ReactNode;
  children: (id: string) => ReactNode;
  className?: string;
  inline?: boolean;
}) {
  const id = useId();
  return (
    <div className={cx('field', inline && 'field--inline', className)}>
      <label className="field__label" htmlFor={id}>
        {label}
      </label>
      {children(id)}
      {hint ? <p className="field__hint">{hint}</p> : null}
    </div>
  );
}

export function TextInput({ className, ...rest }: ComponentPropsWithRef<'input'>) {
  return <input className={cx('input', className)} autoComplete="off" spellCheck={false} {...rest} />;
}

export function TextArea({ className, ...rest }: ComponentPropsWithRef<'textarea'>) {
  return <textarea className={cx('input', 'textarea', className)} {...rest} />;
}

export interface SelectOption {
  value: string;
  label: string;
}

export function Select({
  options,
  className,
  ...rest
}: Omit<ComponentPropsWithRef<'select'>, 'children'> & { options: readonly SelectOption[] }) {
  return (
    <select className={cx('select', className)} {...rest}>
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

export function Checkbox({
  label,
  checked,
  onChange,
  count,
  swatch,
}: {
  label: ReactNode;
  checked: boolean;
  onChange: (checked: boolean) => void;
  count?: number;
  swatch?: ReactNode;
}) {
  return (
    <label className="checkbox">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {swatch}
      <span className="checkbox__label truncate">{label}</span>
      {count !== undefined ? <span className="checkbox__count tabular">{count}</span> : null}
    </label>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      className={cx('switch', checked && 'is-on')}
      onClick={() => onChange(!checked)}
    >
      <span className="switch__thumb" aria-hidden="true" />
    </button>
  );
}
