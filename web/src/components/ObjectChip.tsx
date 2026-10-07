import { useInspector } from '../app/shellState';
import { cx } from '../lib/cx';
import { objectKeyOf, objectTypeOf } from '../lib/format';
import { familyOf, typeLabel } from '../lib/objectTypes';

export function TypeTag({ type, className }: { type: string; className?: string }) {
  return (
    <span
      className={cx('type-tag', `type-tag--${familyOf(type)}`, className)}
      title={`Object type: ${typeLabel(type)}`}
    >
      <span className="type-tag__swatch" aria-hidden="true" />
      {typeLabel(type)}
    </span>
  );
}

/**
 * A clickable reference to any object: opens the object inspector. Names and IDs are untrusted
 * strings and are rendered as text.
 */
export function ObjectChip({
  id,
  name,
  type,
  showType = true,
  className,
}: {
  id: string;
  name?: string | null;
  type?: string | null;
  showType?: boolean;
  className?: string;
}) {
  const { open } = useInspector();
  const resolvedType = type || objectTypeOf(id);
  const label = name || objectKeyOf(id);
  return (
    <button
      type="button"
      className={cx('chip', className)}
      onClick={(event) => {
        event.stopPropagation();
        open(id);
      }}
      title={`Inspect ${id}`}
    >
      {showType ? <TypeTag type={resolvedType} /> : null}
      <span className="chip__name">{label}</span>
    </button>
  );
}

/** Text-only reference (non-interactive), e.g. inside an already-clickable row. */
export function ObjectRefText({ id, name }: { id: string | null | undefined; name?: string | null }) {
  if (!id) return <span className="muted">—</span>;
  return (
    <span className="object-ref" title={id}>
      {name || objectKeyOf(id)}
    </span>
  );
}
