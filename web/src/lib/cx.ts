/** Joins truthy class names. */
export function cx(...classes: Array<string | false | null | undefined | 0>): string {
  return classes.filter(Boolean).join(' ');
}
