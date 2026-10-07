/**
 * Lab create form: client-side checks mirroring the server's rules (src/raf/products/lab) and the
 * exact `POST /lab/labs` body. The server validates everything again (mount paths are resolved and
 * checked on the server); these checks only give earlier, clearer feedback.
 */
import type { LabCreateRequest } from '../../api/types';

export const MAX_MOUNTS = 8;
export const MAX_DESCRIPTION = 500;
export const LAB_BACKENDS = ['auto', 'docker', 'podman'] as const;

export interface LabFormState {
  name: string;
  image: string;
  mounts: string[];
  allowOutbound: boolean;
  memory: string;
  cpus: string;
  root: boolean;
  description: string;
  /** '' = the server's `lab.backend` setting. */
  backend: string;
}

export const EMPTY_LAB_FORM: LabFormState = {
  name: '',
  image: '',
  mounts: [],
  allowOutbound: false,
  memory: '',
  cpus: '',
  root: false,
  description: '',
  backend: '',
};

const NAME_RE = /^[a-z0-9][a-z0-9-]{1,40}$/;
const MEMORY_RE = /^[1-9][0-9]{0,5}[mg]$/i;
const CPUS_RE = /^[0-9]{1,2}(?:\.[0-9]{1,2})?$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

export type LabFormField = 'name' | 'image' | 'mounts' | 'memory' | 'cpus' | 'description';

/** Field problems (empty when the form can be sent). */
export function validateLabForm(form: LabFormState): Partial<Record<LabFormField, string>> {
  const problems: Partial<Record<LabFormField, string>> = {};
  const name = form.name.trim();
  if (!NAME_RE.test(name)) {
    problems.name = '2–41 characters: lowercase letters, digits and “-”, starting with a letter or digit.';
  }
  const image = form.image.trim();
  if (image && (image.length > 255 || /\s/.test(image))) {
    problems.image = 'An image reference has no spaces and at most 255 characters (e.g. alpine:3.20).';
  }
  const mounts = form.mounts.map((mount) => mount.trim()).filter(Boolean);
  if (mounts.length > MAX_MOUNTS) {
    problems.mounts = `At most ${MAX_MOUNTS} mounts.`;
  } else if (mounts.some((mount) => !mount.startsWith('/'))) {
    problems.mounts = 'Mount paths must be absolute: they are resolved on the R$F server.';
  } else if (mounts.some((mount) => /[,:"'\\]/.test(mount) || CONTROL_RE.test(mount))) {
    problems.mounts = 'Mount paths cannot contain “,”, “:”, quotes, backslashes or control characters.';
  } else if (new Set(mounts).size !== mounts.length) {
    problems.mounts = 'Each path can be mounted once.';
  }
  const memory = form.memory.trim();
  if (memory && !MEMORY_RE.test(memory)) {
    problems.memory = 'Megabytes or gigabytes with a unit, 32m to 16g (e.g. 512m, 2g).';
  }
  const cpus = form.cpus.trim();
  if (cpus && (!CPUS_RE.test(cpus) || Number(cpus) < 0.1 || Number(cpus) > 16)) {
    problems.cpus = 'A number of CPUs between 0.1 and 16 (up to two decimals).';
  }
  const description = form.description.trim();
  if (description.length > MAX_DESCRIPTION) {
    problems.description = `At most ${MAX_DESCRIPTION} characters.`;
  } else if (CONTROL_RE.test(description)) {
    problems.description = 'A single line without control characters.';
  }
  return problems;
}

/**
 * The `POST /lab/labs` body: only fields the API accepts (unknown fields are rejected with 422),
 * optional values only when set, and the two flags always as JSON booleans.
 */
export function labCreateBody(form: LabFormState): LabCreateRequest {
  const body: LabCreateRequest = {
    name: form.name.trim(),
    allow_outbound: form.allowOutbound,
    root: form.root,
  };
  const image = form.image.trim();
  if (image) body.image = image;
  const mounts = form.mounts.map((mount) => mount.trim()).filter(Boolean);
  if (mounts.length > 0) body.mounts = mounts;
  const memory = form.memory.trim().toLowerCase();
  if (memory) body.memory = memory;
  const cpus = form.cpus.trim();
  if (cpus) body.cpus = cpus;
  const description = form.description.trim();
  if (description) body.description = description;
  if (form.backend) body.backend = form.backend;
  return body;
}

/** Shell-style rendering of an argument vector for display and copying (`docker create ... -c '...'`). */
export function formatCommand(args: readonly string[]): string {
  return args
    .map((arg) => (/^[\w@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`))
    .join(' ');
}
