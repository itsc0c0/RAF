import { useState } from 'react';
import { isApiError } from '../../api/client';
import type { LifecycleAction } from '../../api/hooks';
import { Badge, type Tone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { Checkbox } from '../../components/Form';
import { ConfirmDialog } from '../../components/Modal';
import { errorSummary } from '../../components/States';
import { useToast } from '../../components/Toast';

const STATE_TONES: Record<string, Tone> = {
  running: 'good',
  started: 'good',
  active: 'good',
  stopped: 'neutral',
  exited: 'neutral',
  defined: 'accent',
  created: 'accent',
  ready: 'accent',
  paused: 'warn',
  restarting: 'warn',
  conflict: 'bad',
  failed: 'bad',
  error: 'bad',
  dead: 'bad',
  destroyed: 'neutral',
};

export function LifecycleState({ state }: { state: string | undefined | null }) {
  if (!state) return <span className="muted">—</span>;
  return <Badge tone={STATE_TONES[state.toLowerCase()] ?? 'neutral'}>{state.toUpperCase()}</Badge>;
}

const LABELS: Record<LifecycleAction, string> = {
  start: 'Start',
  stop: 'Stop',
  reset: 'Reset',
  destroy: 'Destroy',
};

export interface LifecycleOptions {
  /** Destroy only: delete the definition even when the resource cannot be removed. */
  forget: boolean;
}

/**
 * Start/stop/reset/destroy buttons. Every action asks for confirmation; destroy additionally asks
 * the user to type the name. `forgetOption` adds a "forget" choice to the destroy dialog.
 */
export function LifecycleActions<A extends LifecycleAction>({
  name,
  kind,
  actions,
  run,
  busy,
  disabled,
  forgetOption,
}: {
  name: string;
  kind: string;
  actions: readonly A[];
  run: (action: A, options: LifecycleOptions) => Promise<unknown>;
  busy: boolean;
  /** Actions that cannot run now, with the reason (shown as tooltip). */
  disabled?: Partial<Record<A, string>>;
  /** Explanation of the destroy "forget" option; omit to hide it. */
  forgetOption?: string;
}) {
  const [pending, setPending] = useState<A | null>(null);
  const [forget, setForget] = useState(false);
  const { notify } = useToast();
  const close = () => {
    setPending(null);
    setForget(false);
  };
  const confirm = () => {
    if (!pending) return;
    const action = pending;
    run(action, { forget: action === 'destroy' && forget }).then(
      () => {
        notify({ tone: 'good', title: `${LABELS[action]} requested for ${kind} ${name}` });
        close();
      },
      (error: unknown) => {
        notify({
          tone: isApiError(error) && error.isUnavailable ? 'warn' : 'bad',
          title: `${LABELS[action]} failed`,
          description: errorSummary(error),
        });
        close();
      },
    );
  };
  return (
    <span className="row row--wrap">
      {actions.map((action) => {
        const reason = disabled?.[action];
        return (
          <Button
            key={action}
            size="sm"
            variant={action === 'destroy' ? 'danger' : 'secondary'}
            icon={
              action === 'start'
                ? 'play'
                : action === 'stop'
                  ? 'stop'
                  : action === 'reset'
                    ? 'reset'
                    : 'trash'
            }
            disabled={Boolean(reason)}
            title={reason}
            aria-label={`${LABELS[action]} ${kind} ${name}`}
            onClick={(event) => {
              event.stopPropagation();
              setPending(action);
            }}
          >
            {LABELS[action]}
          </Button>
        );
      })}
      {pending ? (
        <ConfirmDialog
          title={`${LABELS[pending]} ${kind} “${name}”?`}
          danger={pending === 'destroy' || pending === 'reset'}
          confirmLabel={LABELS[pending]}
          requireText={pending === 'destroy' ? name : undefined}
          busy={busy}
          onConfirm={confirm}
          onCancel={close}
        >
          {pending === 'destroy' ? (
            <div className="stack stack--tight">
              <p>This permanently removes the {kind} and its data. This cannot be undone.</p>
              {forgetOption ? (
                <>
                  <Checkbox
                    label="Forget only (keep what cannot be removed)"
                    checked={forget}
                    onChange={setForget}
                  />
                  <p className="small muted">{forgetOption}</p>
                </>
              ) : null}
            </div>
          ) : pending === 'reset' ? (
            <p>The {kind} returns to its initial state; changes made since it started are discarded.</p>
          ) : (
            <p>
              {LABELS[pending]} the {kind} “{name}”.
            </p>
          )}
        </ConfirmDialog>
      ) : null}
    </span>
  );
}
