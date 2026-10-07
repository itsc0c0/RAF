import { useState } from 'react';
import { isApiError } from '../../api/client';
import type { LifecycleAction } from '../../api/hooks';
import { Badge, type Tone } from '../../components/Badge';
import { Button } from '../../components/Button';
import { ConfirmDialog } from '../../components/Modal';
import { useToast } from '../../components/Toast';

const STATE_TONES: Record<string, Tone> = {
  running: 'good',
  started: 'good',
  active: 'good',
  stopped: 'neutral',
  created: 'accent',
  ready: 'accent',
  failed: 'bad',
  error: 'bad',
  destroyed: 'neutral',
};

export function LifecycleState({ state }: { state: string | undefined }) {
  if (!state) return <span className="muted">—</span>;
  return <Badge tone={STATE_TONES[state.toLowerCase()] ?? 'neutral'}>{state.toUpperCase()}</Badge>;
}

const LABELS: Record<LifecycleAction, string> = {
  start: 'Start',
  stop: 'Stop',
  reset: 'Reset',
  destroy: 'Destroy',
};

/**
 * Start/stop/reset/destroy buttons. Every action asks for confirmation; destroy additionally asks
 * the user to type the name.
 */
export function LifecycleActions({
  name,
  kind,
  actions,
  run,
  busy,
}: {
  name: string;
  kind: string;
  actions: readonly LifecycleAction[];
  run: (action: LifecycleAction) => Promise<unknown>;
  busy: boolean;
}) {
  const [pending, setPending] = useState<LifecycleAction | null>(null);
  const { notify } = useToast();
  const confirm = () => {
    if (!pending) return;
    const action = pending;
    run(action).then(
      () => {
        notify({ tone: 'good', title: `${LABELS[action]} requested for ${kind} ${name}` });
        setPending(null);
      },
      (error: unknown) => {
        notify({
          tone: isApiError(error) && error.isUnavailable ? 'warn' : 'bad',
          title: `${LABELS[action]} failed`,
          description: isApiError(error) ? [error.message, error.hint].filter(Boolean).join(' ') : undefined,
        });
        setPending(null);
      },
    );
  };
  return (
    <span className="row row--wrap">
      {actions.map((action) => (
        <Button
          key={action}
          size="sm"
          variant={action === 'destroy' ? 'danger' : 'secondary'}
          icon={
            action === 'start' ? 'play' : action === 'stop' ? 'stop' : action === 'reset' ? 'reset' : 'trash'
          }
          onClick={(event) => {
            event.stopPropagation();
            setPending(action);
          }}
        >
          {LABELS[action]}
        </Button>
      ))}
      {pending ? (
        <ConfirmDialog
          title={`${LABELS[pending]} ${kind} “${name}”?`}
          danger={pending === 'destroy' || pending === 'reset'}
          confirmLabel={LABELS[pending]}
          requireText={pending === 'destroy' ? name : undefined}
          busy={busy}
          onConfirm={confirm}
          onCancel={() => setPending(null)}
        >
          {pending === 'destroy' ? (
            <p>This permanently removes the {kind} and its data. This cannot be undone.</p>
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
