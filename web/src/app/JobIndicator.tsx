import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { api, encodeRef } from '../api/client';
import { invalidatePaths, useJobs } from '../api/hooks';
import { Button } from '../components/Button';
import { Meter } from '../components/Data';
import { Icon } from '../components/Icon';
import { Spinner } from '../components/Spinner';
import { useToast } from '../components/Toast';
import { cx } from '../lib/cx';
import { formatPercent } from '../lib/format';
import { useWorkspaceName } from './workspace';

const POLL_MS = 3000;

/** Polls running jobs; when the last one finishes, cached data is refreshed (imports change it). */
export function JobIndicator() {
  const jobs = useJobs({ status: 'RUNNING', limit: 20 }, POLL_MS);
  const running = jobs.data?.items ?? [];
  const count = running.length;
  const [open, setOpen] = useState(false);
  const client = useQueryClient();
  const workspace = useWorkspaceName();
  const { notify } = useToast();
  const previous = useRef(0);

  useEffect(() => {
    if (previous.current > 0 && count === 0) {
      void invalidatePaths(client, ['*']);
      notify({
        tone: 'good',
        title: 'Background jobs finished',
        description: 'Views were refreshed with the new data.',
      });
    }
    previous.current = count;
  }, [count, client, notify]);

  const label = jobs.isError
    ? 'Job status unavailable'
    : count === 0
      ? 'No running jobs'
      : `${count} running job${count === 1 ? '' : 's'}`;

  return (
    <div
      className="jobs"
      onKeyDown={(event) => {
        if (event.key === 'Escape') setOpen(false);
      }}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <button
        type="button"
        className={cx('jobs__button', count > 0 && 'is-running')}
        aria-label={label}
        title={label}
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        {count > 0 ? <Spinner size={14} /> : <Icon name="activity" />}
        <span className="jobs__count tabular">{count > 0 ? count : ''}</span>
      </button>
      {open ? (
        <div className="popover jobs__popover" role="dialog" aria-label="Running jobs">
          <p className="popover__title">Running jobs</p>
          {count === 0 ? (
            <p className="muted small">No jobs are running. Imports and long analyses appear here.</p>
          ) : (
            <ul className="jobs__list">
              {running.map((job) => (
                <li key={job.id} className="jobs__item">
                  <div className="row row--between">
                    <span className="truncate" title={job.title}>
                      {job.title}
                    </span>
                    <span className="mono small muted">{job.id}</span>
                  </div>
                  <Meter value={job.progress} label={`${job.title} progress`} />
                  <div className="row row--between small muted">
                    <span className="truncate">{job.message ?? 'running'}</span>
                    <span className="tabular">{formatPercent(job.progress)}</span>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    icon="stop"
                    disabled={job.cancel_requested}
                    onClick={() => {
                      api.post(`/jobs/${encodeRef(job.id)}/cancel`, { workspace }).then(
                        () => {
                          notify({ tone: 'info', title: `Cancellation requested for ${job.id}` });
                          void invalidatePaths(client, ['/jobs']);
                        },
                        (error: unknown) =>
                          notify({
                            tone: 'bad',
                            title: 'Could not cancel job',
                            description: error instanceof Error ? error.message : undefined,
                          }),
                      );
                    }}
                  >
                    {job.cancel_requested ? 'Cancelling…' : 'Cancel'}
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  );
}
