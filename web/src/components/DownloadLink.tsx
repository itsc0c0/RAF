import { useState, type ReactNode } from 'react';
import {
  downloadsNeedFetch,
  downloadUrl,
  downloadWithFetch,
  isApiError,
  type QueryParams,
} from '../api/client';
import { useWorkspaceName } from '../app/workspace';
import { cx } from '../lib/cx';
import { useToast } from './Toast';

/**
 * Same-origin export link. Without a token it is a plain `<a download>` (the workspace travels as
 * `?workspace=`, links cannot carry headers). When a bearer token is set for this tab the click is
 * intercepted and the file is fetched with the `Authorization` header, then saved from a temporary
 * object URL: the token never appears in the URL.
 */
export function DownloadLink({
  path,
  query,
  filename,
  nameLink = false,
  className,
  children,
  title,
}: {
  path: string;
  query: QueryParams;
  /** File name used when the server sends no `Content-Disposition` name. */
  filename: string;
  /** Also suggest `filename` on the plain link (for exports without `Content-Disposition`). */
  nameLink?: boolean;
  className?: string;
  children: ReactNode;
  title?: string;
}) {
  const workspace = useWorkspaceName();
  const { notify } = useToast();
  const [busy, setBusy] = useState(false);
  const href = downloadUrl(path, query, workspace);
  return (
    <a
      className={cx(className, busy && 'is-busy')}
      href={href}
      download={nameLink ? filename : true}
      title={title}
      aria-busy={busy || undefined}
      onClick={(event) => {
        if (!downloadsNeedFetch()) return;
        event.preventDefault();
        if (busy) return;
        setBusy(true);
        downloadWithFetch(href, filename).then(
          () => setBusy(false),
          (error: unknown) => {
            setBusy(false);
            notify({
              tone: 'bad',
              title: 'Download failed',
              description: isApiError(error) ? error.message : undefined,
            });
          },
        );
      }}
    >
      {children}
    </a>
  );
}
