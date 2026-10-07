import { useQueryClient } from '@tanstack/react-query';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import {
  clearApiToken,
  getApiToken,
  hasApiToken,
  isValidApiToken,
  onUnauthorized,
  setApiToken,
  subscribeApiToken,
} from '../api/auth';
import { Button, IconButton } from '../components/Button';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Callout } from '../components/Panel';
import { useToast } from '../components/Toast';

/**
 * Bearer-token handling for `raf serve` bound to a non-loopback address.
 *
 * A 401 `raf.unauthorized` from any request opens the token prompt (once: after "Cancel" it only
 * reopens on request, e.g. from the top bar or Settings). The token is stored in sessionStorage by
 * `api/auth.ts`, sent by `api/client.ts`, and never rendered, logged or put into a URL.
 */
interface AuthContextValue {
  /** A token is set for this browser tab. */
  hasToken: boolean;
  /** The server asked for a token (401) and no accepted token is known yet. */
  required: boolean;
  openPrompt: () => void;
  /** Removes the token from this tab and drops cached API data. */
  forgetToken: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const { notify } = useToast();
  const hasToken = useSyncExternalStore(subscribeApiToken, hasApiToken, () => false);
  const [required, setRequired] = useState(false);
  const [promptOpen, setPromptOpen] = useState(false);
  // After "Cancel" the prompt does not reopen by itself (polling queries keep answering 401).
  const dismissed = useRef(false);

  useEffect(
    () =>
      onUnauthorized((usedToken) => {
        // An answer to a request sent before the current token was set says nothing about it.
        if (usedToken !== getApiToken()) return;
        setRequired(true);
        if (!dismissed.current) setPromptOpen(true);
      }),
    [],
  );

  const openPrompt = useCallback(() => setPromptOpen(true), []);

  const cancel = useCallback(() => {
    dismissed.current = true;
    setPromptOpen(false);
  }, []);

  const submit = useCallback(
    (token: string) => {
      setApiToken(token);
      dismissed.current = false;
      setRequired(false);
      setPromptOpen(false);
      notify({ tone: 'good', title: 'Access token set for this browser tab' });
      void client.resetQueries();
    },
    [client, notify],
  );

  const forgetToken = useCallback(() => {
    clearApiToken();
    // The user chose to remove it: show "token required" states instead of popping the prompt up.
    dismissed.current = true;
    setPromptOpen(false);
    notify({ tone: 'info', title: 'Access token removed from this browser tab' });
    void client.resetQueries();
  }, [client, notify]);

  const value = useMemo<AuthContextValue>(
    () => ({ hasToken, required, openPrompt, forgetToken }),
    [hasToken, required, openPrompt, forgetToken],
  );

  return (
    <AuthContext.Provider value={value}>
      {children}
      {promptOpen ? (
        <TokenPrompt rejected={hasToken && required} onSubmit={submit} onCancel={cancel} />
      ) : null}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside <AuthProvider>');
  return value;
}

export const TOKEN_STORAGE_NOTE =
  'The token is kept in this tab’s session storage only (cleared when the tab closes, never in local storage) and sent as an Authorization header with every API request.';

function TokenPrompt({
  rejected,
  onSubmit,
  onCancel,
}: {
  rejected: boolean;
  onSubmit: (token: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState('');
  const [problem, setProblem] = useState<string | null>(null);
  const inputId = useId();
  const formId = useId();
  const hintId = useId();
  return (
    <Modal
      title="Access token required"
      onClose={onCancel}
      size="sm"
      footer={
        <>
          <Button onClick={onCancel}>Cancel</Button>
          <Button type="submit" form={formId} variant="primary" icon="key" disabled={!value.trim()}>
            Use token
          </Button>
        </>
      }
    >
      <form
        id={formId}
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          const token = value.trim();
          if (!isValidApiToken(token)) {
            setProblem('Tokens consist of visible characters without spaces.');
            return;
          }
          onSubmit(token);
        }}
      >
        <p>
          This R$F server is bound to a non-loopback address, so every API request needs the bearer token
          printed by <code>raf serve</code> (or the <code>RAF_API_TOKEN</code> it was started with).
        </p>
        {rejected ? (
          <Callout tone="bad" title="The server rejected the current token">
            Enter the token again; it may have changed when the server restarted.
          </Callout>
        ) : null}
        <div className="field">
          <label className="field__label" htmlFor={inputId}>
            Token
          </label>
          <input
            id={inputId}
            className="input mono"
            type="password"
            autoComplete="off"
            spellCheck={false}
            data-autofocus
            aria-describedby={hintId}
            aria-invalid={problem ? true : undefined}
            value={value}
            onChange={(event) => {
              setValue(event.target.value);
              setProblem(null);
            }}
          />
          {problem ? (
            <p className="field__error" role="alert">
              {problem}
            </p>
          ) : null}
          <p className="field__hint" id={hintId}>
            {TOKEN_STORAGE_NOTE}
          </p>
        </div>
      </form>
    </Modal>
  );
}

/** Top-bar button shown while the server asks for a token (reopens the prompt). */
export function AuthIndicator() {
  const { required, openPrompt } = useAuth();
  if (!required) return null;
  return (
    <IconButton
      icon="key"
      label="Access token required: enter token"
      className="auth-indicator"
      onClick={openPrompt}
    />
  );
}

/** Full-view state when the API refused the request for lack of a valid token. */
export function AuthRequiredState() {
  const { openPrompt, hasToken } = useAuth();
  return (
    <div className="state state--unavailable" role="status">
      <Icon name="key" size={20} className="state__icon" />
      <div className="state__body">
        <p className="state__title">Access token required</p>
        <p className="state__message">
          {hasToken
            ? 'The server rejected the token set for this tab.'
            : 'This R$F server requires a bearer token for every API request.'}{' '}
          It is printed by <code>raf serve</code> when the server is bound to a non-loopback address.
        </p>
        <div className="state__actions">
          <Button size="sm" variant="primary" icon="key" onClick={openPrompt}>
            Enter token
          </Button>
        </div>
      </div>
    </div>
  );
}
