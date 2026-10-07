import { useId } from 'react';
import { isApiError } from '../api/client';
import { Icon } from '../components/Icon';
import { useToast } from '../components/Toast';
import { useWorkspace } from './workspace';

/** Workspace selector: switching makes the workspace current (also for the CLI) and rescopes the UI. */
export function WorkspaceSwitcher() {
  const { workspace, workspaces, switchTo } = useWorkspace();
  const { notify } = useToast();
  const id = useId();
  return (
    <div className="ws-switch">
      <Icon name="database" className="ws-switch__icon" />
      <label htmlFor={id} className="sr-only">
        Workspace
      </label>
      <select
        id={id}
        className="ws-switch__select"
        value={workspace ?? ''}
        title="Workspace"
        onChange={(event) => {
          const name = event.target.value;
          switchTo(name).then(
            () => notify({ tone: 'good', title: `Workspace ${name} selected` }),
            (error: unknown) =>
              notify({
                tone: 'bad',
                title: 'Could not switch workspace',
                description: isApiError(error) ? error.message : undefined,
              }),
          );
        }}
      >
        {workspace && !workspaces.some((item) => item.name === workspace) ? (
          <option value={workspace}>{workspace}</option>
        ) : null}
        {workspaces.map((item) => (
          <option key={item.name} value={item.name}>
            {item.name}
          </option>
        ))}
      </select>
      <Icon name="chevronDown" size={14} className="ws-switch__chevron" />
    </div>
  );
}
