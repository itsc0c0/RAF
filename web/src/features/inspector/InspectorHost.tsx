import { useEvent, useObject } from '../../api/hooks';
import { useInspector, type InspectTarget } from '../../app/shellState';
import { IconButton } from '../../components/Button';
import { Drawer } from '../../components/Drawer';
import { QueryView } from '../../components/States';
import { EventDetail } from './EventDetail';
import { ObjectInspector } from './ObjectInspector';

function useTitle(target: InspectTarget): string {
  const object = useObject(target.kind === 'object' ? target.ref : null);
  const event = useEvent(target.kind === 'event' ? target.id : null);
  if (target.kind === 'object') return object.data?.object.name ?? target.ref;
  return event.data?.event_type ?? 'Event';
}

function EventInspector({ id }: { id: string }) {
  const query = useEvent(id);
  return (
    <QueryView query={query} feature="Event details" loadingLabel="Loading event…">
      {(event) => <EventDetail event={event} />}
    </QueryView>
  );
}

function InspectorDrawer({ target }: { target: InspectTarget }) {
  const { close, back, canGoBack } = useInspector();
  const title = useTitle(target);
  return (
    <Drawer
      level="top"
      title={<span className="break">{title}</span>}
      subtitle={target.kind === 'object' ? 'Object inspector' : 'Event'}
      onClose={close}
      closeLabel="Close inspector"
      actions={
        canGoBack ? <IconButton icon="arrowLeft" label="Back to previous item" onClick={back} /> : null
      }
    >
      {target.kind === 'object' ? (
        <ObjectInspector key={`o:${target.ref}`} objectRef={target.ref} />
      ) : (
        <EventInspector key={`e:${target.id}`} id={target.id} />
      )}
    </Drawer>
  );
}

/** Mounted once by the shell: the inspector drawer for whatever object/event was last opened. */
export function InspectorHost() {
  const { current } = useInspector();
  if (!current) return null;
  return <InspectorDrawer target={current} />;
}
