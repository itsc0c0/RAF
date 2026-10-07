import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

/* ------------------------------------------------------------------ inspector */

export type InspectTarget = { kind: 'object'; ref: string } | { kind: 'event'; id: string };

interface InspectorContextValue {
  current: InspectTarget | null;
  canGoBack: boolean;
  /** Inspect any object (ID, name or alias: the API resolves references). */
  open: (ref: string) => void;
  openEvent: (id: string) => void;
  back: () => void;
  close: () => void;
}

const InspectorContext = createContext<InspectorContextValue | null>(null);

function sameTarget(a: InspectTarget | undefined, b: InspectTarget): boolean {
  if (!a || a.kind !== b.kind) return false;
  return a.kind === 'object' ? a.ref === (b as { ref: string }).ref : a.id === (b as { id: string }).id;
}

export function InspectorProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<InspectTarget[]>([]);
  const push = useCallback((target: InspectTarget) => {
    setStack((current) =>
      sameTarget(current[current.length - 1], target) ? current : [...current.slice(-24), target],
    );
  }, []);
  const open = useCallback((ref: string) => push({ kind: 'object', ref }), [push]);
  const openEvent = useCallback((id: string) => push({ kind: 'event', id }), [push]);
  const back = useCallback(() => setStack((current) => current.slice(0, -1)), []);
  const close = useCallback(() => setStack([]), []);
  const value = useMemo<InspectorContextValue>(
    () => ({
      current: stack[stack.length - 1] ?? null,
      canGoBack: stack.length > 1,
      open,
      openEvent,
      back,
      close,
    }),
    [stack, open, openEvent, back, close],
  );
  return <InspectorContext.Provider value={value}>{children}</InspectorContext.Provider>;
}

export function useInspector(): InspectorContextValue {
  const value = useContext(InspectorContext);
  if (!value) throw new Error('useInspector must be used inside <InspectorProvider>');
  return value;
}

/* ------------------------------------------------------------------ oracle panel */

interface OracleContextValue {
  isOpen: boolean;
  /** Question pre-filled when the panel was opened from elsewhere (palette, pages). */
  draft: string;
  open: (question?: string) => void;
  close: () => void;
}

const OracleContext = createContext<OracleContextValue | null>(null);

export function OracleProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState({ isOpen: false, draft: '' });
  const open = useCallback((question?: string) => {
    setState((current) => ({ isOpen: true, draft: question ?? current.draft }));
  }, []);
  const close = useCallback(() => setState((current) => ({ ...current, isOpen: false })), []);
  const value = useMemo(() => ({ ...state, open, close }), [state, open, close]);
  return <OracleContext.Provider value={value}>{children}</OracleContext.Provider>;
}

export function useOracle(): OracleContextValue {
  const value = useContext(OracleContext);
  if (!value) throw new Error('useOracle must be used inside <OracleProvider>');
  return value;
}

/* ------------------------------------------------------------------ command palette */

interface PaletteContextValue {
  isOpen: boolean;
  open: () => void;
  close: () => void;
  toggle: () => void;
}

const PaletteContext = createContext<PaletteContextValue | null>(null);

export function PaletteProvider({ children }: { children: ReactNode }) {
  const [isOpen, setOpen] = useState(false);
  const open = useCallback(() => setOpen(true), []);
  const close = useCallback(() => setOpen(false), []);
  const toggle = useCallback(() => setOpen((current) => !current), []);
  const value = useMemo(() => ({ isOpen, open, close, toggle }), [isOpen, open, close, toggle]);
  return <PaletteContext.Provider value={value}>{children}</PaletteContext.Provider>;
}

export function usePalette(): PaletteContextValue {
  const value = useContext(PaletteContext);
  if (!value) throw new Error('usePalette must be used inside <PaletteProvider>');
  return value;
}
