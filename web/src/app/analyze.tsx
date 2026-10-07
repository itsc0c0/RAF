import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  type ChangeEvent,
  type ReactNode,
} from 'react';
import { useNavigate } from 'react-router-dom';
import { isApiError } from '../api/client';
import { useAnalyzeUpload, type AnalyzeUploadInput } from '../api/hooks';
import type { AnalysisRecord } from '../api/types';
import { errorSummary } from '../components/States';
import { useToast } from '../components/Toast';
import { routeTo } from '../lib/routes';

interface AnalyzeContextValue {
  /** Opens the file picker; the chosen file is uploaded to `POST /analyze` and the result opens. */
  pickFile: () => void;
  /** Uploads `input` (Analyses page form); resolves with the analysis record. */
  analyze: (input: AnalyzeUploadInput) => Promise<AnalysisRecord>;
  isUploading: boolean;
}

const AnalyzeContext = createContext<AnalyzeContextValue | null>(null);

/** Short outcome line of an analysis (`completed`, steps that failed or were skipped). */
export function analysisOutcome(record: AnalysisRecord): string {
  const failed = record.steps.filter((step) => step.status === 'failed').length;
  const skipped = record.steps.filter((step) => step.status === 'skipped').length;
  const parts = [`${record.id} ${record.status}`];
  if (failed) parts.push(`${failed} step${failed === 1 ? '' : 's'} failed`);
  if (skipped) parts.push(`${skipped} skipped`);
  return parts.join(' · ');
}

/**
 * `POST /analyze` (multipart). The analysis runs during the request and the response is the full
 * record, so a successful upload opens it on the Analyses page.
 */
export function AnalyzeProvider({ children }: { children: ReactNode }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const upload = useAnalyzeUpload();
  const { notify } = useToast();
  const navigate = useNavigate();
  const { mutateAsync } = upload;

  const pickFile = useCallback(() => inputRef.current?.click(), []);

  const analyze = useCallback(
    async (input: AnalyzeUploadInput) => {
      notify({ tone: 'info', title: `Analyzing ${input.file.name}…` });
      try {
        const record = await mutateAsync(input);
        notify({
          tone: record.status === 'completed' ? 'good' : record.status === 'partial' ? 'warn' : 'bad',
          title: `Analysis of ${record.input} ${record.status}`,
          description: analysisOutcome(record),
        });
        void navigate(routeTo.analysis(record.id));
        return record;
      } catch (error) {
        if (isApiError(error) && error.isUnavailable) {
          notify({
            tone: 'warn',
            title: 'Analyze is not available yet',
            description: 'Use the CLI meanwhile: raf analyze <file>',
          });
        } else {
          notify({ tone: 'bad', title: 'Analysis failed', description: errorSummary(error) });
        }
        throw error;
      }
    },
    [mutateAsync, navigate, notify],
  );

  const onChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    analyze({ file }).catch(() => undefined);
  };

  const value = useMemo(
    () => ({ pickFile, analyze, isUploading: upload.isPending }),
    [pickFile, analyze, upload.isPending],
  );

  return (
    <AnalyzeContext.Provider value={value}>
      {children}
      <input
        ref={inputRef}
        type="file"
        className="sr-only"
        tabIndex={-1}
        aria-hidden="true"
        onChange={onChange}
        data-testid="analyze-file-input"
      />
    </AnalyzeContext.Provider>
  );
}

export function useAnalyze(): AnalyzeContextValue {
  const value = useContext(AnalyzeContext);
  if (!value) throw new Error('useAnalyze must be used inside <AnalyzeProvider>');
  return value;
}
