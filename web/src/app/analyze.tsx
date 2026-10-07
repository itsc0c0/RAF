import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  type ChangeEvent,
  type ReactNode,
} from 'react';
import { isApiError } from '../api/client';
import { useAnalyzeUpload } from '../api/hooks';
import { useToast } from '../components/Toast';

interface AnalyzeContextValue {
  /** Opens the file picker; the chosen file is uploaded to `POST /analyze`. */
  pickFile: () => void;
  isUploading: boolean;
}

const AnalyzeContext = createContext<AnalyzeContextValue | null>(null);

export function AnalyzeProvider({ children }: { children: ReactNode }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const upload = useAnalyzeUpload();
  const { notify } = useToast();
  const { mutate } = upload;

  const pickFile = useCallback(() => inputRef.current?.click(), []);

  const onChange = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    notify({ tone: 'info', title: `Uploading ${file.name}…` });
    mutate(file, {
      onSuccess: (result) => {
        const job = typeof result?.job?.id === 'string' ? result.job.id : null;
        const analysis = typeof result?.analysis?.id === 'string' ? result.analysis.id : null;
        notify({
          tone: 'good',
          title: 'Analysis started',
          description:
            [analysis && `analysis ${analysis}`, job && `job ${job}`].filter(Boolean).join(' · ') ||
            file.name,
        });
      },
      onError: (error) => {
        if (isApiError(error) && error.isUnavailable) {
          notify({
            tone: 'warn',
            title: 'Analyze is not available yet',
            description: 'Use the CLI meanwhile: raf analyze <file>',
          });
        } else {
          notify({
            tone: 'bad',
            title: 'Analysis failed',
            description: error instanceof Error ? error.message : undefined,
          });
        }
      },
    });
  };

  const value = useMemo(() => ({ pickFile, isUploading: upload.isPending }), [pickFile, upload.isPending]);

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
