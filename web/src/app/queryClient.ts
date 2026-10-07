import { QueryClient } from '@tanstack/react-query';
import { isApiError } from '../api/client';

/**
 * Investigation data changes only through imports/actions, so views do not refetch on window focus;
 * jobs trigger targeted invalidation instead. Client errors (4xx) and unavailable products are never
 * retried; network/5xx errors are retried once.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (isApiError(error) && (error.isUnavailable || (error.status >= 400 && error.status < 500)))
            return false;
          return failureCount < 1;
        },
      },
      mutations: { retry: false },
    },
  });
}
