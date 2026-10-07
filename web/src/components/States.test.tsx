import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/client';
import { ErrorState, UnavailableState } from './States';

describe('ErrorState', () => {
  it('renders the API error message, reason, hint and suggestions', async () => {
    const onRetry = vi.fn();
    const error = new ApiError(404, {
      code: 'raf.not_found',
      message: "No object named 'WS-99' exists in this workspace.",
      reason: 'Name resolution found no candidates.',
      hint: 'Import data first (raf analyze <file>) or load the demo (raf demo load).',
      suggestions: ['raf search WS-99'],
    });
    render(<ErrorState error={error} onRetry={onRetry} />);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent("No object named 'WS-99' exists in this workspace.");
    expect(alert).toHaveTextContent('Name resolution found no candidates.');
    expect(alert).toHaveTextContent(
      'Import data first (raf analyze <file>) or load the demo (raf demo load).',
    );
    expect(screen.getByText('raf search WS-99').tagName).toBe('CODE');
    expect(screen.getByText('raf.not_found')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('renders plain errors without API details', () => {
    render(<ErrorState error={new Error('boom')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('boom');
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument();
  });
});

describe('UnavailableState', () => {
  it('explains that a capability is not available yet (missing route)', () => {
    const error = new ApiError(404, { code: 'raf.http_404', message: 'Not Found' });
    expect(error.isUnavailable).toBe(true);
    render(<UnavailableState feature="Blast radius" error={error} />);
    expect(screen.getByRole('status')).toHaveTextContent('Blast radius is not available yet');
  });

  it('mentions the missing dependency for 503 errors', () => {
    const error = new ApiError(503, {
      code: 'raf.dependency_unavailable',
      message: 'Docker is not available.',
      hint: 'Install Docker to run labs.',
    });
    render(<UnavailableState feature="Labs" error={error} />);
    const status = screen.getByRole('status');
    expect(status).toHaveTextContent('dependency');
    expect(status).toHaveTextContent('Install Docker to run labs.');
  });
});
