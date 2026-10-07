import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { FactorList, MetadataList, signedPoints } from './Data';

describe('FactorList (explainable scores)', () => {
  it('shows signed points and the score total', () => {
    render(
      <FactorList
        total={100}
        factors={[
          { label: '3 critical asset(s) controllable', sign: '+', points: 50, evidence: ['host:db-01'] },
          { label: 'MFA enforced', sign: '-', points: 10 },
          { label: 'internet-facing', sign: '+', points: 60 },
        ]}
      />,
    );
    expect(screen.getByLabelText('plus 50 points')).toHaveTextContent('+50');
    expect(screen.getByLabelText('minus 10 points')).toHaveTextContent('−10');
    expect(screen.getByText('host:db-01')).toBeInTheDocument();
    expect(screen.getByText('100')).toBeInTheDocument();
    expect(screen.queryByText(/factors sum to/)).not.toBeInTheDocument();
  });

  it('notes when the reported score differs from the factor sum', () => {
    render(
      <FactorList
        total={100}
        factors={[
          { label: 'a', sign: '+', points: 80 },
          { label: 'b', sign: '+', points: 52 },
        ]}
      />,
    );
    expect(screen.getByText(/factors sum to 132/)).toBeInTheDocument();
  });

  it('renders direction-only factors (no points) without inventing numbers', () => {
    render(
      <FactorList
        factors={[
          { label: '2 holder(s)', sign: '+', factor: 'holders' },
          { label: 'recently reviewed', sign: '-' },
        ]}
      />,
    );
    expect(screen.getByLabelText('increases')).toHaveTextContent(/^\+$/);
    expect(screen.getByLabelText('decreases')).toHaveTextContent(/^−$/);
    expect(screen.queryByText('Total')).not.toBeInTheDocument();
    expect(signedPoints({ label: 'x', sign: '+' })).toBe(0);
    expect(signedPoints({ label: 'x', sign: '-', points: 7 })).toBe(-7);
  });
});

describe('MetadataList', () => {
  it('renders nested and hostile values as text', () => {
    const { container } = render(
      <MetadataList metadata={{ b: { html: '<img src=x>' }, a: '<script>1</script>' }} />,
    );
    const keys = [...container.querySelectorAll('.kv__key')].map((node) => node.textContent);
    expect(keys).toEqual(['a', 'b']);
    expect(screen.getByText('<script>1</script>')).toBeInTheDocument();
    expect(screen.getByText('{"html":"<img src=x>"}')).toBeInTheDocument();
    expect(container.querySelector('img, script')).toBeNull();
  });
});
