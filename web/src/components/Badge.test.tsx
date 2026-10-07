import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { Finding } from '../api/types';
import { InspectorProvider } from '../app/shellState';
import { FindingsTable } from '../pages/FindingsPage';
import { confidenceLevel, ConfidenceBadge, SeverityBadge } from './Badge';

function finding(id: string, severity: Finding['severity'], confidence: number): Finding {
  return {
    id,
    title: `Finding ${id}`,
    description: '',
    severity,
    confidence,
    confidence_level: confidenceLevel(confidence),
    product: 'iam',
    rule_id: 'iam.stale-admin',
    status: 'OPEN',
    affected_objects: ['identity:old-admin'],
    evidence: [],
    recommendation: '',
    explanation: [],
    created_at: '2026-10-07T11:05:48Z',
    updated_at: '2026-10-07T11:05:48Z',
    tags: [],
    metadata: {},
  };
}

describe('severity and confidence badges', () => {
  it('render independently: "Severity: HIGH, Confidence: LOW" is valid', () => {
    render(
      <p>
        <SeverityBadge severity="HIGH" />
        <ConfidenceBadge confidence={0.3} />
      </p>,
    );
    const severity = screen.getByTitle('Severity: HIGH');
    const confidence = screen.getByTitle('Confidence: LOW (0.30)');
    expect(severity).toHaveTextContent('Severity: HIGH');
    expect(confidence).toHaveTextContent('Confidence: LOW');
    expect(severity).toHaveClass('sev', 'sev--high');
    expect(confidence).toHaveClass('conf', 'conf--low');
    expect(confidence).not.toHaveClass('sev');
    expect(severity).not.toHaveClass('conf');
  });

  it('uses distinct visual systems for the inverse case', () => {
    render(
      <p>
        <SeverityBadge severity="LOW" showLabel />
        <ConfidenceBadge confidence={0.95} showLabel />
      </p>,
    );
    // Visible prefix variant (drawers): "Severity: LOW" next to "Confidence: HIGH" (colon drawn by CSS).
    expect(screen.getByTitle('Severity: LOW')).toHaveTextContent('SeverityLOW');
    const confidence = screen.getByTitle('Confidence: HIGH (0.95)');
    expect(confidence.querySelectorAll('.conf__bar.is-filled')).toHaveLength(3);
  });

  it('follows the backend confidence thresholds and ignores unknown severities', () => {
    expect(confidenceLevel(0.8)).toBe('HIGH');
    expect(confidenceLevel(0.79)).toBe('MEDIUM');
    expect(confidenceLevel(0.5)).toBe('MEDIUM');
    expect(confidenceLevel(0.49)).toBe('LOW');
    render(<SeverityBadge severity="<b>bogus</b>" />);
    expect(screen.getByTitle('Severity: INFO')).toBeInTheDocument();
  });

  it('show both values per finding row in the findings table', () => {
    render(
      <InspectorProvider>
        <FindingsTable
          rows={[finding('finding:a', 'CRITICAL', 0.2), finding('finding:b', 'LOW', 0.9)]}
          selectedId={null}
          onOpen={() => undefined}
        />
      </InspectorProvider>,
    );
    const [, rowA, rowB] = screen.getAllByRole('row');
    expect(within(rowA!).getByTitle('Severity: CRITICAL')).toBeInTheDocument();
    expect(within(rowA!).getByTitle('Confidence: LOW (0.20)')).toBeInTheDocument();
    expect(within(rowB!).getByTitle('Severity: LOW')).toBeInTheDocument();
    expect(within(rowB!).getByTitle('Confidence: HIGH (0.90)')).toBeInTheDocument();
  });
});
