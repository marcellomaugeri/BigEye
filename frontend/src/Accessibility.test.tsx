import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { BigEyeApi } from './services/apiClient';
import styles from './app.css?inline';

function apiDouble(): BigEyeApi {
  return {
    createProject: vi.fn(),
    listProjects: vi.fn().mockResolvedValue([]),
    getProject: vi.fn(),
    getProjectSettings: vi.fn(),
    updateProjectSettings: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn(),
    listCampaigns: vi.fn().mockResolvedValue({ project_id: 1, campaigns: [], assets: [] }),
    getCoverageTree: vi.fn().mockResolvedValue({ project_id: 1, commit_sha: '', files: [], summary: { lines: null, functions: null, branches: null }, pagination: { limit: 1000, offset: 0, total: 0 } }),
    getSourceFile: vi.fn(),
    getCoverageFunctions: vi.fn(),
    getLineEvidence: vi.fn(),
    retainedTestcaseUrl: vi.fn(),
    listFindings: vi.fn().mockResolvedValue({ items: [], next_cursor: null }),
    getFinding: vi.fn(), findingReproducerUrl: vi.fn(), startFindingReproduction: vi.fn(), findingReproductionEventsUrl: vi.fn(), getProjectLog: vi.fn(), getProjectEvent: vi.fn(),
  };
}

describe('Accessibility', () => {
  it('exposes the application landmarks without an empty project picker', async () => {
    render(<App api={apiDouble()} />);

    expect(await screen.findByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    expect(screen.getByRole('main')).toBeVisible();
    expect(screen.queryByLabelText('Current project')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'New project' })).toBeVisible();
  });

  it('keeps keyboard focus on a focusable control covered by the named focus style', async () => {
    const user = userEvent.setup();
    render(<App api={apiDouble()} />);

    await user.tab();
    const projects = screen.getByRole('link', { name: 'Projects' });

    expect(projects).toHaveFocus();
    expect(styles).toContain('button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible');
    expect(styles).toContain('outline: var(--focus-outline);');
  });

  it('defines an opaque focus outline without a translucent focus shadow', () => {
    expect(styles).toContain('--focus-outline: 3px solid var(--color-red);');
    expect(styles).toContain('outline-offset: 3px;');
    expect(styles).not.toMatch(/focus[^}]*rgba\(/i);
    expect(styles).not.toMatch(/focus[^}]*outline:\s*0/i);
  });

  it('uses a neutral border for covered-file chips so red remains reserved for attention', () => {
    expect(styles).toMatch(/\.coverage-area-files span\s*\{[^}]*border-left:\s*2px solid var\(--color-grey\)/s);
    expect(styles).not.toMatch(/\.coverage-area-files span\s*\{[^}]*border-left:\s*2px solid var\(--color-red\)/s);
  });

  it('uses readable muted text and keeps technical summaries visibly focusable', () => {
    expect(styles).toContain('--color-grey: #888078;');
    expect(styles).toContain('--color-text-muted: #C8C2BC;');
    expect(styles).toMatch(/summary\s*\{[^}]*color:\s*var\(--color-white\)/s);
    expect(styles).toMatch(/summary:(?:hover|focus-visible)[^}]*color:\s*var\(--color-red-text\)/s);
  });
});
