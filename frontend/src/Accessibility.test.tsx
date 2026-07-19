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
    pauseProject: vi.fn(),
    resumeProject: vi.fn(),
    listTasks: vi.fn().mockResolvedValue([]),
    getTaskLog: vi.fn(),
    getSettings: vi.fn()
  };
}

describe('Accessibility', () => {
  it('exposes the application landmarks and a labelled project picker', async () => {
    render(<App api={apiDouble()} />);

    expect(await screen.findByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    expect(screen.getByRole('main')).toBeVisible();
    expect(screen.getByLabelText('Current project')).toBeDisabled();
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
});
