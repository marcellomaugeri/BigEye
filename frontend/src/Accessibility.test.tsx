import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { BigEyeApi } from './services/apiClient';

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
});
