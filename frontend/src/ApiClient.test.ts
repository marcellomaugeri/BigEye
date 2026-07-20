import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiClient, friendlyApiError } from './services/apiClient';

describe('ApiClient source assurance boundaries', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reads a truthful empty coverage resource from the API', async () => {
    const empty = {
      project_id: 7, commit_sha: 'a'.repeat(40), files: [],
      pagination: { limit: 1000, offset: 0, total: 0 },
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(empty)));

    await expect(new ApiClient().getCoverageTree('7')).resolves.toEqual(empty);
  });

  it('builds a contained retained-testcase URL with encoded project input', () => {
    const url = new ApiClient('http://127.0.0.1:8000').retainedTestcaseUrl(
      'project/7', 'src/parser name.c', 42, 33, 'b'.repeat(64),
    );

    expect(url).toBe(
      `http://127.0.0.1:8000/api/projects/project%2F7/coverage/lines/42/testcases/33?`
      + `path=src%2Fparser+name.c&sha256=${'b'.repeat(64)}`,
    );
  });

  it('uses only the caller-owned fallback for unknown errors', () => {
    expect(friendlyApiError(new Error('secret at /Users/private/key.txt'), 'Safe fallback.')).toBe('Safe fallback.');
  });
});
