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

  it('requests an explicit bounded source page beyond line five hundred', async () => {
    const fetchMock = vi.fn().mockResolvedValue(Response.json({ lines: [] }));
    vi.stubGlobal('fetch', fetchMock);

    await new ApiClient().getSourceFile('7', 'src/parser name.c', 501, 1000);

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/projects/7/coverage/source?path=src%2Fparser+name.c&start_line=501&end_line=1000',
      undefined,
    );
  });

  it('uses only the caller-owned fallback for unknown errors', () => {
    expect(friendlyApiError(new Error('secret at /Users/private/key.txt'), 'Safe fallback.')).toBe('Safe fallback.');
  });

  it('uses the project-scoped finding and event-log contracts', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json({ items: [], next_cursor: null }))
      .mockResolvedValueOnce(Response.json({ id: '9' }))
      .mockResolvedValueOnce(Response.json({ events: [], next_offset: -1 }));
    vi.stubGlobal('fetch', fetchMock);
    const api = new ApiClient('http://127.0.0.1:8000');

    await api.listFindings('project/7', 'cursor value');
    await api.getFinding('project/7', 'finding/9');
    await api.getProjectLog('project/7', 'debug', 12, 50);

    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
      'http://127.0.0.1:8000/api/projects/project%2F7/findings?cursor=cursor+value',
      'http://127.0.0.1:8000/api/projects/project%2F7/findings/finding%2F9',
      'http://127.0.0.1:8000/api/projects/project%2F7/logs/debug?after=12&limit=50',
    ]);
    expect(api.findingReproducerUrl('project/7', 'finding/9')).toBe(
      'http://127.0.0.1:8000/api/projects/project%2F7/findings/finding%2F9/reproducer',
    );
  });
});
