import { expect, test } from '../../frontend/node_modules/@playwright/test/index.js';

import { acceptanceCleanupDecision } from './acceptanceCleanup.js';


const runtimeRoot = '/opt/bigeye/workspace/e2e/runtime';
const commitSha = 'a'.repeat(40);

function inspection(overrides: Record<string, unknown> = {}) {
  return {
    Config: {
      Labels: {
        'com.bigeye.managed': 'fuzz-campaign',
        'com.bigeye.commit-sha': commitSha,
        'com.bigeye.project-id': '7',
        'com.bigeye.campaign-id': '11',
      },
    },
    Mounts: [
      { Type: 'bind', Source: `${runtimeRoot}/projects/7/campaigns/11/corpus`, Destination: '/campaign/corpus' },
      { Type: 'bind', Source: `${runtimeRoot}/projects/7/campaigns/11/output`, Destination: '/campaign/output' },
      { Type: 'bind', Source: `${runtimeRoot}/projects/7/campaigns/11/config`, Destination: '/campaign/config' },
    ],
    ...overrides,
  };
}

test('does not remove an unrelated container that reuses the project id', () => {
  const candidate = inspection({
    Config: { Labels: {
      ...inspection().Config.Labels,
      'com.bigeye.commit-sha': 'b'.repeat(40),
    } },
  });

  expect(acceptanceCleanupDecision(candidate, {
    runtimeRoot, commitSha, projectId: '7',
  }).removable).toBe(false);
});

test('does not remove a labelled container with a mount outside the acceptance runtime', () => {
  const candidate = inspection({
    Mounts: [
      { Type: 'bind', Source: '/tmp/unrelated/corpus', Destination: '/campaign/corpus' },
      { Type: 'bind', Source: `${runtimeRoot}/projects/7/campaigns/11/output`, Destination: '/campaign/output' },
      { Type: 'bind', Source: `${runtimeRoot}/projects/7/campaigns/11/config`, Destination: '/campaign/config' },
    ],
  });

  expect(acceptanceCleanupDecision(candidate, {
    runtimeRoot, commitSha, projectId: '7',
  }).removable).toBe(false);
});

test('removes an exact acceptance container even when project capture failed', () => {
  expect(acceptanceCleanupDecision(inspection(), {
    runtimeRoot, commitSha, projectId: null,
  })).toEqual({ removable: true, projectId: '7', campaignId: '11' });
});
