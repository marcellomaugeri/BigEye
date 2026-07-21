import { isAbsolute, join, resolve } from 'node:path';


const MANAGED_LABEL = 'com.bigeye.managed';
const COMMIT_LABEL = 'com.bigeye.commit-sha';
const PROJECT_LABEL = 'com.bigeye.project-id';
const CAMPAIGN_LABEL = 'com.bigeye.campaign-id';
const EXPECTED_MOUNTS = [
  ['corpus', '/campaign/corpus'],
  ['output', '/campaign/output'],
  ['config', '/campaign/config'],
] as const;

type CleanupDecision =
  | { removable: true; projectId: string; campaignId: string }
  | { removable: false; reason: string };

type CleanupIdentity = {
  runtimeRoot: string;
  commitSha: string;
  projectId: string | null;
};

function reject(reason: string): CleanupDecision {
  return { removable: false, reason };
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function positiveIdentifier(value: unknown): string | null {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value) ? value : null;
}

/** Decide whether a Docker inspection proves exact ownership by this acceptance run. */
export function acceptanceCleanupDecision(
  inspection: unknown, identity: CleanupIdentity,
): CleanupDecision {
  const inspected = record(inspection);
  const config = record(inspected?.Config);
  const labels = record(config?.Labels);
  if (labels === null) return reject('container labels are missing');
  if (labels[MANAGED_LABEL] !== 'fuzz-campaign') return reject('managed label does not match');
  if (!identity.commitSha || labels[COMMIT_LABEL] !== identity.commitSha) {
    return reject('acceptance commit label does not match');
  }

  const projectId = positiveIdentifier(labels[PROJECT_LABEL]);
  const campaignId = positiveIdentifier(labels[CAMPAIGN_LABEL]);
  if (projectId === null || campaignId === null) return reject('project or campaign label is not positive');
  if (identity.projectId !== null) {
    const expectedProjectId = positiveIdentifier(identity.projectId);
    if (expectedProjectId === null || projectId !== expectedProjectId) {
      return reject('captured project id does not match');
    }
  }

  if (!isAbsolute(identity.runtimeRoot)) return reject('acceptance runtime root is not absolute');
  const runtimeRoot = resolve(identity.runtimeRoot);
  const campaignRoot = join(runtimeRoot, 'projects', projectId, 'campaigns', campaignId);
  if (!Array.isArray(inspected?.Mounts) || inspected.Mounts.length !== EXPECTED_MOUNTS.length) {
    return reject('campaign mount count does not match');
  }

  const remaining = new Map(EXPECTED_MOUNTS.map(([name, destination]) => [destination, name]));
  for (const candidate of inspected.Mounts) {
    const mount = record(candidate);
    if (mount === null || mount.Type !== 'bind') return reject('campaign mount is not a bind mount');
    const source = mount.Source;
    const destination = mount.Destination;
    if (typeof source !== 'string' || typeof destination !== 'string') {
      return reject('campaign mount paths are malformed');
    }
    const name = remaining.get(destination);
    if (name === undefined) return reject('campaign mount destination is unexpected');
    const expectedSource = join(campaignRoot, name);
    if (!isAbsolute(source) || resolve(source) !== source || source !== expectedSource) {
      return reject('campaign mount source is outside the exact acceptance campaign root');
    }
    remaining.delete(destination);
  }
  if (remaining.size !== 0) return reject('required campaign mount is missing');

  return { removable: true, projectId, campaignId };
}
