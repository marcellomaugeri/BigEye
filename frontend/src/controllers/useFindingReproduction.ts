import { useCallback, useEffect, useRef, useState } from 'react';
import type { FindingReproductionModel, ReproductionOutput, ReproductionRun } from '../models/reproduction';
import { friendlyApiError, type BigEyeApi } from '../services/apiClient';
import type { ProjectEventStream } from '../services/eventStream';

export function useFindingReproduction(
  api: BigEyeApi,
  events: ProjectEventStream,
  projectId: string | null,
  findingId: string | null,
): FindingReproductionModel {
  const [run, setRun] = useState<ReproductionRun | null>(null);
  const [output, setOutput] = useState<ReproductionOutput[]>([]);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const unsubscribe = useRef<(() => void) | null>(null);
  const generation = useRef(0);

  useEffect(() => {
    generation.current += 1;
    unsubscribe.current?.();
    unsubscribe.current = null;
    setRun(null);
    setOutput([]);
    setStarting(false);
    setError(null);
    return () => {
      generation.current += 1;
      unsubscribe.current?.();
      unsubscribe.current = null;
    };
  }, [findingId, projectId]);

  const start = useCallback(async () => {
    if (projectId === null || findingId === null || starting) return;
    const currentGeneration = ++generation.current;
    unsubscribe.current?.();
    unsubscribe.current = null;
    setRun(null);
    setOutput([]);
    setStarting(true);
    setError(null);
    try {
      const started = await api.startFindingReproduction(projectId, findingId);
      if (generation.current !== currentGeneration) return;
      setRun(started);
      const url = api.findingReproductionEventsUrl(projectId, findingId, started.run_id);
      if (!events.subscribeReproduction) throw new Error('reproduction stream is unavailable');
      let terminalReceived = false;
      const closeStream = () => {
        const close = unsubscribe.current;
        unsubscribe.current = null;
        close?.();
      };
      const close = events.subscribeReproduction(url, (event) => {
        if (generation.current !== currentGeneration || terminalReceived) return;
        if (event.type === 'output') setOutput((current) => [...current, event.data]);
        else {
          setRun(event.data);
          if (['completed', 'failed', 'timed_out', 'interrupted'].includes(event.data.phase)) {
            terminalReceived = true;
            closeStream();
          }
        }
      }, () => {
        if (generation.current === currentGeneration && !terminalReceived) {
          setError('Live reproduction output is temporarily unavailable.');
        }
      });
      if (terminalReceived) close();
      else unsubscribe.current = close;
    } catch (requestError) {
      if (generation.current === currentGeneration) {
        setError(friendlyApiError(requestError, 'Finding reproduction is temporarily unavailable.'));
      }
    } finally {
      if (generation.current === currentGeneration) setStarting(false);
    }
  }, [api, events, findingId, projectId, starting]);

  return { run, output, starting, error, start };
}
