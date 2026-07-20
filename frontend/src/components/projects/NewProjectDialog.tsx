import * as Dialog from '@radix-ui/react-dialog';
import { Button } from '../design-system/Button';
import { Disclosure } from '../design-system/Disclosure';
import { TextField } from '../design-system/Field';
import { StatusText } from '../design-system/StatusText';
import { MAX_WORKER_COUNT } from '../../models/project';

interface NewProjectDialogProps {
  repositoryUrl: string;
  revision: string;
  workerCount: string;
  privateRepository: boolean;
  repositoryToken: string;
  loading: boolean;
  error: string | null;
  onRepositoryUrlChange: (value: string) => void;
  onRevisionChange: (value: string) => void;
  onWorkerCountChange: (value: string) => void;
  onPrivateRepositoryChange: () => void;
  onRepositoryTokenChange: (value: string) => void;
  onSubmit: () => void;
}

export function NewProjectDialog(props: NewProjectDialogProps) {
  return <Dialog.Root>
    <Dialog.Trigger asChild>
      <Button aria-label="New project">+ New project</Button>
    </Dialog.Trigger>
    <Dialog.Portal>
      <Dialog.Overlay className="dialog-overlay" />
      <Dialog.Content className="dialog-content">
        <Dialog.Title>New project</Dialog.Title>
        <Dialog.Description className="visually-hidden">
          Choose the repository and exact revision BigEye should work on.
        </Dialog.Description>
        <form noValidate onSubmit={(event) => { event.preventDefault(); props.onSubmit(); }}>
          <TextField autoFocus label="Repository URL" name="repository-url" onChange={(event) => props.onRepositoryUrlChange(event.target.value)} placeholder="https://github.com/owner/repository.git" required type="url" value={props.repositoryUrl} />
          <TextField label="Revision" name="revision" onChange={(event) => props.onRevisionChange(event.target.value)} required value={props.revision} />
          <TextField label="Worker count" max={MAX_WORKER_COUNT} min="1" name="worker-count" onChange={(event) => props.onWorkerCountChange(event.target.value)} required step="1" type="number" value={props.workerCount} />
          <Disclosure label="Private repository" onToggle={props.onPrivateRepositoryChange} open={props.privateRepository}>
            <TextField autoComplete="off" label="Read-only access token" name="repository-token" onChange={(event) => props.onRepositoryTokenChange(event.target.value)} type="password" value={props.repositoryToken} />
          </Disclosure>
          {props.error && <StatusText tone="error">{props.error}</StatusText>}
          <div className="dialog-actions">
            <Dialog.Close asChild><Button type="button" variant="secondary">Cancel</Button></Dialog.Close>
            <Button disabled={props.loading} type="submit">{props.loading ? 'Starting project…' : 'Start project'}</Button>
          </div>
        </form>
      </Dialog.Content>
    </Dialog.Portal>
  </Dialog.Root>;
}
