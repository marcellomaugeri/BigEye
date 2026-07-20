import type { CoverageFile } from '../../models/coverage';

export function SourceTree({ files, selectedPath, onSelect }: {
  files: CoverageFile[];
  selectedPath: string | null;
  onSelect: (path: string) => void;
}) {
  return <nav aria-label="Project source files" className="source-tree">
    <p className="eyebrow">Repository</p>
    <h2>Source files</h2>
    {files.length === 0
      ? <p className="muted-copy">No clean coverage has been recorded yet.</p>
      : <ul aria-label="Source assurance files">
        {files.map((file) => <li key={file.path}>
          <button
            aria-current={selectedPath === file.path ? 'true' : undefined}
            onClick={() => onSelect(file.path)}
            type="button"
          >{file.path}</button>
        </li>)}
      </ul>}
  </nav>;
}
