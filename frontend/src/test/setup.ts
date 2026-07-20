import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach } from 'vitest';

beforeEach(() => window.localStorage.setItem('bigeye.intro.seen.v1', '1'));

afterEach(() => cleanup());
