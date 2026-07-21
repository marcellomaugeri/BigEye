const baseURL = process.env.BIGEYE_E2E_BASE_URL;

export default {
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  timeout: 20 * 60 * 1_000,
  expect: { timeout: 2 * 60 * 1_000 },
  outputDir: './workspace/e2e/playwright-results',
  reporter: [['list'], ['html', { open: 'never', outputFolder: './workspace/e2e/playwright-report' }]],
  use: {
    baseURL,
    browserName: 'chromium',
    reducedMotion: 'reduce',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
};
