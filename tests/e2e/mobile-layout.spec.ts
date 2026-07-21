import { expect, test } from '../../frontend/node_modules/@playwright/test/index.js';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const css = readFileSync(resolve(__dirname, '../../frontend/src/app.css'), 'utf8');
const longIdentifier = `target:${'cb2115578'.repeat(12)}`;
const longConfiguration = `address-sanitizer-${'configuration'.repeat(10)}`;

async function renderSurface(page, content: string) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.setContent(`
    <style>${css}</style>
    <div class="app-shell">
      <aside class="sidebar"><div class="brand"><span>BigEye</span></div></aside>
      <main class="work-surface">${content}</main>
    </div>
    <footer class="manager-activity-footer">
      <button>${longIdentifier} ${longConfiguration}</button>
    </footer>
  `);
}

async function expectContainedDocument(page) {
  expect(await page.evaluate(() => (
    document.documentElement.scrollWidth <= document.documentElement.clientWidth
  ))).toBe(true);
  await expect(page.getByText(longIdentifier, { exact: false }).first()).toBeVisible();
  const footer = page.locator('.manager-activity-footer button');
  await expect(footer).toHaveCSS('white-space', 'nowrap');
  await expect(footer).toHaveCSS('overflow', 'hidden');
  await expect(footer).toHaveCSS('text-overflow', 'ellipsis');
}

test.describe('mobile primary surfaces', () => {
  test('Overview wraps long target, configuration, and prose without document overflow', async ({ page }) => {
    await renderSurface(page, `
      <div class="overview-layout"><div class="overview-primary"><section class="current-focus">
        <h3>${longIdentifier}</h3><p class="focus-configuration">${longConfiguration}</p>
        <p>${longIdentifier} is retained as complete evidence in this deliberately long explanation.</p>
      </section></div><aside class="overview-aside"><section><p>${longIdentifier}</p></section></aside></div>
    `);
    await expectContainedDocument(page);
  });

  test('Fuzzing contains its intentionally wide table in a local scroller', async ({ page }) => {
    await renderSurface(page, `
      <section class="fuzzing-view"><div class="table-scroll fuzzing-table-scroll">
        <table class="evidence-table fuzzing-table"><tbody><tr>
          <th>${longIdentifier}<span>${longConfiguration}</span></th><td>Running</td><td>3/3 replay</td>
        </tr></tbody></table>
      </div></section>
    `);
    await expectContainedDocument(page);
  });

  test('Findings wraps identifiers and prose without hiding either', async ({ page }) => {
    await renderSurface(page, `
      <section class="findings-view"><div class="findings-workspace">
        <nav class="finding-list"><ol><li><button><span>${longConfiguration}</span><strong>${longIdentifier}</strong></button></li></ol></nav>
        <article class="finding-detail"><h2>${longIdentifier}</h2><p class="finding-description">${longConfiguration}</p><p class="technical-metadata">${longIdentifier}</p></article>
      </div></section>
    `);
    await expectContainedDocument(page);
  });
});
