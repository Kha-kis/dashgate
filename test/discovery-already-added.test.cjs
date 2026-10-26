const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'js', 'admin-discovery.js'), 'utf8');

function loadMatcher(apps, discoveredApps = []) {
  const context = {
    URL,
    adminState: { apps, discoveredApps },
    document: { getElementById: () => null },
    window: {},
  };
  vm.runInNewContext(source, context, { filename: 'admin-discovery.js' });
  return route => context.publishedAppForDiscoveredRoute(route);
}

test('already added discovery matches only the same HTTP URL as a published app', () => {
  const match = loadMatcher([{ source: 'config', name: 'Grafana', url: 'http://localhost:3000' }]);
  assert.equal(match({ url: 'http://localhost:3000/' })?.name, 'Grafana');
  assert.equal(match({ url: 'http://localhost:3000/api' }), null);
  assert.equal(match({ url: 'http://localhost:3000/?view=admin' }), null);
  const defaultPort = loadMatcher([{ source: 'config', name: 'Local', url: 'http://localhost' }]);
  assert.equal(defaultPort({ url: 'http://localhost:80/' })?.name, 'Local');
  assert.equal(match({ url: 'ftp://localhost:3000/' }), null);
  assert.equal(match({ url: 'not a url' }), null);
});

test('already added discovery recognizes a configured discovered app effective URL', () => {
  const match = loadMatcher([], [
    { name: 'Found', url: 'https://source.example.test', source: 'nginx', override: { hidden: false, nameOverride: 'Dashboard app', urlOverride: 'https://public.example.test/app' } },
    { name: 'Hidden', url: 'https://hidden.example.test', source: 'nginx', override: { hidden: true } },
  ]);
  assert.equal(match({ url: 'https://public.example.test/app' })?.name, 'Dashboard app');
  assert.equal(match({ url: 'https://source.example.test' }), null);
  assert.equal(match({ url: 'https://hidden.example.test' }), null);
});

test('already added discovery excludes configured routes skipped by dashboard URL de-duplication', () => {
  const match = loadMatcher(
    [{ source: 'config', name: 'Manual', url: 'https://raw.example.test' }],
    [{ name: 'Discovered', url: 'https://raw.example.test', source: 'nginx', override: { hidden: false, urlOverride: 'https://other.example.test' } }],
  );
  assert.equal(match({ url: 'https://other.example.test' }), null);
});
