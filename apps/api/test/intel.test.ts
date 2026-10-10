import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { nearestZone, parseZoneCoord, type Zone } from '../src/intel.ts';

test('parseZoneCoord reads both zone.tab formats', () => {
  assert.deepEqual(parseZoneCoord('+4230+00131'), { lat: 42.5, lon: 1 + 31 / 60 });
  const sydney = parseZoneCoord('-3352+15113')!;
  assert.ok(sydney.lat < -33 && sydney.lon > 151);
  const seconds = parseZoneCoord('+404251-0740023')!;
  assert.ok(Math.abs(seconds.lat - 40.714) < 0.001 && Math.abs(seconds.lon + 74.006) < 0.001);
  assert.equal(parseZoneCoord('nonsense'), null);
});

test('nearestZone picks the zone of the closest reference city', () => {
  const us: Zone[] = [
    { tz: 'America/New_York', ...parseZoneCoord('+404251-0740023')! },
    { tz: 'America/Chicago', ...parseZoneCoord('+415100-0873900')! },
    { tz: 'America/Denver', ...parseZoneCoord('+394421-1045903')! },
    { tz: 'America/Los_Angeles', ...parseZoneCoord('+340308-1181434')! },
  ];
  assert.equal(nearestZone(us, 42.36, -71.06), 'America/New_York'); // Boston
  assert.equal(nearestZone(us, 37.42, -122.08), 'America/Los_Angeles'); // Mountain View
  assert.equal(nearestZone(us, 41.88, -87.63), 'America/Chicago');
  assert.equal(nearestZone([{ tz: 'Europe/Amsterdam', lat: 52.37, lon: 4.9 }], undefined, undefined), 'Europe/Amsterdam');
  assert.equal(nearestZone([], 1, 1), null);
});

test('every zone.tab line parses when the dataset is present', { skip: !existsData() }, () => {
  const rows = readFileSync(new URL('../../../data/zone.tab', import.meta.url), 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  for (const l of rows) assert.ok(parseZoneCoord(l.split('\t')[1]!), l);
});

function existsData() {
  try {
    readFileSync(new URL('../../../data/zone.tab', import.meta.url));
    return true;
  } catch {
    return false;
  }
}
