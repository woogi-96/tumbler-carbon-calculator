// End-to-end tests for Game.html (멍뭉이 털을 찾아라).
// Run: node --test
// Serves the repo with the Content-Security-Policy from vercel.json so the
// game is checked under the same headers it gets in production.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const ROOT = path.join(__dirname, '..');
const vercel = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
const HEADERS = Object.fromEntries(vercel.headers[0].headers.map(h => [h.key, h.value]));

let server, base, browser;

before(async () => {
  server = http.createServer((req, res) => {
    const urlPath = decodeURIComponent(req.url.split('?')[0]);
    let file = path.join(ROOT, urlPath === '/' ? 'index.html' : urlPath);
    if (!path.extname(file) && fs.existsSync(file + '.html')) file += '.html'; // Vercel-style clean URL
    if (!file.startsWith(ROOT) || !fs.existsSync(file)) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { ...HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch();
});
after(async () => { await browser?.close(); server?.close(); });

async function open(opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 400, height: 780 }, ...opts });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push('pageerror: ' + e.message));
  page.on('console', m => {
    // Google Fonts may be unreachable in CI; everything else is a real error
    if (m.type() === 'error' && !/fonts\.(googleapis|gstatic)/.test(m.text())) errors.push('console: ' + m.text());
  });
  await page.goto(base + '/Game', { waitUntil: 'load' });
  await page.waitForFunction(() => window.__mm);
  await page.waitForTimeout(400); // sprite variants are generated on load
  return { page, ctx, errors };
}

// Click a hair through the real pointer path. Picks a point on the hair where no
// other hair is close enough to be grabbed too (맨손 grabs everything within ~13px,
// the other tools only take the single nearest hair).
async function clickHair(page, white, { touch = false } = {}) {
  // wait until the head has settled after the previous pluck's bounce/shake
  await page.waitForFunction(() => __mm.G.bounce === 0 && __mm.G.shake === 0, null, { timeout: 3000 });
  const handle = await page.waitForFunction(white => {
    const { G, toScreen, hairDist } = __mm;
    const clashR = G.tool === 0 ? 17 : 1.5;
    for (const h of G.hairs) {
      if (h.white !== white || h.dying || h.born >= 0 && G.t - h.born < .4) continue;
      for (const t of [1, .9, .75, .6, .5]) {
        const u = 1 - t;
        const x = u * u * h.x + 2 * u * t * h.cx + t * t * h.tx, y = u * u * h.y + 2 * u * t * h.cy + t * t * h.ty;
        const s = toScreen(x, y), r = document.getElementById('cvWrap').getBoundingClientRect();
        if (s.x < 6 || s.y < 6 || s.x > r.width - 6 || s.y > r.height - 6) continue; // must be tappable
        if (!G.hairs.some(o => o !== h && hairDist(o, x, y) < clashR)) return s;
      }
    }
    return null;
  }, white, { timeout: 8000 });
  const pt = await handle.jsonValue();
  const box = await page.locator('#cvWrap').boundingBox();
  if (touch) await page.touchscreen.tap(box.x + pt.x, box.y + pt.y);
  else await page.mouse.click(box.x + pt.x, box.y + pt.y);
}

test('page is served at /Game with production CSP and loads without errors', async () => {
  const { page, ctx, errors } = await open();
  assert.equal(await page.title(), '멍뭉이 털을 찾아라');
  assert.match(await page.locator('#sTitle h1').innerText(), /멍뭉이 털을 찾아라/);
  assert.equal(await page.locator('#stageGrid button').count(), 10);
  assert.equal(await page.locator('#stageGrid button:not([disabled])').count(), 1, 'only stage 1 unlocked at first');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('stage 1 intro: arrival, single 좋아 answer, tool card, 2:00 timer', async () => {
  const { page, ctx, errors } = await open();
  await page.click('#btnStart');
  await page.waitForSelector('#mmBubble.on', { timeout: 10000 });
  assert.equal(await page.locator('#mmBubble').innerText(), '오늘도 흰머리를 뽑아보자!');
  await page.waitForSelector('#choice.on');
  const answers = page.locator('#choice button');
  assert.equal(await answers.count(), 1);
  assert.equal((await answers.innerText()).trim(), '좋아');
  await answers.click();
  await page.waitForSelector('#toolOv.on', { timeout: 5000 });
  assert.equal(await page.locator('#toolName').innerText(), '맨손');
  await page.click('#btnGo');
  await page.waitForSelector('#sGame.on');
  assert.match(await page.locator('#timeTxt').innerText(), /2:00|1:59/);
  assert.equal(await page.locator('#scoreTxt').innerText(), '0 / 20점');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('scoring: white hair +5 with happy face, black hair -1 with angry face', async () => {
  const { page, ctx, errors } = await open();
  await page.evaluate(() => __mm.startGame(1)); // 족집게: exactly one hair per pluck
  await clickHair(page, true);
  assert.equal(await page.evaluate(() => __mm.G.score), 5);
  assert.equal(await page.evaluate(() => __mm.G.expr), 'happy');
  await page.waitForTimeout(1100);
  await clickHair(page, false);
  assert.equal(await page.evaluate(() => __mm.G.score), 4);
  assert.equal(await page.evaluate(() => __mm.G.expr), 'angry');
  assert.equal(await page.locator('#scoreTxt').innerText(), '4 / 20점');
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('reaching 20 points clears the stage and saves progress', async () => {
  const { page, ctx, errors } = await open();
  await page.evaluate(() => __mm.startGame(1));
  for (let k = 0; k < 4; k++) { await clickHair(page, true); await page.waitForTimeout(50); }
  assert.equal(await page.evaluate(() => __mm.G.score), 20);
  assert.equal(await page.evaluate(() => __mm.G.running), false);
  await page.waitForSelector('#resultOv.on');
  assert.match(await page.locator('#resultCard').innerText(), /2단계 통과/);
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('mmhair_v1')));
  assert.equal(saved.cleared, 1);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('time running out fails the stage and retry resets it', async () => {
  const { page, ctx, errors } = await open();
  await page.evaluate(() => { __mm.startGame(0); __mm.G.timeLeft = 0.3; });
  await page.waitForSelector('#resultOv.on', { timeout: 3000 });
  assert.match(await page.locator('#resultCard').innerText(), /시간 초과/);
  await page.click('[data-a="retry"]');
  assert.equal(await page.evaluate(() => __mm.G.score), 0);
  assert.equal(await page.evaluate(() => __mm.G.timeLeft > 119), true);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('10 stages get harder and unlock tools', async () => {
  const { page, ctx } = await open();
  const ps = await page.evaluate(() => Array.from({ length: 10 }, (_, i) => __mm.stageParams(i)));
  assert.equal(ps[0].time, 120);
  for (let i = 1; i < 10; i++) {
    assert.ok(ps[i].time <= ps[i - 1].time, 'time limit never grows');
    assert.ok(ps[i].black > ps[i - 1].black, 'more black hairs each stage');
    assert.ok(ps[i].white <= ps[i - 1].white, 'fewer white hairs at once');
  }
  assert.equal(await page.evaluate(() => __mm.TOOLS.length), 10);
  const trays = {};
  for (const i of [0, 3, 7, 8]) {
    await page.evaluate(i => __mm.startGame(i), i);
    trays[i] = await page.locator('#tray .tbtn').evaluateAll(bs => bs.map(b => b.id));
  }
  assert.deepEqual(trays[0], []);
  assert.deepEqual(trays[3], ['tComb']);
  assert.deepEqual(trays[7], ['tComb', 'tTime']);
  assert.deepEqual(trays[8], ['tComb', 'tTime', 'tRadar']);
  // tool buttons do what they say
  const before = await page.evaluate(() => __mm.G.timeLeft);
  await page.click('#tTime');
  assert.ok(await page.evaluate(b => __mm.G.timeLeft > b + 19, before), '시간+20 adds 20 seconds');
  await page.waitForFunction(() => document.getElementById('tTime').disabled, null, { timeout: 2000 }); // hourglass works only once
  await page.click('#tComb');
  assert.ok(await page.evaluate(() => __mm.G.comb > 0));
  await ctx.close();
});

test('after a clear: dance home, next morning, and DAY 2 at 우기네 집', async () => {
  const { page, ctx, errors } = await open();
  // stage 1, but with tweezers precision: this test is about the day flow, and with
  // bare hands a random layout can leave no white hair without black neighbours
  await page.evaluate(() => { __mm.startGame(0); __mm.G.tool = 1; __mm.G.score = 15; });
  await clickHair(page, true);
  await page.waitForSelector('[data-a="out"]', { timeout: 3000 });
  await page.click('[data-a="out"]');
  await page.waitForSelector('#sOut.on');
  assert.match(await page.locator('#oMM').getAttribute('class'), /dance/);
  await page.waitForSelector('#sNext.on', { timeout: 20000 });
  assert.equal(await page.locator('#nextTitle').innerText(), 'DAY 2 아침');
  await page.click('#btnNextDay');
  await page.waitForSelector('#sRoom.on');
  assert.match(await page.locator('#dayTag').innerText(), /DAY 2/);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('clearing stage 10 shows the ending', async () => {
  const { page, ctx, errors } = await open();
  await page.evaluate(() => { __mm.startGame(9); __mm.G.score = 15; });
  await clickHair(page, true);
  await page.waitForSelector('[data-a="out"]', { timeout: 3000 });
  await page.click('[data-a="out"]');
  await page.waitForSelector('#sEnd.on', { timeout: 20000 });
  assert.match(await page.locator('#sEnd h1').innerText(), /흰머리 정복 완료/);
  assert.deepEqual(errors, []);
  await ctx.close();
});

test('mobile: plays with touch on a phone-sized screen', async () => {
  const { page, ctx, errors } = await open({ viewport: { width: 360, height: 640 }, hasTouch: true, isMobile: true, deviceScaleFactor: 2 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert.equal(overflow, false, 'no horizontal scroll');
  await page.evaluate(() => __mm.startGame(1));
  await clickHair(page, true, { touch: true });
  assert.equal(await page.evaluate(() => __mm.G.score), 5);
  assert.deepEqual(errors, []);
  await ctx.close();
});
