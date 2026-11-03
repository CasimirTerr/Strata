// Browser checks for docs/index.html. Run after `python tests/web/make_cases.py`:
//   node tests/web/check_web.js
// 1. The JavaScript engine gives the same JSON as Python on every case.
// 2. "Replay as live" streams every event and ends on the full result.
// 3. The chat works with an API key (mocked Anthropic API) and inside claude.ai (mocked claude.use).
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");

const PAGE = "file://" + path.resolve(__dirname, "../../docs/index.html");
const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "cases.json"), "utf8"));
let failures = 0;
const check = (ok, label) => { console.log(`${ok ? "ok  " : "FAIL"} ${label}`); if (!ok) failures++; };

(async () => {
  const browser = await chromium.launch();
  const open = async (init) => {
    const page = await (await browser.newContext({ viewport: { width: 1300, height: 1000 } })).newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
    if (init) await page.addInitScript(init);
    await page.goto(PAGE);
    await page.waitForTimeout(300);
    return { page, errors };
  };

  // 1. Parity with Python.
  let { page, errors } = await open();
  const got = await page.evaluate((cs) => cs.map((c) => Strata.scanRecords(c.records, c.lambdas, c.allow)), cases);
  const mismatched = cases.filter((c, i) => JSON.stringify(c.expected) !== JSON.stringify(got[i])).length;
  check(mismatched === 0, `JavaScript matches Python on ${cases.length} cases (${mismatched} different)`);

  // 2. Replay.
  await page.click('.speed button[data-speed="4"]');
  await page.click("#play");
  await page.waitForTimeout(1500);
  const mid = await page.locator("#stats").innerText();
  await page.waitForFunction(() => document.getElementById("play").textContent === "Replay as live", null, { timeout: 30000 });
  const end = await page.locator("#stats").innerText();
  check(/of 53 events/.test(mid), `replay shows progress (${mid.replace(/\n/g, " ")})`);
  check(/18\s*detections/.test(end) && /3\s*attack chains/.test(end), "replay ends on the full scan");
  check((await page.locator("#feed li.hit").count()) > 0, "replay feed highlights detections");

  // 3a. Chat with an API key.
  let request = null;
  await page.route("https://api.anthropic.com/v1/messages", async (route) => {
    request = { headers: route.request().headers(), body: JSON.parse(route.request().postData()) };
    await route.fulfill({ status: 200, contentType: "application/json", headers: { "access-control-allow-origin": "*" },
      body: JSON.stringify({ content: [{ type: "text", text: "It was **ci-deployer**." }] }) });
  });
  check(await page.locator("#send").isDisabled(), "chat is off until Claude is connected");
  await page.fill("#apikey", "sk-ant-test");
  await page.click("#keyform button");
  await page.click("#suggest button >> nth=0");
  await page.waitForSelector("#messages li.bot b");
  check(request && request.headers["x-api-key"] === "sk-ant-test", "API key is sent to the Anthropic API");
  check(request && request.body.system.includes("<scan_results>"), "chat sends the scan results as context");
  await page.unroute("https://api.anthropic.com/v1/messages");
  await page.route("https://api.anthropic.com/v1/messages", (r) => r.fulfill({ status: 401, contentType: "application/json",
    headers: { "access-control-allow-origin": "*" }, body: JSON.stringify({ error: { message: "invalid x-api-key" } }) }));
  await page.fill("#question", "again?");
  await page.press("#question", "Enter");
  await page.waitForSelector("#messages li.err");
  check((await page.locator("#messages li.err").innerText()).includes("rejected"), "a bad key gets a clear error");
  check(errors.length === 0, `no page errors (${errors.join("; ")})`);

  // 3b. Chat inside claude.ai.
  ({ page, errors } = await open(() => {
    const sample = async (input, opts) => { opts.onText({ text: "...", delta: "" }); return { text: "From **claude.ai**.", truncated: false }; };
    window.claude = { use: async (name) => (name === "sample" ? sample : null) };
  }));
  await page.waitForFunction(() => document.getElementById("chatStatus").textContent.includes("claude.ai account"));
  check(await page.locator("#keyform").isHidden(), "inside claude.ai the key form is hidden");
  await page.fill("#question", "What happened?");
  await page.click("#send");
  await page.waitForFunction(() => (document.querySelector("#messages li.bot") || {}).textContent === "From claude.ai.");
  check(true, "chat answers through claude.ai");
  check(errors.length === 0, `no page errors in claude.ai mode (${errors.join("; ")})`);

  await browser.close();
  console.log(failures ? `\n${failures} check(s) failed` : "\nall web checks passed");
  process.exit(failures ? 1 : 0);
})();
