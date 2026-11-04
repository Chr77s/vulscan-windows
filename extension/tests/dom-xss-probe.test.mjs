import { test } from "node:test";
import assert from "node:assert/strict";
import { DOM_PAYLOAD_TEMPLATES, buildDomProbes, runDomProbes, domFindingFromHit } from "../src/utils/dom-xss-probe.js";

const counter = () => { let n = 0; return () => `T${++n}`; };
const build = (url, o = {}) => buildDomProbes(url, { makeToken: counter(), ...o });
const CTX = ["html", "js-single", "js-double", "js-url"];

test("builds one probe per param per template in order", () => {
  const probes = build("https://x.test/p?a=1&b=2#");
  const hashless = probes.filter((p) => p.param !== "#hash");
  assert.deepEqual(hashless.map((p) => `${p.param}:${p.context}`),
    ["a", "b"].flatMap((n) => CTX.map((c) => `${n}:${c}`)));
  assert.deepEqual(DOM_PAYLOAD_TEMPLATES.map((t) => t.context), CTX);
  assert.ok(probes[0].payload.includes("data-vulnscan-hit"));
});

test("adds #hash probes and replaces an existing fragment", () => {
  for (const url of ["https://x.test/p", "https://x.test/p?a=1#old-frag"]) {
    const hash = build(url, { maxProbes: 99 }).filter((p) => p.param === "#hash");
    assert.equal(hash.length, 4);
    for (const p of hash) {
      const u = new URL(p.probeUrl);
      assert.ok(!u.hash.includes("old-frag"));
      assert.equal(u.hash.split("#").length, 2);
      assert.ok(decodeURIComponent(u.hash.slice(1)).includes(p.token));
    }
  }
});

test("keeps other params intact and round-trips encoded values", () => {
  const url = "https://x.test/p?a=1%262%232+x&b=y%20z&c=3";
  const probe = build(url).find((p) => p.param === "b");
  const u = new URL(probe.probeUrl);
  assert.equal(u.origin, "https://x.test");
  assert.equal(u.searchParams.get("a"), "1&2#2 x");
  assert.equal(u.searchParams.get("c"), "3");
  assert.equal(u.searchParams.get("b"), probe.payload);
});

test("caps at maxProbes", () => {
  assert.equal(build("https://x.test/p?a=1&b=2&c=3&d=4&e=5").length, 16);
  assert.equal(build("https://x.test/p?a=1", { maxProbes: 3 }).length, 3);
});

test("tokens are unique and appear in payload", () => {
  const probes = build("https://x.test/p?a=1&b=2");
  assert.equal(new Set(probes.map((p) => p.token)).size, probes.length);
  for (const p of probes) assert.ok(p.payload.includes(p.token));
});

const mk = (param, context, i = 0) => ({ param, context, token: `${param}${i}`, payload: "p", probeUrl: `https://x.test/?${param}` });

test("runner stops a parameter after its first hit", async () => {
  const probes = [mk("a", "html"), mk("a", "js-single"), mk("a", "js-double"), mk("b", "html")];
  const seen = [];
  const hits = await runDomProbes({
    probes, now: () => 0,
    check: async (p) => { seen.push(`${p.param}:${p.context}`); return p.param === "a" && p.context === "js-single"; },
  });
  assert.deepEqual(seen, ["a:html", "a:js-single", "b:html"]);
  assert.deepEqual(hits.map((h) => h.context), ["js-single"]);
});

test("runner stops at budget", async () => {
  let t = 0;
  const seen = [];
  await runDomProbes({
    probes: [mk("a", "html"), mk("b", "html"), mk("c", "html")], budgetMs: 1000,
    now: () => t,
    check: async (p) => { seen.push(p.param); t += 600; return false; },
  });
  assert.deepEqual(seen, ["a", "b"]);
});

test("runner stops when isStopped", async () => {
  let stop = false;
  const seen = [];
  await runDomProbes({
    probes: [mk("a", "html"), mk("b", "html")], now: () => 0, isStopped: () => stop,
    check: async (p) => { seen.push(p.param); stop = true; return true; },
  });
  assert.deepEqual(seen, ["a"]);
});

test("throwing check counts as not confirmed", async () => {
  const hits = await runDomProbes({
    probes: [mk("a", "html"), mk("a", "js-single")], now: () => 0,
    check: async (p) => { if (p.context === "html") throw new Error("boom"); return true; },
  });
  assert.deepEqual(hits.map((h) => h.context), ["js-single"]);
});

test("finding has the spec fields and copy", () => {
  const hit = { param: "#hash", context: "html", token: "TK", payload: "PL", probeUrl: "https://x.test/#PL" };
  const f = domFindingFromHit(hit, "https://x.test/");
  assert.match(f.description, /DOM/);
  assert.match(f.recommendation, /textContent/);
  delete f.description; delete f.recommendation;
  assert.deepEqual(f, {
    type: "xss",
    title: "DOM XSS confirmée — exécution observée",
    severity: "high",
    confidence: 95,
    detectionMethod: "dom-execution-confirmed",
    source: "extension:dom-xss",
    parameter: "#hash",
    payload: "PL",
    url: "https://x.test/",
    evidence: "Le payload a posé data-vulnscan-hit=TK sur <html> (contexte html) — URL de sonde : https://x.test/#PL",
    cwe: "CWE-79",
    owasp: "A03:2021",
  });
});
