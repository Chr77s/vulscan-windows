import { test } from "node:test";
import assert from "node:assert/strict";
import { pollScanJob } from "../src/utils/job-poller.js";

// Fake I/O: getJob replays `script` (a value is a body, an Error is thrown); sleep advances the fake clock.
function harness(script, { maxDurationMs = 60000, step = 2000, ...extra } = {}) {
  let t = 0;
  const calls = { get: 0, cancel: [], ticks: [], progress: [] };
  const opts = {
    startJob: async () => ({ jobId: "j1" }),
    getJob: async () => {
      const item = script[Math.min(calls.get++, script.length - 1)];
      if (item instanceof Error) throw item;
      return item;
    },
    cancelJob: async (id) => { calls.cancel.push(id); },
    sleep: async () => { t += step; },
    now: () => t,
    onProgress: (e) => calls.progress.push(e),
    onTick: (id) => calls.ticks.push(id),
    maxDurationMs,
    ...extra,
  };
  return { opts, calls };
}
const body = (status, moduleLog, extra = {}) => ({ jobId: "j1", status, currentModule: "", moduleLog, elapsedMs: 0, ...extra });

test("delivers each moduleLog entry once across polls", async () => {
  const { opts, calls } = harness([
    body("running", ["a"]),
    body("running", ["a", "b", "c"]),
    body("done", ["a", "b", "c", "d"], { result: { findings: [] } }),
  ]);
  const r = await pollScanJob(opts);
  assert.deepEqual(calls.progress, [["a"], ["b", "c"], ["d"]]);
  assert.deepEqual(r.moduleLog, ["a", "b", "c", "d"]);
});

test("no duplicate after a failed poll then a success", async () => {
  const { opts, calls } = harness([
    body("running", ["a"]),
    new Error("net"),
    body("done", ["a", "b"], { result: { ok: 1 } }),
  ]);
  await pollScanJob(opts);
  assert.deepEqual(calls.progress, [["a"], ["b"]]);
});

test("stops and returns result on done", async () => {
  const { opts, calls } = harness([body("done", ["a"], { result: { findings: [1] } })]);
  const r = await pollScanJob(opts);
  assert.equal(r.status, "done");
  assert.deepEqual(r.result, { findings: [1] });
  assert.equal(calls.get, 1);
  assert.equal(calls.cancel.length, 0);
});

test("returns partial result on cancelled", async () => {
  const { opts } = harness([body("cancelled", ["a"], { result: { findings: [], partial: true } })]);
  const r = await pollScanJob(opts);
  assert.equal(r.status, "cancelled");
  assert.deepEqual(r.result, { findings: [], partial: true });
});

test("returns error status on error", async () => {
  const { opts } = harness([body("error", ["a"], { error: "boom" })]);
  const r = await pollScanJob(opts);
  assert.equal(r.status, "error");
  assert.equal(r.result, null);
  assert.deepEqual(r.moduleLog, ["a"]);
});

test("timeout cancels once then returns the partial result", async () => {
  const { opts, calls } = harness(
    [
      body("running", ["a"]),
      body("running", ["a"]),
      body("running", ["a"]),
      body("cancelled", ["a", "b"], { result: { partial: true } }),
    ],
    { maxDurationMs: 5000 }, // step 2000: exceeded on the 3rd poll
  );
  const r = await pollScanJob(opts);
  assert.deepEqual(calls.cancel, ["j1"]);
  assert.equal(r.status, "cancelled");
  assert.deepEqual(r.result, { partial: true });
});

test("timeout gives up after 5 extra polls if the job never stops", async () => {
  const { opts, calls } = harness([body("running", [])], { maxDurationMs: 1000 });
  const r = await pollScanJob(opts);
  assert.equal(calls.cancel.length, 1);
  assert.equal(calls.get, 6); // the timeout poll + 5 extra
  assert.equal(r.result, null);
});

test("gives up after 3 consecutive failures and cancels best-effort", async () => {
  const { opts, calls } = harness([body("running", ["a"]), new Error("x")], {
    cancelJob: async () => { throw new Error("cancel failed too"); },
  });
  const r = await pollScanJob(opts);
  assert.deepEqual(r, { status: "error", result: null, moduleLog: ["a"] });
  assert.equal(calls.get, 4); // 1 ok + 3 consecutive failures
});

test("calls onTick every poll with the job id", async () => {
  const { opts, calls } = harness([body("running", []), new Error("x"), body("done", [], { result: {} })]);
  await pollScanJob(opts);
  assert.deepEqual(calls.ticks, ["j1", "j1", "j1"]);
});

test("throwing callbacks never stop polling nor duplicate entries", async () => {
  let progressCalls = 0;
  const { opts, calls } = harness([
    body("running", ["a"]),
    body("running", ["a", "b"]),
    body("done", ["a", "b", "c"], { result: { ok: 1 } }),
  ], {
    onTick: () => { throw new Error("storage"); },
    onProgress: (e) => { calls0.push(e); if (++progressCalls === 1) throw new Error("once"); },
  });
  const calls0 = [];
  const r = await pollScanJob(opts);
  assert.equal(r.status, "done");
  assert.deepEqual(calls0, [["a"], ["b"], ["c"]]);
  assert.deepEqual(r.moduleLog, ["a", "b", "c"]);
});

test("rejects a missing or non-finite maxDurationMs before starting", async () => {
  for (const bad of [undefined, 0, -1, NaN, Infinity, "5"]) {
    let started = false;
    const { opts } = harness([body("done", [])], { startJob: async () => { started = true; return { jobId: "j1" }; } });
    opts.maxDurationMs = bad; // set after harness: its default would mask undefined
    await assert.rejects(pollScanJob(opts), TypeError);
    assert.equal(started, false);
  }
});

test("sends cancel at most once even if polls fail after a timeout-cancel", async () => {
  const { opts, calls } = harness([body("running", []), new Error("x")], { maxDurationMs: 1000 });
  const r = await pollScanJob(opts);
  assert.equal(r.status, "error");
  assert.deepEqual(calls.cancel, ["j1"]);
});

test("a null/undefined getJob result counts as a failure", async () => {
  const { opts, calls } = harness([body("running", ["a"]), undefined, null, undefined]);
  const r = await pollScanJob(opts);
  assert.equal(r.status, "error");
  assert.equal(calls.get, 4);
  assert.deepEqual(calls.cancel, ["j1"]);
});

test("startJob rejection rejects pollScanJob", async () => {
  const { opts } = harness([body("done", [])], { startJob: async () => { throw new Error("down"); } });
  await assert.rejects(pollScanJob(opts), /down/);
});

test("a shorter moduleLog on a later poll does not crash or re-deliver", async () => {
  const { opts, calls } = harness([
    body("running", ["a", "b"]),
    body("running", ["a"]),
    body("done", ["a", "b", "c"], { result: {} }),
  ]);
  const r = await pollScanJob(opts);
  assert.deepEqual(calls.progress, [["a", "b"], ["c"]]);
  assert.equal(r.status, "done");
});

test("timeout with a job that never stops resolves running/null", async () => {
  const { opts } = harness([body("running", [])], { maxDurationMs: 1000 });
  const r = await pollScanJob(opts);
  assert.equal(r.status, "running");
  assert.equal(r.result, null);
});
