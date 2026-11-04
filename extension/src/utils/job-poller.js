// Pure polling loop for backend scan jobs. All I/O is injected so it runs in Node tests.
const TERMINAL = new Set(["done", "cancelled", "error"]);
const EXTRA_POLLS_AFTER_CANCEL = 5;

export async function pollScanJob({
  startJob, getJob, cancelJob, sleep, now, onProgress, onTick,
  intervalMs = 2000, maxDurationMs, maxConsecutiveErrors = 3,
}) {
  const { jobId } = await startJob();
  const start = now();
  let delivered = 0; // moduleLog only grows, so a count is enough
  let errors = 0;
  let cancelSent = false;
  let extraPolls = 0;
  let status = "running";
  const log = [];

  for (;;) {
    await sleep(intervalMs);
    let job = null;
    try {
      job = await getJob(jobId);
      errors = 0;
    } catch {
      errors += 1;
    }
    if (onTick) onTick(jobId);

    if (job) {
      status = job.status;
      const entries = job.moduleLog || [];
      if (entries.length > delivered) {
        const fresh = entries.slice(delivered);
        delivered = entries.length;
        log.push(...fresh);
        if (onProgress) onProgress(fresh);
      }
      if (TERMINAL.has(status)) {
        return { status, result: job.result ?? null, moduleLog: log };
      }
    } else if (errors >= maxConsecutiveErrors) {
      try { await cancelJob(jobId); } catch { /* best effort */ }
      return { status: "error", result: null, moduleLog: log };
    }

    if (cancelSent) {
      if (++extraPolls >= EXTRA_POLLS_AFTER_CANCEL) return { status, result: null, moduleLog: log };
    } else if (now() - start > maxDurationMs) {
      cancelSent = true;
      try { await cancelJob(jobId); } catch { /* best effort */ }
    }
  }
}
