"""Scans en arrière-plan : JobStore thread-safe (lancement, instantané, annulation)."""
from __future__ import annotations
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

MAX_RUNNING = 2
RETENTION_S = 900
MAX_STORED = 50


class TooManyJobs(Exception):
    pass


class JobStore:
    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._jobs: Dict[str, Dict[str, Any]] = {}

    def _purge(self) -> None:  # appelé sous le verrou
        now = self._clock()
        for jid in [j for j, v in self._jobs.items()
                    if v["finished_at"] is not None and now - v["finished_at"] > RETENTION_S]:
            del self._jobs[jid]
        finished = sorted((v["finished_at"], j) for j, v in self._jobs.items()
                          if v["finished_at"] is not None)
        while len(self._jobs) > MAX_STORED and finished:
            del self._jobs[finished.pop(0)[1]]

    def create(self, run_fn, target, context, enabled, crawl) -> str:
        with self._lock:
            self._purge()
            if sum(1 for v in self._jobs.values() if v["status"] == "running") >= MAX_RUNNING:
                raise TooManyJobs()
            jid = uuid.uuid4().hex
            context["module_log"] = []  # jamais la valeur du client
            job = {"status": "running", "context": context, "findings": None, "error": None,
                   "started_at": self._clock(), "finished_at": None}
            self._jobs[jid] = job
        try:
            threading.Thread(target=self._run, args=(job, run_fn, target, enabled, crawl),
                             daemon=True).start()
        except BaseException:
            with self._lock:
                self._jobs.pop(jid, None)
            raise
        return jid

    def _run(self, job, run_fn, target, enabled, crawl) -> None:
        ctx = job["context"]
        findings, error = None, "interrupted"
        try:
            findings, error = run_fn(target, ctx, enabled, crawl), None
        except BaseException as e:  # SystemExit etc. : le job ne doit jamais rester "running"
            error = str(e) or type(e).__name__
        finally:
            with self._lock:
                job["findings"], job["error"] = findings, error
                job["status"] = ("error" if error is not None
                                 else "cancelled" if ctx.get("cancelled") else "done")
                job["finished_at"] = self._clock()

    def snapshot(self, job_id: str) -> Optional[dict]:
        with self._lock:
            self._purge()
            job = self._jobs.get(job_id)
            if job is None:
                return None
            ctx, finished = job["context"], job["finished_at"] is not None
            return {
                "status": job["status"],
                "current_module": ctx.get("current_module"),
                "module_log": list(ctx.get("module_log", [])),
                "findings": job["findings"] if finished else None,
                "context": ctx if finished else None,
                "error": job["error"],
                "elapsed_ms": round(((job["finished_at"] or self._clock()) - job["started_at"]) * 1000),
            }

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            if job["status"] == "running":
                # Même mécanisme que le budget temps : deadline dépassée + drapeau.
                job["context"]["cancelled"] = True
                job["context"]["deadline"] = time.monotonic()
            return True
