import os
import time
def check_heartbeats(comm_root, agent_id, time_delta_timeout=0):
    """
    Always return a dict:
    {
        "meta": { error_success, error, last_seen_any, latest_delta, thread_count },
        "threads": { thread_name: { ...status info... }, ... }
    }
    """
    base = os.path.join(comm_root, agent_id, "hello.moto")
    now = time.time()
    threads = {}
    error = None
    last_seen_any = 0
    latest_delta = 0

    try:
        files = [f for f in os.listdir(base) if f.startswith("poke.")]
        for fname in files:
            parts = fname.split(".")
            if len(parts) < 5:
                continue

            _, thread, timeout, sleep_for, wake_due = parts[:5]
            timeout = int(timeout) if timeout.isdigit() else 0
            sleep_for = int(sleep_for) if sleep_for.isdigit() else 0
            wake_due = int(wake_due) if wake_due.isdigit() else 0

            fpath = os.path.join(base, fname)
            last_seen = os.path.getmtime(fpath)
            last_seen_any = max(last_seen_any, last_seen)

            if wake_due and now < wake_due:
                status = "sleeping"
                delta = now - wake_due
            else:
                delta = now - last_seen
                fail_cutoff = max(timeout, time_delta_timeout)
                status = "alive" if fail_cutoff == 0 or delta < fail_cutoff else "failed"

            latest_delta = max(latest_delta, delta)

            threads[thread] = {
                "thread": thread,
                "status": status,
                "last_seen": last_seen,
                "timeout": timeout,
                "sleep_for": sleep_for,
                "wake_due": wake_due,
                "delta": delta,
            }
    except FileNotFoundError:
        error = f"hello.moto missing for {agent_id}"

    if not threads:
        error = error or "no heartbeat files"

    return {
        "meta": {
            "error_success": 0 if not error else 1,
            "error": error,
            "last_seen_any": last_seen_any,
            "latest_delta": latest_delta,
            "thread_count": len(threads),
        },
        "threads": threads,
    }
