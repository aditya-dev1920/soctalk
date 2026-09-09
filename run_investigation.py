#!/usr/bin/env python3
"""
Single-investigation triage automation runner for SocTalk.
Enqueues a target investigation, scales runs-worker to 1, streams logs,
extracts Jira outputs, and guarantees scale-down to 0 upon exit.
"""

import argparse
import signal
import subprocess
import sys
import time

TERMINAL_STATUSES = {"completed", "failed", "succeeded", "error", "halted_budget"}


def run_kubectl(cmd: list[str], check: bool = True) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"\033[31m[Error] Command failed: {' '.join(cmd)}\n{res.stderr.strip()}\033[0m", file=sys.stderr)
        sys.exit(res.returncode)
    return res.stdout.strip()


def scale_worker(deployment: str, namespace: str, replicas: int):
    print(f"\033[33m==> Setting deployment/{deployment} replicas to {replicas} in {namespace}...\033[0m")
    run_kubectl(["kubectl", "scale", f"deployment/{deployment}", "-n", namespace, f"--replicas={replicas}"])


def main():
    parser = argparse.ArgumentParser(
        description="Targeted single-run SocTalk investigation runner with auto scale-down.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--id",
        dest="investigation_id",
        default="29574524-0bc4-4269-8524-a4980816a8fb",
        help="Target investigation UUID to enqueue and triage.",
    )
    parser.add_argument(
        "--worker-ns",
        default="tenant-nopal-cyber",
        help="Kubernetes namespace where soctalk-runs-worker is deployed.",
    )
    parser.add_argument(
        "--db-ns",
        default="soctalk-system",
        help="Kubernetes namespace where PostgreSQL pod runs.",
    )
    parser.add_argument(
        "--deployment",
        default="soctalk-runs-worker",
        help="Worker deployment name.",
    )
    parser.add_argument(
        "--postgres-pod",
        default="soctalk-system-postgres-0",
        help="PostgreSQL pod name.",
    )
    parser.add_argument(
        "--db-user",
        default="soctalk_admin",
        help="PostgreSQL username.",
    )
    parser.add_argument(
        "--db-name",
        default="soctalk",
        help="PostgreSQL database name.",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=3,
        help="Polling frequency (in seconds) for database status checks.",
    )

    args = parser.parse_args()

    print(f"\033[36m=====================================================")
    print(f" SocTalk Single Run Dispatcher")
    print(f" Investigation ID : {args.investigation_id}")
    print(f" Worker Namespace : {args.worker_ns}")
    print(f" DB Namespace     : {args.db_ns}")
    print(f"=====================================================\033[0m")

    log_proc = None

    def handle_sigint(signum, frame):
        print("\n\033[33m[Interrupt] SIGINT/SIGTERM received. Shutting down...\033[0m")
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    try:
        # 1. Reset queue and insert target investigation run
        print("\033[34m==> Isolating investigation queue in PostgreSQL...\033[0m")
        sql_seed = f"""
        TRUNCATE TABLE investigation_runs CASCADE;
        INSERT INTO investigation_runs (id, tenant_id, investigation_id, status, not_before, started_at)
        SELECT gen_random_uuid(), tenant_id, id, 'active', '1970-01-01 00:00:00+00'::timestamptz, NOW()
        FROM investigations
        WHERE id = '{args.investigation_id}';
        """
        run_kubectl([
            "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
            "--", "psql", "-U", args.db_user, "-d", args.db_name, "-c", sql_seed,
        ])

        # 2. Scale worker up to 1
        scale_worker(args.deployment, args.worker_ns, 1)

        # 3. Wait for pod ready
        print("\033[33m==> Waiting for runs-worker container readiness...\033[0m")
        while True:
            ready = run_kubectl([
                "kubectl", "get", "pods", "-n", args.worker_ns,
                "-l", f"app.kubernetes.io/name={args.deployment}",
                "-o", "jsonpath={.items[0].status.containerStatuses[0].ready}",
            ], check=False)
            if ready == "true":
                break
            time.sleep(2)

        # 4. Stream worker logs in non-blocking subprocess
        print("\033[32m==> Worker ready. Streaming execution logs...\033[0m")
        log_proc = subprocess.Popen([
            "kubectl", "logs", f"deployment/{args.deployment}",
            "-n", args.worker_ns, "-f", "--tail=30",
        ])

        # Poll PostgreSQL for run completion
        status_query = f"""
        SELECT status FROM investigation_runs 
        WHERE investigation_id = '{args.investigation_id}' 
        ORDER BY started_at DESC LIMIT 1;
        """
        while True:
            current_status = run_kubectl([
                "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
                "--", "psql", "-U", args.db_user, "-d", args.db_name, "-t", "-A", "-c", status_query,
            ], check=False).strip()

            if current_status in TERMINAL_STATUSES:
                print(f"\n\033[32m==> Investigation completed with terminal status: {current_status}\033[0m")
                break
            time.sleep(args.poll_interval)

        # 5. Extract Jira ticket info from execution log
        jira_query = f"""
        SELECT output_payload->>'issue_key', output_payload->>'url'
        FROM execution_log 
        WHERE tool_name = 'jira_create_ticket' AND investigation_id = '{args.investigation_id}'
        ORDER BY created_at DESC LIMIT 1;
        """
        jira_raw = run_kubectl([
            "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
            "--", "psql", "-U", args.db_user, "-d", args.db_name, "-t", "-A", "-F|", "-c", jira_query,
        ], check=False).strip()

        if jira_raw and "|" in jira_raw:
            issue_key, issue_url = jira_raw.split("|", 1)
            print(f"\033[35m=====================================================")
            print(f" Jira Ticket Key : {issue_key}")
            print(f" Jira Ticket URL : {issue_url}")
            print(f"=====================================================\033[0m")

    finally:
        if log_proc and log_proc.poll() is None:
            log_proc.terminate()
            log_proc.wait()

        # Guaranteed scale-down
        scale_worker(args.deployment, args.worker_ns, 0)
        print("\033[36m==> Cleanup complete. Worker replicas: 0.\033[0m")


if __name__ == "__main__":
    main()