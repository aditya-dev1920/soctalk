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


def run_kubectl(cmd: list[str], check: bool = True) -> tuple[str, str, int]:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"\033[31m[Error] Command failed: {' '.join(cmd)}\n{res.stderr.strip()}\033[0m", file=sys.stderr)
        sys.exit(res.returncode)
    return res.stdout.strip(), res.stderr.strip(), res.returncode


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
        # 1. Resolve Target ID across investigations, runs, and embedded JSON fields
        print("\033[34m==> Resolving target investigation in PostgreSQL...\033[0m")
        resolve_sql = f"""
        -- 1. Match direct investigation ID
        SELECT id::text FROM investigations WHERE id::text = '{args.investigation_id}'
        UNION ALL
        -- 2. Match run ID from investigation_runs
        SELECT investigation_id::text FROM investigation_runs WHERE id::text = '{args.investigation_id}'
        UNION ALL
        -- 3. Match threat/alert ID anywhere in the investigation row JSON
        SELECT id::text FROM investigations 
        WHERE to_jsonb(investigations)::text ILIKE '%{args.investigation_id}%'
        LIMIT 1;
        """
        target_inv_id, err, code = run_kubectl([
            "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
            "--", "psql", "-U", args.db_user, "-d", args.db_name, "-t", "-A", "-c", resolve_sql,
        ], check=False)

        if code != 0 and err:
            print(f"\033[31m[Database Error] Failed querying PostgreSQL:\n{err}\033[0m", file=sys.stderr)
            sys.exit(code)

        if not target_inv_id:
            print(f"\033[31m[Error] No investigation found matching ID '{args.investigation_id}'.\033[0m", file=sys.stderr)
            print("\033[33m==> Fetching 3 most recent available investigations from database...\033[0m")
            recent_sql = "SELECT id, status, LEFT(summary, 50) FROM investigations ORDER BY created_at DESC LIMIT 3;"
            recent_list, _, _ = run_kubectl([
                "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
                "--", "psql", "-U", args.db_user, "-d", args.db_name, "-c", recent_sql,
            ], check=False)
            print(recent_list)
            sys.exit(1)

        print(f"\033[32m==> Target matched to Investigation ID: {target_inv_id}\033[0m")

        # 2. Complete ALL non-terminal runs and enqueue target
        sql_seed = f"""
        UPDATE investigation_runs
        SET status = 'completed'
        WHERE status NOT IN ('completed', 'failed', 'succeeded', 'error', 'halted_budget')
          AND investigation_id != '{target_inv_id}';

        DELETE FROM investigation_runs WHERE investigation_id = '{target_inv_id}';
        INSERT INTO investigation_runs (id, tenant_id, investigation_id, status, not_before, started_at)
        SELECT gen_random_uuid(), tenant_id, id, 'active', '1970-01-01 00:00:00+00'::timestamptz, NOW()
        FROM investigations
        WHERE id = '{target_inv_id}';
        """
        run_kubectl([
            "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
            "--", "psql", "-U", args.db_user, "-d", args.db_name, "-c", sql_seed,
        ])

        # 2. Scale worker up to 1
        scale_worker(args.deployment, args.worker_ns, 1)

        # 3. Wait for pod ready
        print("\033[33m==> Waiting for runs-worker container readiness...\033[0m")
        run_kubectl([
            "kubectl", "rollout", "status", f"deployment/{args.deployment}",
            "-n", args.worker_ns, "--timeout=60s",
        ])

        # 4. Stream worker logs in non-blocking subprocess
        print("\033[32m==> Worker ready. Streaming execution logs...\033[0m")
        log_proc = subprocess.Popen([
            "kubectl", "logs", f"deployment/{args.deployment}",
            "-n", args.worker_ns, "-f", "--tail=30",
        ])

        # Poll PostgreSQL for run completion
        status_query = f"""
        SELECT status FROM investigation_runs 
        WHERE investigation_id = '{target_inv_id}' 
        ORDER BY started_at DESC LIMIT 1;
        """
        while True:
            raw_status_out, _, _ = run_kubectl([
                "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
                "--", "psql", "-U", args.db_user, "-d", args.db_name, "-t", "-A", "-c", status_query,
            ], check=False)
            current_status = raw_status_out.strip()

            if current_status in TERMINAL_STATUSES:
                time.sleep(2)
                print(f"\n\033[32m==> Investigation completed with terminal status: {current_status}\033[0m")
                break
            time.sleep(args.poll_interval)

        # 5. Extract Jira ticket info from execution log
        jira_query = f"""
        SELECT 
            COALESCE(e.output_payload->>'issue_key', i.jira_issue_key),
            COALESCE(e.output_payload->>'url', i.jira_ticket_url)
        FROM investigations i
        LEFT JOIN execution_log e 
            ON e.investigation_id = i.id AND e.tool_name = 'jira_create_ticket'
        WHERE i.id = '{target_inv_id}'
        ORDER BY e.created_at DESC NULLS LAST LIMIT 1;
        """
        raw_jira_out, _, _ = run_kubectl([
            "kubectl", "exec", args.postgres_pod, "-n", args.db_ns,
            "--", "psql", "-U", args.db_user, "-d", args.db_name, "-t", "-A", "-F|", "-c", jira_query,
        ], check=False)
        jira_raw = raw_jira_out.strip()

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