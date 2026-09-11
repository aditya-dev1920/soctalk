BEGIN;

-- 1. Establish MSSP audience context to satisfy Row-Level Security
SET LOCAL app.current_audience = 'mssp';
SET LOCAL app.current_tenant_id = '';

-- 2. Backfill Seq 1: alert_ingested for all 894 empty investigations
INSERT INTO investigation_events (
    event_id,
    tenant_id,
    investigation_id,
    seq,
    kind,
    payload,
    idempotency_key,
    visibility,
    created_at
)
SELECT 
    gen_random_uuid(),
    a.tenant_id,
    a.investigation_id,
    1,
    'alert_ingested',
    jsonb_build_object(
        'alert_id', a.id::text,
        'rule_id', COALESCE(a.rule_id, 'unknown'),
        'description', COALESCE(a.description, i.title),
        'severity', COALESCE(a.severity, i.severity, 6),
        'full_log', COALESCE(a.full_log, i.title),
        'entities', '[]'::jsonb,
        'asset_ids', COALESCE(a.asset_ids, '[]'::jsonb),
        'initial_iocs', COALESCE(a.initial_iocs, '[]'::jsonb),
        'source_events', COALESCE(a.source_event_ids, '[]'::jsonb),
        'mitre', '{}'::jsonb,
        'ai_confidence', COALESCE(a.ai_confidence, 0.85),
        'initial_hypothesis', 'under_investigation'
    ),
    encode(sha256(format('%s|%s|alert_ingest', a.investigation_id, a.id)::bytea), 'hex'),
    'mssp_only',
    COALESCE(a.created_at, i.opened_at, i.created_at)
FROM alerts a
JOIN investigations i ON i.id = a.investigation_id
WHERE a.investigation_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM investigation_events ie 
      WHERE ie.investigation_id = a.investigation_id
  )
ON CONFLICT (investigation_id, idempotency_key) DO NOTHING;

-- 3. Backfill Seq 2: status_changed for investigations that are already closed or auto-closed
INSERT INTO investigation_events (
    event_id,
    tenant_id,
    investigation_id,
    seq,
    kind,
    payload,
    idempotency_key,
    visibility,
    created_at
)
SELECT 
    gen_random_uuid(),
    i.tenant_id,
    i.id,
    2,
    'status_changed',
    jsonb_build_object(
        'from_status', 'active',
        'to_status', i.status,
        'reason', COALESCE(i.close_reason, 'Investigation resolved')
    ),
    encode(sha256(format('%s|status_changed|%s', i.id, i.status)::bytea), 'hex'),
    'mssp_only',
    COALESCE(i.closed_at, i.updated_at, now())
FROM investigations i
WHERE i.status IN ('closed', 'auto_closed_fp', 'cancelled')
  AND NOT EXISTS (
      SELECT 1 FROM investigation_events ie 
      WHERE ie.investigation_id = i.id 
        AND ie.kind = 'status_changed'
  )
ON CONFLICT (investigation_id, idempotency_key) DO NOTHING;

-- 4. Output backfill verification counts
SELECT 
    count(*) AS total_events_now,
    count(DISTINCT investigation_id) AS covered_investigations
FROM investigation_events;

COMMIT;
