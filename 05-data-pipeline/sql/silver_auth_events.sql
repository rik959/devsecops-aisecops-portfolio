-- Bronze -> Silver: type, clean, standardise, de-duplicate.
-- Parameters (substituted by the runner): {bronze_path}, {dt}
WITH raw AS (
    SELECT *
    FROM read_json_auto('{bronze_path}', format = 'newline_delimited', union_by_name = true)
),
typed AS (
    SELECT
        event_id,
        TRY_CAST(ts AS TIMESTAMPTZ)                      AS event_ts,
        lower(trim("user"))                              AS user_id,
        src_ip,
        upper(outcome)                                   AS outcome,
        CAST(mfa AS BOOLEAN)                             AS mfa_used,
        coalesce(user_agent, 'unknown')                  AS user_agent,
        user_agent ILIKE 'curl%' OR user_agent ILIKE 'python-%' AS is_scripted_client
    FROM raw
),
deduped AS (
    SELECT *, row_number() OVER (PARTITION BY event_id ORDER BY event_ts) AS rn
    FROM typed
)
SELECT
    event_id, event_ts, user_id, src_ip, outcome, mfa_used, user_agent, is_scripted_client,
    DATE '{dt}' AS dt
FROM deduped
WHERE rn = 1
  AND event_ts IS NOT NULL
  AND user_id IS NOT NULL
  AND outcome IN ('SUCCESS', 'FAILURE')
  AND CAST(event_ts AS DATE) = DATE '{dt}'
