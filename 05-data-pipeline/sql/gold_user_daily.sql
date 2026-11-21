-- Silver -> Gold: per-user daily auth summary (dimensional fact at user x day grain).
SELECT
    dt,
    user_id,
    count(*)                                               AS logins,
    sum(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END)   AS failures,
    sum(CASE WHEN outcome = 'SUCCESS' AND NOT mfa_used THEN 1 ELSE 0 END) AS successes_without_mfa,
    count(DISTINCT src_ip)                                 AS distinct_ips,
    min(event_ts)                                          AS first_seen,
    max(event_ts)                                          AS last_seen
FROM silver
GROUP BY dt, user_id
