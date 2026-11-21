-- Silver -> Gold: per-source-IP daily threat metrics for the SOC dashboard.
-- A likely password-spray source = many distinct users, high failure ratio.
SELECT
    dt,
    src_ip,
    count(*)                                                     AS attempts,
    count(DISTINCT user_id)                                      AS distinct_users,
    sum(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END)         AS failures,
    round(avg(CASE WHEN outcome = 'FAILURE' THEN 1.0 ELSE 0 END), 4) AS failure_ratio,
    round(avg(CASE WHEN is_scripted_client THEN 1.0 ELSE 0 END), 4)  AS scripted_ratio,
    (count(DISTINCT user_id) >= 10
        AND avg(CASE WHEN outcome = 'FAILURE' THEN 1.0 ELSE 0 END) >= 0.5) AS suspected_spray
FROM silver
GROUP BY dt, src_ip
ORDER BY failures DESC
