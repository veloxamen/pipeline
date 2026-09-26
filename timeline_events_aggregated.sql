CREATE OR REPLACE VIEW `your-project.your_dataset.nexus_events` AS
WITH net AS (
  SELECT
    event_timestamp AS utc_timestamp,
    DATETIME(event_timestamp, 'Asia/Tokyo') AS local_datetime, -- default: Asia/Tokyo
    'network' AS log_source,
    device_name AS device_name,
    user_name AS username,
    src_ip,
    dst_ip,
    dst_port,
    action,
    CONCAT(COALESCE(log_type, ''), ': ', COALESCE(threat_name, action, '')) AS summary_detail,
    event_uuid
  FROM
    `your-project.your_dataset.network_events`
  WHERE event_timestamp IS NOT NULL
),
timeline AS (
  SELECT
    event_timestamp AS utc_timestamp,
    DATETIME(event_timestamp, 'Asia/Tokyo') AS local_datetime, -- default: Asia/Tokyo
    'endpoint' AS log_source,
    device_name,
    username,
    CAST(NULL AS STRING) AS src_ip,
    CAST(NULL AS STRING) AS dst_ip,
    CAST(INT64(NULL) AS INT64) AS dst_port,
    CAST(NULL AS STRING) AS action,
    CONCAT('[', COALESCE(parser, 'unknown'), '] ', COALESCE(message, '')) AS summary_detail,
    event_uuid
  FROM
    `your-project.your_dataset.timeline_events`
  WHERE event_timestamp IS NOT NULL
)

SELECT * FROM net
UNION ALL
SELECT * FROM timeline
;