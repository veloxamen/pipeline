CREATE OR REPLACE TABLE `[PROJECT].[DATASET].timeline_nexus` AS

WITH parsed AS (
  SELECT
    event_timestamp,
    event_uuid,
    device_name,
    event_identifier,
    REGEXP_EXTRACT_ALL(
      REGEXP_EXTRACT(message, r'Strings:\s*\[(.*?)\]'),
      r"'([^']*)'"
    ) AS strings_arr
  FROM `[PROJECT].[DATASET].timeline_events`
  WHERE data_type = 'windows:evtx:record'
    AND event_identifier IN (4624, 4625)
    AND message IS NOT NULL
    -- specify the earliest network log date or retention duration
    -- AND event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 90 DAY)
    AND event_timestamp >= "2026-09-01 00:00:00"
)

-- Security-Auditing successful logon (4624). 27-element array; offsets
-- confirmed against sample.
SELECT
  event_timestamp,
  event_uuid,
  strings_arr[SAFE_OFFSET(18)] AS src_ip,   -- IpAddress
  strings_arr[SAFE_OFFSET(11)] AS src_name, -- WorkstationName
  CAST(NULL AS STRING)         AS dst_ip,
  device_name                 AS dst_name,
  strings_arr[SAFE_OFFSET(5)]  AS user_name  -- TargetUserName
FROM parsed
WHERE event_identifier = 4624

UNION ALL

-- Security-Auditing failed logon (4625). 21-element array with a DIFFERENT
-- layout than 4624 past index ~13 — do not reuse 4624's offsets. Offsets
-- confirmed against sample.
SELECT
  event_timestamp,
  event_uuid,
  strings_arr[SAFE_OFFSET(19)] AS src_ip,   -- IpAddress
  strings_arr[SAFE_OFFSET(13)] AS src_name, -- WorkstationName
  CAST(NULL AS STRING)         AS dst_ip,
  device_name                 AS dst_name,
  strings_arr[SAFE_OFFSET(5)]  AS user_name  -- TargetUserName
FROM parsed
WHERE event_identifier = 4625

UNION ALL

SELECT
  event_timestamp,
  event_uuid,
  src_ip,
  CAST(NULL AS STRING) AS dst_name,
  dst_ip,
  CAST(NULL AS STRING) AS dst_name,
  user_name
FROM `[PROJECT].[DATASET].network_events`
;