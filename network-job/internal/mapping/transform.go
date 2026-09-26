// Copyright 2026 CrabCanneryShip
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mapping

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// protocolNumbers maps IANA protocol numbers to human-readable names,
// used by the "proto_num" transform (AWS, Google both express protocol
// as a number rather than a name).
var protocolNumbers = map[string]string{
	"1":  "ICMP",
	"6":  "TCP",
	"17": "UDP",
}

// ApplyTransform applies a non-timestamp transform to a resolved source
// value. This is deliberately a fixed switch, not a plugin/expression
// system — a mapping config can only ever do one of these operations,
// never arbitrary code.
func ApplyTransform(raw, transform string) (string, error) {
	switch transform {
	case "":
		return raw, nil
	case "upper":
		return strings.ToUpper(raw), nil
	case "lower":
		return strings.ToLower(raw), nil
	case "url_decode":
		v, err := url.QueryUnescape(raw)
		if err != nil {
			return "", fmt.Errorf("url_decode: %w", err)
		}
		return v, nil
	case "proto_num":
		if name, ok := protocolNumbers[raw]; ok {
			return name, nil
		}
		return raw, nil
	case "basename":
		// Last "/"-separated segment — e.g. an Azure resourceId
		// (".../azureFirewalls/myFirewall" -> "myFirewall").
		parts := strings.Split(raw, "/")
		return parts[len(parts)-1], nil
	case "gcp_log_name_project":
		project, _ := splitGCPLogName(raw)
		return project, nil
	case "gcp_log_name_id":
		_, logID := splitGCPLogName(raw)
		return logID, nil
	default:
		return "", fmt.Errorf("unknown transform %q", transform)
	}
}

// splitGCPLogName splits a Cloud Logging logName
// ("projects/<project>/logs/<url-encoded log id>") into the project ID
// and the URL-decoded log ID, e.g.
// "projects/my-project/logs/compute.googleapis.com%2Ffirewall" ->
// ("my-project", "compute.googleapis.com/firewall").
func splitGCPLogName(logName string) (project, logID string) {
	parts := strings.SplitN(logName, "/logs/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	project = strings.TrimPrefix(parts[0], "projects/")
	if decoded, err := url.QueryUnescape(parts[1]); err == nil {
		logID = decoded
	} else {
		logID = parts[1]
	}
	return project, logID
}

// ParseTimestamp parses a resolved source value into a time.Time using
// the field mapping's Transform as the format selector. Unlike
// ApplyTransform, this is only used for the event_timestamp target,
// since it produces a time.Time rather than a string.
func ParseTimestamp(raw, transform string) (time.Time, error) {
	switch {
	case transform == "" || transform == "rfc3339":
		t, err := time.Parse(time.RFC3339, raw)
		return t.UTC(), err
	case transform == "rfc3339nano":
		t, err := time.Parse(time.RFC3339Nano, raw)
		return t.UTC(), err
	case transform == "unix":
		sec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("unix: %w", err)
		}
		return time.Unix(sec, 0).UTC(), nil
	case transform == "unix_ms":
		ms, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("unix_ms: %w", err)
		}
		return time.UnixMilli(ms).UTC(), nil
	case transform == "aws_suricata":
		// Suricata-style timestamp AWS Network Firewall emits, e.g.
		// "2024-12-09T02:26:33.828371+0000" (microseconds, offset with
		// no colon) — not parseable by RFC3339/RFC3339Nano directly.
		for _, layout := range []string{
			"2006-01-02T15:04:05.999999-0700",
			"2006-01-02T15:04:05-0700",
		} {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("aws_suricata: unrecognized timestamp format %q", raw)
	case transform == "auto":
		// Tries, in order: unix epoch seconds, RFC3339, then two common
		// "space-separated date/time" layouts. For a log format whose
		// exact timestamp shape isn't known ahead of time (e.g. an
		// unlabeled generic CSV export); prefer a specific transform
		// above when the format IS known, since "auto" silently picks
		// whichever layout happens to parse rather than confirming it's
		// the right one.
		if sec, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC(), nil
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006/01/02 15:04:05"} {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("auto: unrecognized timestamp format %q", raw)
	case strings.HasPrefix(transform, "layout:"):
		layout := strings.TrimPrefix(transform, "layout:")
		t, err := time.Parse(layout, raw)
		return t.UTC(), err
	default:
		return time.Time{}, fmt.Errorf("unknown timestamp transform %q", transform)
	}
}
