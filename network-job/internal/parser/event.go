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

package parser

import (
	"fmt"
	"strings"

	"github.com/veloxamen/network-job/internal/mapping"
)

// BuildEventFromMapping resolves every field in cfg.Fields against rec
// and assembles a NetworkEvent. It is the single place that knows how
// each mapping "target" name corresponds to a NetworkEvent column —
// the three generic parsers (JSON/KV/CSV) are otherwise identical past
// this point.
func BuildEventFromMapping(rec mapping.Record, cfg *mapping.Config) (NetworkEvent, error) {
	var ev NetworkEvent

	for _, fm := range cfg.Fields {
		raw, ok := resolveRaw(rec, fm)
		if !ok {
			raw = fm.Default // verbatim fallback/constant — never run through ValueMap or Transform
		} else if mapped, exists := fm.ValueMap[raw]; exists {
			raw = mapped
		}

		if fm.Target == "event_timestamp" {
			if raw == "" {
				return ev, fmt.Errorf("event_timestamp: no value resolved (source=%v)", fm.Source)
			}
			t, err := mapping.ParseTimestamp(raw, fm.Transform)
			if err != nil {
				return ev, fmt.Errorf("event_timestamp: %w", err)
			}
			ev.EventTimestamp = t
			continue
		}

		if raw == "" {
			continue // leave this column at its zero value
		}
		val, err := mapping.ApplyTransform(raw, fm.Transform)
		if err != nil {
			return ev, fmt.Errorf("%s: %w", fm.Target, err)
		}

		switch fm.Target {
		case "device_name":
			ev.DeviceName = val
		case "log_type":
			ev.LogType = val
		case "action":
			ev.Action = val
		case "rule_id":
			ev.RuleID = val
		case "rule_name":
			ev.RuleName = val
		case "direction":
			ev.Direction = val
		case "src_ip":
			ev.SrcIP = val
		case "src_port":
			ev.SrcPort = atoiOrZero(val)
		case "dst_ip":
			ev.DstIP = val
		case "dst_port":
			ev.DstPort = atoiOrZero(val)
		case "protocol":
			ev.Protocol = val
		case "ing_if":
			ev.IngIf = val
		case "egr_if":
			ev.EgrIf = val
		case "vpn_remote_ip":
			ev.VPNRemoteIP = val
		case "nat_src_ip":
			ev.NatSrcIP = val
		case "nat_src_port":
			ev.NatSrcPort = atoiOrZero(val)
		case "nat_dst_ip":
			ev.NatDstIP = val
		case "nat_dst_port":
			ev.NatDstPort = atoiOrZero(val)
		case "user_name":
			ev.UserName = val
		case "app_name":
			ev.AppName = val
		case "sent_bytes":
			ev.SentBytes = atoiOrZero(val)
		case "rcvd_bytes":
			ev.RcvdBytes = atoiOrZero(val)
		case "duration":
			ev.Duration = atoiOrZero(val)
		case "threat_name":
			ev.ThreatName = val
		default:
			return ev, fmt.Errorf("unknown mapping target field %q", fm.Target)
		}
	}

	return ev, nil
}

// resolveRaw resolves a field mapping's value, before Transform/Default
// are applied: Join concatenation if set, otherwise Source fallback.
func resolveRaw(rec mapping.Record, fm mapping.FieldMapping) (string, bool) {
	if len(fm.Join) > 0 {
		return resolveJoin(rec, fm.Join, fm.Separator)
	}
	return resolveSource(rec, fm.Source)
}

// resolveJoin concatenates the values found at each path, in order,
// skipping any that are missing or empty. Returns ("", false) if none
// resolved at all.
func resolveJoin(rec mapping.Record, paths []string, separator string) (string, bool) {
	if separator == "" {
		separator = ":"
	}
	var parts []string
	for _, p := range paths {
		if v, ok := rec.Lookup(p); ok && v != "" {
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, separator), true
}

// resolveSource tries each candidate source path in order and returns
// the first one that resolves to a non-empty value.
func resolveSource(rec mapping.Record, sources mapping.Sources) (string, bool) {
	for _, src := range sources {
		if src == "" {
			continue
		}
		if v, ok := rec.Lookup(src); ok && v != "" {
			return v, true
		}
	}
	return "", false
}
