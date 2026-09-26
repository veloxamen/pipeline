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
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// GenericCSVParser handles header-based CSV log exports.
type GenericCSVParser struct{}

func (GenericCSVParser) Parse(r io.Reader, emit func(NetworkEvent) error, onRowError func(RowError)) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1

	header, err := cr.Read()
	if err == io.EOF {
		return fmt.Errorf("empty file, no header row")
	}
	if err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	columns := make([]string, len(header))
	for i, h := range header {
		columns[i] = canonicalColumn(h)
	}

	lineNum := 1
	for {
		lineNum++
		fields, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			onRowError(RowError{LineNumber: lineNum, Err: fmt.Errorf("csv read: %w", err)})
			continue
		}

		row := make(map[string]string, len(columns))
		for i, v := range fields {
			if i >= len(columns) || columns[i] == "" {
				continue
			}
			row[columns[i]] = v
		}

		ev, err := genericEventFromRow(row)
		if err != nil {
			onRowError(RowError{
				LineNumber: lineNum,
				Line:       strings.Join(fields, ","),
				Err:        err,
			})
			continue
		}
		ev.EventUUID = hashRawLine(strings.Join(fields, ","))
		if err := emit(ev); err != nil {
			return fmt.Errorf("emit line %d: %w", lineNum, err)
		}
	}
}

// canonicalColumn maps a raw header cell to a canonical field name.
func canonicalColumn(header string) string {
	switch strings.ToLower(strings.TrimSpace(header)) {
	case "event_timestamp", "event_datetime", "timestamp", "datetime", "time":
		return "event_timestamp"
	case "device_name", "devname", "hostname", "device":
		return "device_name"
	case "log_type", "type", "subtype":
		return "log_type"
	case "src_ip", "source_ip", "srcip", "source address":
		return "src_ip"
	case "dst_ip", "destination_ip", "dstip", "destination address":
		return "dst_ip"
	case "src_port", "source_port", "srcport":
		return "src_port"
	case "dst_port", "destination_port", "dstport":
		return "dst_port"
	case "protocol", "proto":
		return "protocol"
	case "action":
		return "action"
	case "ing_if", "ingress_interface", "srcintf", "interface":
		return "ing_if"
	case "egr_if", "egress_interface", "dstintf":
		return "egr_if"
	case "vpn_remote_ip", "remip":
		return "vpn_remote_ip"
	case "nat_src_ip", "translated_source_ip", "tranip":
		return "nat_src_ip"
	case "nat_src_port", "translated_source_port", "tranport":
		return "nat_src_port"
	case "nat_dst_ip", "translated_destination_ip", "dstinip", "trandstip":
		return "nat_dst_ip"
	case "nat_dst_port", "translated_destination_port", "trandstport":
		return "nat_dst_port"
	case "user_name", "user", "username", "unauthuser":
		return "user_name"
	case "app_name", "app", "application", "appcat":
		return "app_name"
	case "bytes_sent", "sent_bytes", "sentbyte":
		return "sent_bytes"
	case "bytes_received", "received_bytes", "rcvd_bytes", "rcvdbyte":
		return "rcvd_bytes"
	case "duration":
		return "duration"
	case "threat_name", "threat", "msg":
		return "threat_name"
	case "rule_id", "policy_id", "policyid":
		return "rule_id"
	case "rule_name", "policy_name", "policyname", "rule":
		return "rule_name"
	default:
		return ""
	}
}

// genericEventFromRow constructs a NetworkEvent from a mapped row.
func genericEventFromRow(row map[string]string) (NetworkEvent, error) {
	ts, ok := row["event_timestamp"]
	if !ok || ts == "" {
		return NetworkEvent{}, fmt.Errorf("no recognized timestamp column")
	}
	t, err := parseGenericTimestamp(ts)
	if err != nil {
		return NetworkEvent{}, fmt.Errorf("parse timestamp %q: %w", ts, err)
	}

	ev := NetworkEvent{
		EventTimestamp: t,
		DeviceName:     row["device_name"],
		LogType:        row["log_type"],
		Action:         row["action"],
		RuleID:         row["rule_id"],
		RuleName:       row["rule_name"],
		SrcIP:          row["src_ip"],
		SrcPort:        atoiOrZero(row["src_port"]),
		DstIP:          row["dst_ip"],
		DstPort:        atoiOrZero(row["dst_port"]),
		Protocol:       row["protocol"],
		IngIf:          row["ing_if"],
		EgrIf:          row["egr_if"],
		VPNRemoteIP:    row["vpn_remote_ip"],
		NatSrcIP:       row["nat_src_ip"],
		NatSrcPort:     atoiOrZero(row["nat_src_port"]),
		NatDstIP:       row["nat_dst_ip"],
		NatDstPort:     atoiOrZero(row["nat_dst_port"]),
		UserName:       row["user_name"],
		AppName:        row["app_name"],
		SentBytes:      atoiOrZero(row["sent_bytes"]),
		RcvdBytes:      atoiOrZero(row["rcvd_bytes"]),
		Duration:       atoiOrZero(row["duration"]),
		ThreatName:     row["threat_name"],
	}
	return ev, nil
}

// parseGenericTimestamp parses a timestamp string using supported formats.
func parseGenericTimestamp(s string) (time.Time, error) {
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(sec, 0).UTC(), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006/01/02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp format")
}
