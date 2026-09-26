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

// These tests exercise the CSV/KV mapping parsers against hand-built
// fixture lines for the two vendors that have NO real device sample
// (Palo Alto, Check Point) — see the pipeline repo's top-level
// README.md. They
// confirm the mapping mechanism works correctly against the assumed
// format; they do NOT confirm the assumed format matches a real
// device's actual output.
package parser

import (
	"strings"
	"testing"

	"github.com/veloxamen/network-job/internal/mapping"
)

func mustParseMapping(t *testing.T, jsonText string) *mapping.Config {
	t.Helper()
	cfg, err := mapping.Parse([]byte(jsonText))
	if err != nil {
		t.Fatalf("mapping.Parse: %v", err)
	}
	return cfg
}

func TestMappingCSV_PaloAltoTemplate(t *testing.T) {
	cfg := mustParseMapping(t, `{
		"log_type": "paloalto",
		"format": "csv",
		"has_header": true,
		"fields": [
			{ "target": "event_timestamp", "source": "Receive Time", "transform": "layout:2006/01/02 15:04:05" },
			{ "target": "src_ip", "source": "Source address" },
			{ "target": "dst_ip", "source": "Destination address" },
			{ "target": "src_port", "source": "Source Port" },
			{ "target": "dst_port", "source": "Destination Port" },
			{ "target": "protocol", "source": "IP Protocol", "transform": "upper" },
			{ "target": "action", "source": "Action" },
			{ "target": "rule_name", "source": "Rule" },
			{ "target": "sent_bytes", "source": "Bytes Sent" },
			{ "target": "rcvd_bytes", "source": "Bytes Received" }
		]
	}`)
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	csvData := "Receive Time,Source address,Destination address,Source Port,Destination Port,IP Protocol,Action,Rule,Bytes Sent,Bytes Received\n" +
		"2024/07/13 12:45:00,10.0.0.5,8.8.8.8,54321,443,tcp,allow,Allow-Web,1024,2048\n"

	var got []NetworkEvent
	err = p.Parse(strings.NewReader(csvData), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v", re.Err)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.SrcIP != "10.0.0.5" || ev.DstIP != "8.8.8.8" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("expected TCP, got %q", ev.Protocol)
	}
	if ev.RuleName != "Allow-Web" {
		t.Errorf("unexpected rule name %q", ev.RuleName)
	}
	if ev.SentBytes != 1024 || ev.RcvdBytes != 2048 {
		t.Errorf("unexpected bytes: %+v", ev)
	}
	if ev.EventTimestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}
}

func TestMappingKV_CheckPointTemplate(t *testing.T) {
	cfg := mustParseMapping(t, `{
		"log_type": "checkpoint",
		"format": "kv",
		"delimiter": "space",
		"fields": [
			{ "target": "event_timestamp", "source": "time", "transform": "unix" },
			{ "target": "device_name", "source": ["product", "orig"] },
			{ "target": "action", "source": "action" },
			{ "target": "rule_id", "source": "rule_uid" },
			{ "target": "rule_name", "source": "rule_name" },
			{ "target": "direction", "source": "i/f_dir" },
			{ "target": "src_ip", "source": "src" },
			{ "target": "src_port", "source": "s_port" },
			{ "target": "dst_ip", "source": "dst" },
			{ "target": "dst_port", "source": ["dst_port", "service"] },
			{ "target": "protocol", "source": "proto", "transform": "upper" },
			{ "target": "ing_if", "source": "i/f_name" },
			{ "target": "sent_bytes", "source": "bytes" }
		]
	}`)
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	line := `time=1700000000 action="Accept" product="VPN-1 & FireWall-1" i/f_dir="inbound" i/f_name="eth0" proto="tcp" src="10.0.0.5" s_port="12345" dst="8.8.8.8" service="443" rule_name="Allow-Web" rule_uid="{abc-123}" bytes="1024"`

	var got []NetworkEvent
	err = p.Parse(strings.NewReader(line), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v", re.Err)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.Direction != "inbound" {
		// Note: unlike the earlier hand-rolled CheckPointParser, the
		// generic mapping system does not special-case "inbound" ->
		// "Inbound" — it copies the raw value verbatim (no capitalization
		// transform exists, deliberately, to keep the transform set
		// small and reviewable). Add a "titlecase" transform, or
		// normalize upstream, if canonical casing matters.
		t.Errorf("expected raw value 'inbound', got %q", ev.Direction)
	}
	if ev.SrcIP != "10.0.0.5" || ev.DstIP != "8.8.8.8" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.DstPort != 443 {
		t.Errorf("expected dst_port 443 (from service=), got %d", ev.DstPort)
	}
	if ev.DeviceName != "VPN-1 & FireWall-1" {
		t.Errorf("unexpected device_name %q", ev.DeviceName)
	}
	if ev.RuleName != "Allow-Web" || ev.RuleID != "{abc-123}" {
		t.Errorf("unexpected rule fields: %+v", ev)
	}
	if ev.EventTimestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}
}

func TestMappingRegex_CiscoASASample_ACL(t *testing.T) {
	cfg := loadMapping(t, "cisco_asa")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	line := `Jul 15 2024 10:00:00 fw1 %ASA-6-106100: access-list ACL_IN permitted tcp inside/192.168.1.10(12345) -> outside/8.8.8.8(53)`
	var got []NetworkEvent
	err = p.Parse(strings.NewReader(line), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v", re.Err)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.Action != "Allow" {
		t.Errorf("expected value_map to translate permitted->Allow, got %q", ev.Action)
	}
	if ev.RuleName != "ACL_IN" {
		t.Errorf("unexpected rule name %q", ev.RuleName)
	}
	if ev.LogType != "access-list" {
		t.Errorf("expected pattern-level const log_type=access-list, got %q", ev.LogType)
	}
	if ev.SrcIP != "192.168.1.10" || ev.DstIP != "8.8.8.8" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("expected TCP, got %q", ev.Protocol)
	}
	if ev.EventTimestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}
}

func TestMappingRegex_CiscoASASample_Connection(t *testing.T) {
	cfg := loadMapping(t, "cisco_asa")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	line := `Jul 15 2024 10:00:05 fw1 %ASA-6-302013: Built outbound TCP connection 123 for outside:8.8.8.8/443 (8.8.8.8/443) to inside:10.0.0.5/54321 (10.0.0.5/54321)`
	var got []NetworkEvent
	err = p.Parse(strings.NewReader(line), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v", re.Err)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.Direction != "Outbound" {
		t.Errorf("expected value_map to translate outbound->Outbound, got %q", ev.Direction)
	}
	if ev.Action != "Built" {
		// This pattern's "action" vocabulary (Built/Teardown) has no
		// entry in the shared value_map, so it passes through unchanged
		// — same Fields entry the ACL pattern uses, different pattern's
		// vocabulary.
		t.Errorf("expected Built to pass through unchanged, got %q", ev.Action)
	}
	if ev.LogType != "connection" {
		t.Errorf("expected pattern-level const log_type=connection, got %q", ev.LogType)
	}
	if ev.SrcIP != "8.8.8.8" || ev.DstIP != "10.0.0.5" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
}

func TestMappingRegex_CiscoASASample_UnknownLineSkipped(t *testing.T) {
	cfg := loadMapping(t, "cisco_asa")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var rowErrs int
	err = p.Parse(strings.NewReader("this is not an ASA traffic log line"), func(ev NetworkEvent) error {
		t.Errorf("did not expect an event to be emitted")
		return nil
	}, func(re RowError) {
		rowErrs++
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rowErrs != 1 {
		t.Fatalf("expected 1 row error, got %d", rowErrs)
	}
}
