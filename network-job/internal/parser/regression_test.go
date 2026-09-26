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
	"strings"
	"testing"
)

// TestMappingKV_FortiGateSample confirms the FortiGate mapping config
// template (nw-config-templates/fortigate.json) reproduces what the old
// FortiGateKVParser used to do, including the log_type join
// (type+":"+subtype) and Direction staying blank when the log has no
// such field.
//
// One behavior actually changed for the better in this migration: the
// old FortiGateKVParser used encoding/csv with default (non-lazy) quote
// handling, which rejected a literal `"` that didn't sit at the very
// start of a field — real FortiGate exports' devname="FGT1" style would
// have tripped that. The generic KV tokenizer used here sets
// LazyQuotes, so this fixture uses quoted values (as a real export
// would) and it Just Works.
func TestMappingKV_FortiGateSample(t *testing.T) {
	cfg := loadMapping(t, "fortigate")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	line := `itime=1700000000,devname="FGT1",type="traffic",subtype="forward",action="accept",policyid="1",policyname="Allow-Web",srcip=10.0.0.5,srcport=54321,dstip=8.8.8.8,dstport=443,proto=6,srcintf="port1",dstintf="port2"` + "\n"
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
	if ev.DeviceName != "FGT1" {
		t.Errorf("unexpected device_name %q", ev.DeviceName)
	}
	if ev.LogType != "traffic:forward" {
		t.Errorf("expected joined log_type traffic:forward, got %q", ev.LogType)
	}
	if ev.Direction != "" {
		t.Errorf("expected empty direction (not present in sample), got %q", ev.Direction)
	}
	if ev.SrcIP != "10.0.0.5" || ev.DstIP != "8.8.8.8" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("expected TCP, got %q", ev.Protocol)
	}
	if ev.RuleID != "1" || ev.RuleName != "Allow-Web" {
		t.Errorf("unexpected rule fields: %+v", ev)
	}
}

// TestMappingCSV_GenericCSVSample confirms the generic_csv mapping
// template (nw-config-templates/generic_csv.json) reproduces what the old
// dedicated GenericCSVParser used to do: header-alias matching (e.g.
// "time" -> event_timestamp) and multi-format timestamp auto-detection.
func TestMappingCSV_GenericCSVSample(t *testing.T) {
	cfg := loadMapping(t, "generic_csv")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	csvData := "time,src_ip,dst_ip,src_port,dst_port,protocol,action,direction\n" +
		"2024-07-13 12:45:00,10.0.0.5,8.8.8.8,54321,443,TCP,allow,Outbound\n"
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
	if got[0].Direction != "Outbound" {
		t.Errorf("expected Outbound, got %q", got[0].Direction)
	}
}

// TestMappingCSV_AWSVPCFlowLog_SpaceDelimited demonstrates that the
// classic (non-Suricata) AWS VPC Flow Log default format — normally a
// bespoke space-delimited positional parser — needs no dedicated Go
// code at all under the mapping system: it's just csv with
// delimiter:"space" and has_header:false.
func TestMappingCSV_AWSVPCFlowLog_SpaceDelimited(t *testing.T) {
	cfg := mustParseMapping(t, `{
		"log_type": "aws_vpc_flow",
		"format": "csv",
		"delimiter": "space",
		"has_header": false,
		"fields": [
			{ "target": "event_timestamp", "source": "col:11", "transform": "unix" },
			{ "target": "device_name", "source": "col:3" },
			{ "target": "src_ip", "source": "col:4" },
			{ "target": "dst_ip", "source": "col:5" },
			{ "target": "src_port", "source": "col:6" },
			{ "target": "dst_port", "source": "col:7" },
			{ "target": "protocol", "source": "col:8", "transform": "proto_num" },
			{ "target": "sent_bytes", "source": "col:10" },
			{ "target": "action", "source": "col:13" }
		]
	}`)
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	line := "2 123456789010 eni-1234abcd 10.0.1.5 10.0.2.6 55554 443 6 10 800 1620000000 1620000060 ACCEPT OK\n"
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
	if ev.DeviceName != "eni-1234abcd" {
		t.Errorf("unexpected device_name %q", ev.DeviceName)
	}
	if ev.SrcIP != "10.0.1.5" || ev.DstIP != "10.0.2.6" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("expected TCP, got %q", ev.Protocol)
	}
	if ev.Action != "ACCEPT" {
		t.Errorf("expected ACCEPT, got %q", ev.Action)
	}
	if ev.SentBytes != 800 {
		t.Errorf("expected sent_bytes 800, got %d", ev.SentBytes)
	}
}
