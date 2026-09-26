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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veloxamen/network-job/internal/mapping"
)

// templatesDir is where the shipped mapping-config templates live —
// starting points meant to be reviewed and adjusted per environment
// before uploading the ones actually in use to
// gs://[PROJECT]-nw/config/ (not a directory meant to be uploaded
// wholesale) — one level up from this repo at the pipeline root (see
// ../../../README.md). Tests load directly from here — see
// internal/mapping/configcheck_test.go for the same pattern — rather
// than keeping a separate, easily-stale copy under testdata/.
const templatesDir = "../../../nw-config-templates"

// loadMapping loads and parses a mapping config template by name
// (without the .json extension) from templatesDir.
func loadMapping(t *testing.T, name string) *mapping.Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(templatesDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mapping.Parse(data)
	if err != nil {
		t.Fatalf("mapping.Parse: %v", err)
	}
	return cfg
}

// The three raw log samples below are the exact inputs this pipeline
// was built from — kept here as literals (rather than files under
// testdata/) alongside the assertions that depend on them, since they
// are small, per this package. nw-config-templates/*.json themselves
// are not duplicated the same way: tests read them from templatesDir
// directly instead of keeping a second, driftable copy.

const googleSampleJSON = `{
  "insertId": "abc123xyz",
  "jsonPayload": {
    "connection": {
      "src_ip": "192.168.1.10",
      "dest_ip": "10.0.0.5",
      "src_port": 54321,
      "dest_port": 443,
      "protocol": 6
    },
    "rule_details": {
      "reference": "network:default-allow-tcp",
      "action": "ALLOW"
    }
  },
  "logName": "projects/my-project/logs/compute.googleapis.com%2Ffirewall",
  "receiveTimestamp": "2026-09-16T12:00:00.000000000Z",
  "timestamp": "2026-09-16T11:59:59.123456Z"
}`

const awsFlowlogNDJSON = `{
    "firewall_name": "NFW-Firewall",
    "availability_zone": "ap-northeast-1a",
    "event_timestamp": "1733711193",
    "event": {
        "tcp": {
            "tcp_flags": "02",
            "syn": true
        },
        "app_proto": "unknown",
        "src_ip": "10.0.2.253",
        "src_port": 58088,
        "netflow": {
            "pkts": 5,
            "bytes": 300,
            "start": "2024-12-09T02:20:26.691827+0000",
            "end": "2024-12-09T02:20:42.110635+0000",
            "age": 16,
            "min_ttl": 126,
            "max_ttl": 126
        },
        "event_type": "netflow",
        "flow_id": 719578654249789,
        "dest_ip": "52.119.222.211",
        "proto": "TCP",
        "dest_port": 443,
        "timestamp": "2024-12-09T02:26:33.828371+0000"
    }
}`

const azureSampleJSON = `[
  {
    "time": "2024-07-13T12:45:00Z",
    "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myFirewall",
    "category": "AzureFirewallNetworkRule",
    "operationName": "AzureFirewallNetworkRuleLog",
    "properties": {
      "msg": "Deny",
      "protocol": "TCP",
      "sourceIP": "203.0.113.1",
      "destinationIP": "192.168.1.10",
      "sourcePort": "44321",
      "destinationPort": "3389",
      "action": "Deny",
      "ruleCollectionName": "RCNetRuleCollection",
      "ruleName": "DenyRDP",
      "direction": "Inbound",
      "priority": 100,
      "policy": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/firewallPolicies/myFirewallPolicy"
    }
  },
  {
    "time": "2024-07-13T12:50:00Z",
    "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myFirewall",
    "category": "AzureFirewallApplicationRule",
    "operationName": "AzureFirewallApplicationRuleLog",
    "properties": {
      "msg": "Allow",
      "protocol": "HTTP",
      "sourceIP": "198.51.100.2",
      "destinationIP": "10.0.0.5",
      "sourcePort": "51123",
      "destinationPort": "80",
      "action": "Allow",
      "ruleCollectionName": "RCAppRuleCollection",
      "ruleName": "AllowWebTraffic",
      "direction": "Outbound",
      "priority": 200,
      "policy": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/firewallPolicies/myFirewallPolicy"
    }
  },
  {
    "time": "2024-07-13T13:00:00Z",
    "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myFirewall",
    "category": "AzureFirewallThreatIntel",
    "operationName": "AzureFirewallThreatIntelLog",
    "properties": {
      "msg": "Alert",
      "threatType": "Malware",
      "sourceIP": "203.0.113.3",
      "destinationIP": "10.0.0.7",
      "sourcePort": "51333",
      "destinationPort": "80",
      "action": "Alert",
      "threatDescription": "Known malware site accessed",
      "policy": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/firewallPolicies/myFirewallPolicy"
    }
  },
  {
    "time": "2024-07-13T13:10:00Z",
    "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myFirewall",
    "category": "AzureFirewallNetworkRule",
    "operationName": "AzureFirewallNetworkRuleLog",
    "properties": {
      "msg": "Allow",
      "protocol": "UDP",
      "sourceIP": "192.0.2.1",
      "destinationIP": "10.0.0.8",
      "sourcePort": "60000",
      "destinationPort": "53",
      "action": "Allow",
      "ruleCollectionName": "RCNetRuleCollection",
      "ruleName": "AllowDNS",
      "direction": "Outbound",
      "priority": 300,
      "policy": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/firewallPolicies/myFirewallPolicy"
    }
  },
  {
    "time": "2024-07-13T13:15:00Z",
    "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myFirewall",
    "category": "AzureFirewallThreatIntel",
    "operationName": "AzureFirewallThreatIntelLog",
    "properties": {
      "msg": "Alert",
      "threatType": "BruteForce",
      "sourceIP": "198.51.100.4",
      "destinationIP": "192.168.1.10",
      "sourcePort": "49999",
      "destinationPort": "22",
      "action": "Alert",
      "threatDescription": "Brute force attack detected on SSH port",
      "policy": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/firewallPolicies/myFirewallPolicy"
    }
  },
  {
    "time": "2024-07-13T13:20:00Z",
    "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myFirewall",
    "category": "AzureFirewallApplicationRule",
    "operationName": "AzureFirewallApplicationRuleLog",
    "properties": {
      "msg": "Deny",
      "protocol": "HTTPS",
      "sourceIP": "192.0.2.5",
      "destinationIP": "10.0.0.9",
      "sourcePort": "52345",
      "destinationPort": "443",
      "action": "Deny",
      "ruleCollectionName": "RCAppRuleCollection",
      "ruleName": "DenySuspiciousHTTPS",
      "direction": "Outbound",
      "priority": 150,
      "policy": "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/myResourceGroup/providers/Microsoft.Network/firewallPolicies/myFirewallPolicy"
    }
  }
]`

func TestMapping_GoogleSample(t *testing.T) {
	cfg := loadMapping(t, "google")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var got []NetworkEvent
	err = p.Parse(strings.NewReader(googleSampleJSON), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v (line %q)", re.Err, re.Line)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.SrcIP != "192.168.1.10" || ev.DstIP != "10.0.0.5" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.SrcPort != 54321 || ev.DstPort != 443 {
		t.Errorf("unexpected ports: %+v", ev)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("expected TCP, got %q", ev.Protocol)
	}
	if ev.Action != "ALLOW" {
		t.Errorf("expected ALLOW, got %q", ev.Action)
	}
	if ev.RuleName != "network:default-allow-tcp" {
		t.Errorf("unexpected rule name %q", ev.RuleName)
	}
	if ev.DeviceName != "my-project" {
		t.Errorf("expected device_name my-project, got %q", ev.DeviceName)
	}
	if ev.LogType != "compute.googleapis.com/firewall" {
		t.Errorf("unexpected log_type %q", ev.LogType)
	}
	if ev.Direction != "" {
		t.Errorf("expected direction blank, got %q", ev.Direction)
	}
	if ev.EventTimestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}
	if ev.EventUUID == "" {
		t.Errorf("expected non-empty event_uuid")
	}
}

func TestMapping_AWSSample(t *testing.T) {
	cfg := loadMapping(t, "aws")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var got []NetworkEvent
	err = p.Parse(strings.NewReader(awsFlowlogNDJSON), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v (line %q)", re.Err, re.Line)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 event, got %d", len(got))
	}
	ev := got[0]
	if ev.DeviceName != "NFW-Firewall" {
		t.Errorf("unexpected device_name %q", ev.DeviceName)
	}
	if ev.SrcIP != "10.0.2.253" || ev.DstIP != "52.119.222.211" {
		t.Errorf("unexpected src/dst: %+v", ev)
	}
	if ev.SrcPort != 58088 || ev.DstPort != 443 {
		t.Errorf("unexpected ports: %+v", ev)
	}
	if ev.Protocol != "TCP" {
		t.Errorf("expected TCP, got %q", ev.Protocol)
	}
	if ev.LogType != "netflow" {
		t.Errorf("unexpected log_type %q", ev.LogType)
	}
	if ev.SentBytes != 300 {
		t.Errorf("expected sent_bytes 300, got %d", ev.SentBytes)
	}
	if ev.Duration != 16 {
		t.Errorf("expected duration 16, got %d", ev.Duration)
	}
	if ev.Direction != "" {
		t.Errorf("expected direction blank, got %q", ev.Direction)
	}
	if ev.EventTimestamp.IsZero() {
		t.Errorf("expected non-zero timestamp")
	}
}

func TestMapping_AzureSample(t *testing.T) {
	cfg := loadMapping(t, "azure")
	p, err := NewMappingParser(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var got []NetworkEvent
	err = p.Parse(strings.NewReader(azureSampleJSON), func(ev NetworkEvent) error {
		got = append(got, ev)
		return nil
	}, func(re RowError) {
		t.Errorf("unexpected row error: %v (line %q)", re.Err, re.Line)
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("expected 6 events, got %d", len(got))
	}

	first := got[0]
	if first.Action != "Deny" {
		t.Errorf("expected action Deny, got %q", first.Action)
	}
	if first.Direction != "Inbound" {
		t.Errorf("expected direction Inbound, got %q", first.Direction)
	}
	if first.SrcIP != "203.0.113.1" || first.DstIP != "192.168.1.10" {
		t.Errorf("unexpected src/dst: %+v", first)
	}
	if first.SrcPort != 44321 || first.DstPort != 3389 {
		t.Errorf("unexpected ports: %+v", first)
	}
	if first.RuleName != "RCNetRuleCollection/DenyRDP" {
		t.Errorf("unexpected rule name %q", first.RuleName)
	}
	if first.DeviceName != "myFirewall" {
		t.Errorf("expected device_name myFirewall, got %q", first.DeviceName)
	}
	if first.LogType != "AzureFirewallNetworkRule" {
		t.Errorf("unexpected log_type %q", first.LogType)
	}

	second := got[1]
	if second.Direction != "Outbound" {
		t.Errorf("expected direction Outbound, got %q", second.Direction)
	}

	threat := got[2]
	if threat.ThreatName != "Known malware site accessed" {
		t.Errorf("unexpected threat_name %q", threat.ThreatName)
	}
	if threat.Action != "Alert" {
		t.Errorf("expected action Alert, got %q", threat.Action)
	}
}
