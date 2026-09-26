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

// Package parser converts raw network log files into NetworkEvent rows.
package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/veloxamen/network-job/internal/mapping"
)

// NetworkEvent represents a single row in the network_events table.
//
// Field set follows the normalized multi-vendor schema (event_timestamp,
// device_name, log_type, ing_if/egr_if, vpn_remote_ip, nat_src_*/nat_dst_*,
// user_name, app_name, sent_bytes/rcvd_bytes, duration, threat_name), plus
// rule_name (policyname) kept beyond that schema alongside rule_id rather
// than collapsed into it. raw_line and log_source were dropped: raw files
// remain greppable in GCS, and log_source wasn't worth the extra column.
// nat_dst_port was added alongside nat_dst_ip for DNAT/port-forward symmetry
// with nat_src_ip/nat_src_port. event_uuid is a deterministic hash for
// cross-table correlation (see hashRawLine).
//
// direction (Inbound/Outbound) was added between rule_name and src_ip.
// Not every vendor's log format states this explicitly:
//   - Azure Firewall logs carry it directly (properties.direction) and it
//     is mapped 1:1.
//   - Check Point logs carry an equivalent field (i/f_dir) and it is
//     mapped 1:1.
//   - FortiGate, AWS, and Google Cloud sample logs used to build this
//     pipeline had no equivalent field, so Direction is left empty ("") for
//     those parsers. It is intentionally NOT guessed/derived from interface
//     names or zones, since that would be unreliable. Populate it by hand
//     later (e.g. a follow-up UPDATE keyed on ing_if/egr_if or rule_name)
//     once the real mapping for each environment is known.
type NetworkEvent struct {
	EventTimestamp time.Time `json:"event_timestamp"`
	DeviceName     string    `json:"device_name"`
	LogType        string    `json:"log_type"`
	Action         string    `json:"action"`
	RuleID         string    `json:"rule_id"`
	RuleName       string    `json:"rule_name"`
	Direction      string    `json:"direction"`
	SrcIP          string    `json:"src_ip"`
	SrcPort        int64     `json:"src_port"`
	DstIP          string    `json:"dst_ip"`
	DstPort        int64     `json:"dst_port"`
	Protocol       string    `json:"protocol"`
	IngIf          string    `json:"ing_if"`
	EgrIf          string    `json:"egr_if"`
	VPNRemoteIP    string    `json:"vpn_remote_ip"`
	NatSrcIP       string    `json:"nat_src_ip"`
	NatSrcPort     int64     `json:"nat_src_port"`
	NatDstIP       string    `json:"nat_dst_ip"`
	NatDstPort     int64     `json:"nat_dst_port"`
	UserName       string    `json:"user_name"`
	AppName        string    `json:"app_name"`
	SentBytes      int64     `json:"sent_bytes"`
	RcvdBytes      int64     `json:"rcvd_bytes"`
	Duration       int64     `json:"duration"`
	ThreatName     string    `json:"threat_name"`
	EventUUID      string    `json:"event_uuid"`
}

// hashRawLine derives event_uuid as the SHA256 hex digest of the raw,
// pre-parse input line (the exact CSV/KV tokens read off disk, rejoined
// with ","). Matches timeline_events' event_uuid scheme (also a SHA256
// digest) for a single Looker-facing tags table keyed on event_uuid across
// both tables.
//
// Replaces an earlier natural-key-fields version that hashed a chosen
// subset of fields (letting rows sharing all of them collapse onto one
// uuid, intentionally). This is simpler — no field list to keep in sync
// with the schema — but only collapses byte-identical raw lines: two rows
// that share some fields but differ in any other raw field now get
// distinct uuids. That's fine for reprocessing idempotency (re-reading the
// same file twice collapses correctly); it just means "near-duplicate"
// rows are no longer merged automatically — go back to hashing selected
// fields if that's needed later.
func hashRawLine(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// RowError describes a skipped input row.
type RowError struct {
	LineNumber int
	Line       string
	Err        error
}

// Parser defines the interface for streaming and parsing raw log files.
type Parser interface {
	Parse(r io.Reader, emit func(NetworkEvent) error, onRowError func(RowError)) error
}

// registry holds parsers that ship as Go code rather than an externally
// configured mapping. It is empty: every log type — including
// generic_csv, fortigate, and cisco_asa, which used to be dedicated Go
// parsers here — is now onboarded by writing a config/<log_type>.json
// mapping file instead (starting from a reviewed copy of the matching
// template in nw-config-templates/ at the pipeline root). The "regex"
// format (named capture groups) is what let the last holdout, Cisco
// ASA, move out of Go: it covers syslog-style formats that embed
// fields inside free-text sentences rather than JSON/KV/CSV structure.
// See
// NewMappingParser and the internal/mapping package.
//
// The registry itself is kept (rather than deleted along with its last
// entry) as the documented escape hatch for a genuinely
// mapping-config-inexpressible format, should one ever come up; adding
// to it is expected to be rare to never.
var registry = map[string]Parser{}

// Lookup returns the Parser registered for logType, or false if none
// exists in the static registry. A miss here does not mean logType is
// invalid — the caller (cmd/network-job) falls back to loading
// config/<log_type>.json and building a mapping-driven parser with
// NewMappingParser.
func Lookup(logType string) (Parser, bool) {
	p, ok := registry[logType]
	return p, ok
}

// NewMappingParser builds the Parser for an externally supplied mapping
// config, selecting the JSON/KV/CSV/regex implementation by cfg.Format.
func NewMappingParser(cfg *mapping.Config) (Parser, error) {
	switch cfg.Format {
	case "json":
		return MappingJSONParser{Cfg: cfg}, nil
	case "kv":
		return MappingKVParser{Cfg: cfg}, nil
	case "csv":
		return MappingCSVParser{Cfg: cfg}, nil
	case "regex":
		return NewMappingRegexParser(cfg)
	default:
		return nil, fmt.Errorf("unsupported mapping format %q", cfg.Format)
	}
}

// atoiOrZero parses s as a base-10 int64, returning 0 (rather than an
// error) if s is empty or not a valid integer — used for numeric
// NetworkEvent columns (ports, byte counts, duration) where a
// missing/unparsable source value should read as "not set" rather than
// fail the whole row.
func atoiOrZero(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}
