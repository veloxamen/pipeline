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

// Package mapping implements the externalized field-mapping config that
// lets a new log vendor be onboarded by writing a JSON config file
// (config/<log_type>.json in the ingestion bucket) instead of a Go
// parser. It covers four source formats — "json" (nested, dot-path
// addressed), "kv" (FortiGate/Check Point style key=value lines), "csv"
// (header or positional columns), and "regex" (named capture groups,
// for formats that embed fields in free-text sentences, e.g. Cisco ASA
// syslog) — deliberately NOT a general expression language: only a
// fixed, reviewable set of transforms is supported (see
// ApplyTransform/ParseTimestamp), so a mapping config can never execute
// arbitrary code.
package mapping

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// Config is the top-level shape of config/<log_type>.json.
type Config struct {
	LogType string `json:"log_type"`
	// Format selects the parser: "json", "kv", "csv", or "regex".
	Format string `json:"format"`
	// RecordPath (JSON only, optional). Dot-path, within each decoded
	// top-level JSON value, to an array of individual records — e.g.
	// "records" for Azure Monitor's {"records":[...]} export shape.
	// Leave empty when each top-level JSON value already IS one record
	// (NDJSON), or when the top-level value is itself a bare array of
	// records.
	RecordPath string `json:"record_path,omitempty"`
	// Delimiter (KV and CSV). For KV: "space" (default) for
	// `key="value" key2=value2` style lines (Check Point Log Exporter),
	// or "comma" for `key=value,key2="value2"` style lines (FortiGate).
	// For CSV: the field separator — "comma" (default), "space", "tab",
	// or "pipe". "space" lets a whitespace-delimited positional format
	// (e.g. AWS's classic VPC Flow Log default format) be expressed as
	// csv + has_header:false + "col:N" sources, with no dedicated code.
	Delimiter string `json:"delimiter,omitempty"`
	// HasHeader (CSV only). If true, Source values in Fields are matched
	// against the file's header row (case-insensitive). If false, Source
	// values must be positional: "col:1" is the first column.
	HasHeader bool `json:"has_header,omitempty"`
	// Patterns (regex only). Each line is tried against these, in order;
	// the first match wins. A line matching none of them is a row error
	// (skipped, not guessed at) — there is no fallback pattern. See
	// RegexPattern.
	Patterns []RegexPattern `json:"patterns,omitempty"`
	// Fields lists every NetworkEvent column this config populates.
	// Any column not listed is left at its zero value. For "regex", a
	// Source is a capture group name (shared across every pattern in
	// Patterns — a pattern that has no such group, or didn't match at
	// all for this row, simply leaves that Source unresolved, same as a
	// missing KV key).
	Fields []FieldMapping `json:"fields"`
	// TemplateWarning, if set, is logged once (slog.Warn) the first time
	// this config is used to parse a file — e.g. to flag that it was
	// written without a real device sample to validate against. Purely
	// informational; never affects parsing behavior.
	TemplateWarning string `json:"template_warning,omitempty"`
}

// RegexPattern is one candidate pattern for "regex" format configs.
type RegexPattern struct {
	// Match is a Go regular expression (RE2 syntax) with named capture
	// groups, e.g. `(?P<src_ip>[0-9.]+)`. Each named group becomes a
	// value addressable from Fields[].source (or join), exactly like a
	// KV key.
	Match string `json:"match"`
	// Consts are static key/value pairs merged into the row's
	// addressable values alongside its capture groups — for a value
	// that's constant for every line matching this specific pattern
	// (typically log_type) rather than something to extract. A capture
	// group of the same name always wins over a Consts entry of that
	// name.
	Consts map[string]string `json:"consts,omitempty"`
}

// FieldMapping maps one NetworkEvent column (Target) to one or more
// candidate source locations, tried in order until one resolves to a
// non-empty value.
type FieldMapping struct {
	// Target is the NetworkEvent field's JSON tag name, e.g. "src_ip",
	// "event_timestamp", "direction". See parser.BuildEventFromMapping
	// for the full accepted set.
	Target string `json:"target"`
	// Source is one path, or a list of paths tried in order (first
	// non-empty wins). JSON: dot-separated ("event.src_ip"). KV: the raw
	// key name. CSV: a header name, or "col:N" (1-indexed) when
	// HasHeader is false. Regex: a named capture group. Omit or leave
	// empty (e.g. []) for a field with no source in this vendor's log —
	// combine with Default to hard-code a constant, or leave both empty
	// to leave the column blank.
	Source Sources `json:"source,omitempty"`
	// Join, as an alternative to Source, concatenates the values found
	// at multiple paths (in order, skipping any that are missing/empty)
	// with Separator (default ":") — e.g. FortiGate's log_type is
	// type+":"+subtype ("traffic:forward"), and Azure's rule_name is
	// ruleCollectionName+"/"+ruleName. Mutually exclusive with Source.
	// If every path is missing/empty, this behaves like Source: falls
	// through to Default.
	Join      []string `json:"join,omitempty"`
	Separator string   `json:"separator,omitempty"`
	// ValueMap, if set, looks up the value resolved from Source/Join
	// verbatim and substitutes the mapped value if found — e.g. Cisco
	// ASA's access-list messages log "permitted"/"denied", mapped here
	// to "Allow"/"Deny" to match every other vendor's Action values. A
	// resolved value with no entry in ValueMap passes through
	// unchanged (not an error) — this lets one Fields entry serve
	// multiple regex Patterns that populate the same Target with
	// different vocabularies, translating only the ones that need it.
	// Never applied to Default (Default is already the literal desired
	// value).
	ValueMap map[string]string `json:"value_map,omitempty"`
	// Transform is applied to whichever source value resolved (after
	// ValueMap, if any). Empty means "use as-is". See ApplyTransform and
	// ParseTimestamp for the fixed set of supported values — unknown
	// values are a config error, not silently ignored, so a typo is
	// caught immediately rather than producing silently-wrong data.
	Transform string `json:"transform,omitempty"`
	// Default is used verbatim (never run through ValueMap or
	// Transform) when every Source entry is missing or resolves to an
	// empty string. Also how a constant value (e.g. a fixed log_type
	// label) is set: give no Source and only a Default.
	Default string `json:"default,omitempty"`
}

// Sources accepts either a bare JSON string or an array of strings in
// the config file, always normalized to a []string.
type Sources []string

func (s *Sources) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = Sources{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err == nil {
		*s = Sources(multi)
		return nil
	}
	return fmt.Errorf("source must be a string or array of strings")
}

// Parse validates and decodes a mapping config file's raw bytes.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid mapping JSON: %w", err)
	}
	switch cfg.Format {
	case "json", "kv", "csv", "regex":
	default:
		return nil, fmt.Errorf("unsupported format %q (must be json, kv, csv, or regex)", cfg.Format)
	}
	if len(cfg.Fields) == 0 {
		return nil, fmt.Errorf("mapping config has no fields")
	}
	for _, fm := range cfg.Fields {
		if fm.Target == "" {
			return nil, fmt.Errorf("field mapping missing target")
		}
		if len(fm.Source) > 0 && len(fm.Join) > 0 {
			return nil, fmt.Errorf("field %q: source and join are mutually exclusive", fm.Target)
		}
	}
	if cfg.Format == "csv" {
		switch cfg.Delimiter {
		case "", "comma", "space", "tab", "pipe":
		default:
			return nil, fmt.Errorf("unsupported csv delimiter %q (must be comma, space, tab, or pipe)", cfg.Delimiter)
		}
	}
	if cfg.Format == "regex" {
		if len(cfg.Patterns) == 0 {
			return nil, fmt.Errorf("regex format requires at least one pattern")
		}
		for i, pat := range cfg.Patterns {
			if _, err := regexp.Compile(pat.Match); err != nil {
				return nil, fmt.Errorf("pattern %d: invalid regex %q: %w", i, pat.Match, err)
			}
		}
	}
	return &cfg, nil
}

// CSVComma returns the rune encoding/csv.Reader.Comma should be set to
// for a config's Delimiter value ("" and "comma" both mean ',').
func CSVComma(delimiter string) rune {
	switch delimiter {
	case "space":
		return ' '
	case "tab":
		return '\t'
	case "pipe":
		return '|'
	default:
		return ','
	}
}
