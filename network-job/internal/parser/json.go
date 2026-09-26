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
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/veloxamen/network-job/internal/mapping"
)

// MappingJSONParser parses any JSON-based log format using an
// externally supplied mapping.Config (format: "json"). It handles three
// shapes without any vendor-specific code:
//
//   - NDJSON: one record object per top-level JSON value (AWS Network
//     Firewall, Google Cloud Logging sinks). record_path empty.
//   - A bare top-level array of records (e.g. an ad-hoc export).
//     record_path empty.
//   - An envelope object wrapping an array of records under a known key
//     (Azure Monitor's {"records":[...]}), possibly repeated one
//     envelope per flush in the same file. record_path: "records".
//
// A streaming json.Decoder is used rather than a line scanner, so it
// also tolerates pretty-printed (multi-line) JSON, not just minified
// NDJSON.
type MappingJSONParser struct {
	Cfg *mapping.Config
}

func (p MappingJSONParser) Parse(r io.Reader, emit func(NetworkEvent) error, onRowError func(RowError)) error {
	warnIfTemplate(p.Cfg)

	dec := json.NewDecoder(r)

	rowNum := 0
	for {
		var top json.RawMessage
		if err := dec.Decode(&top); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("decode top-level JSON value %d: %w", rowNum+1, err)
		}

		records, err := extractJSONRecords(top, p.Cfg.RecordPath)
		if err != nil {
			rowNum++
			onRowError(RowError{LineNumber: rowNum, Line: string(top), Err: err})
			continue
		}

		for _, raw := range records {
			rowNum++
			line := strings.TrimSpace(string(raw))

			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				onRowError(RowError{LineNumber: rowNum, Line: line, Err: fmt.Errorf("json unmarshal: %w", err)})
				continue
			}

			ev, err := BuildEventFromMapping(mapping.NewJSONRecord(doc), p.Cfg)
			if err != nil {
				onRowError(RowError{LineNumber: rowNum, Line: line, Err: err})
				continue
			}
			ev.EventUUID = hashRawLine(line)
			if err := emit(ev); err != nil {
				return fmt.Errorf("emit record %d: %w", rowNum, err)
			}
		}
	}
}

// extractJSONRecords normalizes one decoded top-level JSON value into
// individual record byte-slices (preserving exact original bytes for
// EventUUID hashing), per the three shapes described above. record_path
// only applies when the top-level value is a JSON object — a bare
// top-level array is always treated as a list of records outright,
// since there's no envelope object to look inside.
func extractJSONRecords(top json.RawMessage, recordPath string) ([]json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(top))
	if trimmed == "" {
		return nil, nil
	}

	if recordPath != "" && trimmed[0] == '{' {
		cur := top
		parts := strings.Split(recordPath, ".")
		for i, part := range parts {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(cur, &obj); err != nil {
				return nil, fmt.Errorf("record_path %q: expected an object while resolving %q: %w", recordPath, part, err)
			}
			next, ok := obj[part]
			if !ok {
				return nil, fmt.Errorf("record_path %q: key %q not found", recordPath, part)
			}
			if i == len(parts)-1 {
				var arr []json.RawMessage
				if err := json.Unmarshal(next, &arr); err != nil {
					// Not an array at the end of record_path — treat the
					// resolved value itself as a single record.
					return []json.RawMessage{next}, nil
				}
				return arr, nil
			}
			cur = next
		}
	}

	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(top, &arr); err != nil {
			return nil, fmt.Errorf("unmarshal array: %w", err)
		}
		return arr, nil
	}
	return []json.RawMessage{top}, nil
}
