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
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/veloxamen/network-job/internal/mapping"
)

// MappingKVParser parses one-line-per-record key=value logs using an
// externally supplied mapping.Config (format: "kv"). Two token styles
// are supported via Cfg.Delimiter:
//
//   - "comma" (default if empty): key=value,key2="value2",... — the
//     comma-separated style FortiGate uses.
//   - "space": key="value" key2=value2 ... — the space-separated style
//     Check Point's Log Exporter "generic" format uses. Quoted values
//     may contain spaces; unquoted ones may not.
type MappingKVParser struct {
	Cfg *mapping.Config
}

func (p MappingKVParser) Parse(r io.Reader, emit func(NetworkEvent) error, onRowError func(RowError)) error {
	warnIfTemplate(p.Cfg)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	spaceDelimited := p.Cfg.Delimiter == "space"

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var kv map[string]string
		var err error
		if spaceDelimited {
			kv = tokenizeSpaceKV(line)
		} else {
			kv, err = tokenizeCommaKV(line)
			if err != nil {
				onRowError(RowError{LineNumber: lineNum, Line: line, Err: err})
				continue
			}
		}

		ev, err := BuildEventFromMapping(mapping.NewFlatRecord(kv), p.Cfg)
		if err != nil {
			onRowError(RowError{LineNumber: lineNum, Line: line, Err: err})
			continue
		}
		ev.EventUUID = hashRawLine(line)
		if err := emit(ev); err != nil {
			return fmt.Errorf("emit line %d: %w", lineNum, err)
		}
	}
	return scanner.Err()
}

// tokenizeCommaKV splits a FortiGate-style comma-separated key=value
// line via encoding/csv (so a comma inside a quoted value doesn't split
// the field), then splits each field on the first "=".
func tokenizeCommaKV(line string) (map[string]string, error) {
	cr := csv.NewReader(strings.NewReader(line))
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	fields, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("csv tokenize: %w", err)
	}
	kv := make(map[string]string, len(fields))
	for _, f := range fields {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return kv, nil
}

// tokenizeSpaceKV splits a Check-Point-style space-separated
// key="value" line, respecting double quotes so a quoted value may
// contain spaces.
func tokenizeSpaceKV(line string) map[string]string {
	kv := make(map[string]string)
	var key, val strings.Builder
	inValue, inQuotes := false, false

	flush := func() {
		if key.Len() > 0 {
			kv[key.String()] = strings.Trim(val.String(), `"`)
		}
		key.Reset()
		val.Reset()
		inValue = false
	}

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			if inValue {
				val.WriteRune(r)
			}
		case r == ' ' && !inQuotes:
			flush()
		case r == '=' && !inValue && !inQuotes:
			inValue = true
		case inValue:
			val.WriteRune(r)
		default:
			key.WriteRune(r)
		}
	}
	flush()
	return kv
}
