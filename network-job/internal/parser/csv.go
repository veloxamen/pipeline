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
	"strings"

	"github.com/veloxamen/network-job/internal/mapping"
)

// MappingCSVParser parses a CSV log format using an externally supplied
// mapping.Config (format: "csv"). If Cfg.HasHeader is true, Source
// values in the config are matched against the file's own header row
// (case-insensitive) — this is the safe default, since it doesn't
// depend on guessing a vendor's column order. If false, Source values
// must be "col:N" (1-indexed); use this only when the export genuinely
// has no header row and the column order for that specific export is
// known and has been confirmed against a real file.
type MappingCSVParser struct {
	Cfg *mapping.Config
}

func (p MappingCSVParser) Parse(r io.Reader, emit func(NetworkEvent) error, onRowError func(RowError)) error {
	warnIfTemplate(p.Cfg)

	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.Comma = mapping.CSVComma(p.Cfg.Delimiter)

	var header []string
	lineNum := 0
	if p.Cfg.HasHeader {
		h, err := cr.Read()
		if err == io.EOF {
			return fmt.Errorf("empty file, no header row")
		}
		if err != nil {
			return fmt.Errorf("read header: %w", err)
		}
		header = h
		lineNum++
	}

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

		ev, err := BuildEventFromMapping(mapping.NewCSVRecord(header, fields), p.Cfg)
		if err != nil {
			onRowError(RowError{LineNumber: lineNum, Line: strings.Join(fields, ","), Err: err})
			continue
		}
		ev.EventUUID = hashRawLine(strings.Join(fields, ","))
		if err := emit(ev); err != nil {
			return fmt.Errorf("emit line %d: %w", lineNum, err)
		}
	}
}
