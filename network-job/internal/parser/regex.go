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
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/veloxamen/network-job/internal/mapping"
)

// MappingRegexParser parses one-line-per-record logs whose fields are
// embedded in free-text sentences rather than JSON/KV/CSV structure
// (e.g. Cisco ASA syslog: "%ASA-6-106100: access-list ACL_IN permitted
// tcp ..."), using an externally supplied mapping.Config
// (format: "regex").
//
// Each configured pattern (Cfg.Patterns) is tried against every line, in
// order; the first one whose regex matches wins. That pattern's named
// capture groups (plus any Consts it declares) become the set of values
// Cfg.Fields can pull from — addressed exactly like a KV record, so one
// shared Fields list can serve multiple patterns whose capture groups
// happen to share a name (see FieldMapping.ValueMap for translating two
// patterns' different vocabularies for the same target, e.g. one using
// "permitted"/"denied" and another using "Built"/"Teardown" for
// something both call "action"). A line matching no pattern is a row
// error — never guessed at.
type MappingRegexParser struct {
	Cfg      *mapping.Config
	compiled []*regexp.Regexp // parallel to Cfg.Patterns; see NewMappingRegexParser
}

// NewMappingRegexParser compiles every pattern in cfg.Patterns once, up
// front, so a typo in a regex fails the job immediately with a clear
// error instead of surfacing as "line matched no pattern" row errors
// later. mapping.Parse already validates that every pattern compiles,
// so a failure here would mean cfg was constructed some other way.
func NewMappingRegexParser(cfg *mapping.Config) (MappingRegexParser, error) {
	compiled := make([]*regexp.Regexp, len(cfg.Patterns))
	for i, pat := range cfg.Patterns {
		re, err := regexp.Compile(pat.Match)
		if err != nil {
			return MappingRegexParser{}, fmt.Errorf("pattern %d: invalid regex %q: %w", i, pat.Match, err)
		}
		compiled[i] = re
	}
	return MappingRegexParser{Cfg: cfg, compiled: compiled}, nil
}

func (p MappingRegexParser) Parse(r io.Reader, emit func(NetworkEvent) error, onRowError func(RowError)) error {
	warnIfTemplate(p.Cfg)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		values, matched := p.matchLine(line)
		if !matched {
			onRowError(RowError{LineNumber: lineNum, Line: line, Err: fmt.Errorf("line matched none of the %d configured pattern(s)", len(p.compiled))})
			continue
		}

		ev, err := BuildEventFromMapping(mapping.NewFlatRecord(values), p.Cfg)
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

// matchLine tries each compiled pattern against line, in order, and
// returns the first match's named capture groups merged with that
// pattern's Consts (a capture group always wins over a Consts entry of
// the same name).
func (p MappingRegexParser) matchLine(line string) (map[string]string, bool) {
	for i, re := range p.compiled {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		values := make(map[string]string, len(m)+len(p.Cfg.Patterns[i].Consts))
		for k, v := range p.Cfg.Patterns[i].Consts {
			values[k] = v
		}
		for j, name := range re.SubexpNames() {
			if j == 0 || name == "" {
				continue
			}
			values[name] = m[j]
		}
		return values, true
	}
	return nil, false
}
