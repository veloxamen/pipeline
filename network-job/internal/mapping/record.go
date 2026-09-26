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

package mapping

import (
	"strconv"
	"strings"
)

// Record resolves one FieldMapping.Source path against one row/entry of
// the source file. What counts as a "path" depends on the concrete
// implementation (dot-path for JSON, key name for KV, header name or
// "col:N" for CSV).
type Record interface {
	Lookup(path string) (value string, found bool)
}

// ---- JSON (dot-path into a decoded interface{} document) ----

type jsonRecord struct{ doc any }

// NewJSONRecord wraps an already json.Unmarshal-ed value (typically a
// map[string]any) for dot-path lookups, e.g. "event.src_ip" navigates
// doc["event"]["src_ip"].
func NewJSONRecord(doc any) Record { return jsonRecord{doc: doc} }

func (r jsonRecord) Lookup(path string) (string, bool) {
	cur := r.doc
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = m[part]
		if !ok {
			return "", false
		}
	}
	return stringifyJSONLeaf(cur)
}

// stringifyJSONLeaf converts a decoded JSON leaf value to its string
// form. Objects and arrays are not leaves and are reported as absent —
// a mapping config that ends its path one level too shallow gets an
// empty value rather than a confusing Go-syntax dump.
func stringifyJSONLeaf(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}

// ---- KV (flat key -> value map, e.g. from a tokenized key=value line) ----

type flatRecord map[string]string

// NewFlatRecord wraps a flat key/value map (KV format) for exact-key
// lookups. Also reused by CSV for header-name lookups (see
// NewCSVRecord).
func NewFlatRecord(kv map[string]string) Record { return flatRecord(kv) }

func (r flatRecord) Lookup(path string) (string, bool) {
	v, ok := r[path]
	return v, ok
}

// ---- CSV (header-name and/or 1-indexed positional lookup) ----

type csvRecord struct {
	byHeader map[string]string // lower-cased header -> value
	byIndex  []string
}

// NewCSVRecord wraps one CSV row. header may be nil when the file has
// no header row (has_header: false in the config); in that case only
// "col:N" (1-indexed) sources resolve.
func NewCSVRecord(header, fields []string) Record {
	rec := csvRecord{byIndex: fields}
	if header != nil {
		rec.byHeader = make(map[string]string, len(header))
		for i, h := range header {
			if i < len(fields) {
				rec.byHeader[strings.ToLower(strings.TrimSpace(h))] = fields[i]
			}
		}
	}
	return rec
}

func (r csvRecord) Lookup(path string) (string, bool) {
	if idx, ok := strings.CutPrefix(path, "col:"); ok {
		n, err := strconv.Atoi(idx)
		if err != nil || n < 1 || n > len(r.byIndex) {
			return "", false
		}
		return r.byIndex[n-1], true
	}
	if r.byHeader == nil {
		return "", false
	}
	v, ok := r.byHeader[strings.ToLower(strings.TrimSpace(path))]
	return v, ok
}
