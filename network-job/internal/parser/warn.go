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
	"log/slog"
	"sync"

	"github.com/veloxamen/network-job/internal/mapping"
)

// warnOnceSeen dedupes template-config warnings per log_type so a large
// file doesn't spam the log once per line/record — logged once per
// process, the first time each such config is used.
var (
	warnOnceMu   sync.Mutex
	warnOnceSeen = map[string]bool{}
)

// warnIfTemplate logs cfg.TemplateWarning once (if set) — see
// mapping.Config.TemplateWarning's doc comment. Called at the start of
// every mapping-driven parser's Parse method; a no-op for configs that
// don't set it.
func warnIfTemplate(cfg *mapping.Config) {
	if cfg.TemplateWarning == "" {
		return
	}
	warnOnceMu.Lock()
	defer warnOnceMu.Unlock()
	if warnOnceSeen[cfg.LogType] {
		return
	}
	warnOnceSeen[cfg.LogType] = true
	slog.Warn("using an unvalidated template mapping config — verify output carefully",
		"log_type", cfg.LogType, "note", cfg.TemplateWarning)
}
