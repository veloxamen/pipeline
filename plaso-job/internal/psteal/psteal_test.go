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

package psteal_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veloxamen/plaso-job/internal/psteal"
)

func writeRawLines(t *testing.T, dir string, lines []string) string {
	t.Helper()
	path := filepath.Join(dir, "raw.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write raw jsonl: %v", err)
	}
	return path
}

func TestPostProcess_AddsDeviceFromDisplayNameAndOmitsCaseID(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"data_type":"windows:evtx:record","display_name":"OS:` + inputRoot + `/SERVER01/C/Windows/System32/winevt/Logs/Security.evtx","message":"hello","parser":"winevtx"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	count, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event, got %d", count)
	}

	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}

	var event map[string]interface{}
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if _, exists := event["case_id"]; exists {
		t.Errorf("case_id should not be set, got %v", event["case_id"])
	}
	if event["device_name"] != "SERVER01" {
		t.Errorf("device_name = %v, want SERVER01", event["device_name"])
	}
	if event["timestamp"] != "2024-01-01T00:00:00Z" {
		t.Errorf("timestamp = %v, want 2024-01-01T00:00:00Z", event["timestamp"])
	}
	if event["display_name"] != "C:/Windows/System32/winevt/Logs/Security.evtx" {
		t.Errorf("display_name = %v, want C:/Windows/System32/winevt/Logs/Security.evtx", event["display_name"])
	}
	if event["data_type"] != "windows:evtx:record" {
		t.Errorf("data_type = %v, want windows:evtx:record", event["data_type"])
	}
	if _, exists := event["ingested_at"]; exists {
		t.Errorf("ingested_at should not be set, got %v", event["ingested_at"])
	}
	if _, exists := event["source_short"]; exists {
		t.Errorf("source_short should not be set, got %v", event["source_short"])
	}
}

func TestPostProcess_TimestampSurvivesLargeValueRoundTrip(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067234123456,"message":"large timestamp"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	if !strings.Contains(string(data), `"timestamp":"2024-01-01T00:00:34.123456Z"`) {
		t.Errorf("output %s does not contain the expected UTC timestamp string", data)
	}
}

func TestPostProcess_LeavesMissingTimestampAbsent(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"message":"no timestamp field"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	var event map[string]interface{}
	json.Unmarshal(data, &event)

	if _, exists := event["timestamp"]; exists {
		t.Errorf("timestamp should stay absent, got %v", event["timestamp"])
	}
}

func TestPostProcess_LeavesUnmodeledFieldsPassthrough(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"source":"EVT","tag":{"labels":["Malware"]},"message":"hello"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	var event map[string]interface{}
	json.Unmarshal(data, &event)

	if event["source"] != "EVT" {
		t.Errorf("source = %v, want EVT", event["source"])
	}
	if event["timestamp"] != "2024-01-01T00:00:00Z" {
		t.Errorf("timestamp = %v, want 2024-01-01T00:00:00Z", event["timestamp"])
	}
}

func TestPostProcess_CoercesEventIdentifierToString(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"event_identifier":4624,"message":"logon"}`,
		`{"timestamp":1704067200000000,"event_identifier":"already-a-string","message":"other"}`,
		`{"timestamp":1704067200000000,"message":"no id"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 output lines, got %d", len(lines))
	}

	var e1, e2, e3 map[string]interface{}
	json.Unmarshal([]byte(lines[0]), &e1)
	json.Unmarshal([]byte(lines[1]), &e2)
	json.Unmarshal([]byte(lines[2]), &e3)

	if v, ok := e1["event_identifier"].(string); !ok || v != "4624" {
		t.Errorf("event_identifier = %#v, want string \"4624\"", e1["event_identifier"])
	}
	if v, ok := e2["event_identifier"].(string); !ok || v != "already-a-string" {
		t.Errorf("event_identifier = %#v, want string \"already-a-string\"", e2["event_identifier"])
	}
	if _, exists := e3["event_identifier"]; exists {
		t.Errorf("event_identifier should stay absent, got %v", e3["event_identifier"])
	}
}

func TestPostProcess_FallsBackToDefaultDeviceWithoutDisplayName(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"message":"synthetic event with no source file"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	var event map[string]interface{}
	json.Unmarshal(data, &event)

	if event["device_name"] != "unknown" {
		t.Errorf("device_name = %v, want unknown", event["device_name"])
	}
}

func TestPostProcess_CleansDisplayNameToOriginalPath(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"display_name":"OS:` + inputRoot + `/SERVER01/C/Users/alice/Desktop/notes.txt"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	var event map[string]interface{}
	json.Unmarshal(data, &event)

	if event["display_name"] != "C:/Users/alice/Desktop/notes.txt" {
		t.Errorf("display_name = %v, want C:/Users/alice/Desktop/notes.txt", event["display_name"])
	}
}

func TestPostProcess_LeavesDisplayNameUnchangedWhenRootDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"display_name":"OS:/some/unrelated/path/file.txt"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	var event map[string]interface{}
	json.Unmarshal(data, &event)

	if event["display_name"] != "OS:/some/unrelated/path/file.txt" {
		t.Errorf("display_name = %v, want unchanged original value", event["display_name"])
	}
	if event["device_name"] != "unknown" {
		t.Errorf("device_name = %v, want unknown", event["device_name"])
	}
}

func TestPostProcess_PreservesNonCDriveLetters(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"display_name":"OS:` + inputRoot + `/SERVER01/D/Evidence/case_data.dat"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	var event map[string]interface{}
	json.Unmarshal(data, &event)

	if event["display_name"] != "D:/Evidence/case_data.dat" {
		t.Errorf("display_name = %v, want D:/Evidence/case_data.dat", event["display_name"])
	}
}

func TestPostProcess_EventUUIDIsDeterministicAndDiffersOnRawLineChange(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"data_type":"windows:evtx:record","message":"logon","event_identifier":4624,"display_name":"OS:` + inputRoot + `/SERVER01/C/x.evtx"}`,
		`{"timestamp":1704067200000000,"data_type":"windows:evtx:record","message":"logon","event_identifier":4624,"display_name":"OS:` + inputRoot + `/SERVER01/C/x.evtx"}`,
		`{"timestamp":1704067200000000,"data_type":"windows:evtx:record","message":"logoff","event_identifier":4624,"display_name":"OS:` + inputRoot + `/SERVER01/C/x.evtx"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	_, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}

	data, _ := os.ReadFile(final)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 output lines, got %d", len(lines))
	}
	var e1, e2, e3 map[string]interface{}
	json.Unmarshal([]byte(lines[0]), &e1)
	json.Unmarshal([]byte(lines[1]), &e2)
	json.Unmarshal([]byte(lines[2]), &e3)

	if e1["event_uuid"] == nil || e1["event_uuid"] == "" {
		t.Fatalf("event_uuid not set: %v", e1["event_uuid"])
	}
	if e1["event_uuid"] != e2["event_uuid"] {
		t.Errorf("byte-identical raw lines should share event_uuid: %v vs %v", e1["event_uuid"], e2["event_uuid"])
	}
	if e1["event_uuid"] == e3["event_uuid"] {
		t.Errorf("raw lines differing in message should not share event_uuid")
	}
}

func TestPostProcess_MultipleDevicesInSameCase(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	raw := writeRawLines(t, dir, []string{
		`{"timestamp":1704067200000000,"display_name":"OS:` + inputRoot + `/SERVER01/file1.txt"}`,
		`{"timestamp":1704070800000000,"display_name":"OS:` + inputRoot + `/SERVER02/file2.txt"}`,
	})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	count, _, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 events, got %d", count)
	}

	data, err := os.ReadFile(final)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 output lines, got %d", len(lines))
	}

	var e1, e2 map[string]interface{}
	json.Unmarshal([]byte(lines[0]), &e1)
	json.Unmarshal([]byte(lines[1]), &e2)

	if e1["device_name"] != "SERVER01" {
		t.Errorf("event 1 device_name = %v, want SERVER01", e1["device_name"])
	}
	if e2["device_name"] != "SERVER02" {
		t.Errorf("event 2 device_name = %v, want SERVER02", e2["device_name"])
	}
}

func TestPostProcess_OversizedLineIsSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	inputRoot := filepath.Join(dir, "input")

	hugeMessage := strings.Repeat("A", 11*1024*1024) // 11 MB, over the 10 MB threshold
	normal := `{"timestamp":1704067200000000,"parser":"winevtx","message":"normal event"}`
	huge := `{"timestamp":1704070800000000,"parser":"winreg","display_name":"OS:` + inputRoot +
		`/SERVER01/C/Windows/System32/config/SOFTWARE","guid":"4d36e972-e325-11ce-bfc1-08002be10318","message":"` + hugeMessage + `"}`

	raw := writeRawLines(t, dir, []string{normal, huge})
	final := filepath.Join(dir, "final.jsonl")
	errLines := filepath.Join(dir, "errlines.jsonl")

	count, skipped, err := psteal.PostProcess(raw, final, errLines, inputRoot, "unknown")
	if err != nil {
		t.Fatalf("PostProcess: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (only the normal-sized event)", count)
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}

	finalData, _ := os.ReadFile(final)
	if strings.Contains(string(finalData), "winreg") {
		t.Errorf("oversized event should not appear in final timeline output")
	}

	errData, err := os.ReadFile(errLines)
	if err != nil {
		t.Fatalf("read errLines: %v", err)
	}
	var summary map[string]interface{}
	if err := json.Unmarshal(bytes.TrimSpace(errData), &summary); err != nil {
		t.Fatalf("unmarshal error-line summary: %v", err)
	}
	if summary["parser"] != "winreg" {
		t.Errorf("summary parser = %v, want winreg", summary["parser"])
	}
	if summary["guid"] != "4d36e972-e325-11ce-bfc1-08002be10318" {
		t.Errorf("summary guid = %v, want the GUID from the message", summary["guid"])
	}
	if summary["byte_length"] == nil || summary["byte_length"].(float64) < 11*1024*1024 {
		t.Errorf("summary byte_length = %v, want >= 11MB", summary["byte_length"])
	}
	if _, ok := summary["message_head"].(string); !ok {
		t.Errorf("summary should include a truncated message_head")
	}
}
