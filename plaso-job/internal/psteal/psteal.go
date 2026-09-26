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

// Package psteal wraps psteal.py and normalizes its JSON Lines output
// for BigQuery timeline ingestion.
package psteal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// maxLineBytes bounds the maximum allowed size for a single JSON line.
const maxLineBytes = 10 * 1024 * 1024

// Run executes psteal.py against sourceDir, writing JSON Lines to outputPath.
func Run(ctx context.Context, pstealBin, sourceDir, outputPath string) error {
	cmd := exec.CommandContext(ctx, pstealBin,
		"--source", sourceDir,
		"-o", "json_line",
		"-w", outputPath,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("psteal failed: %w\n--- stdout ---\n%s\n--- stderr ---\n%s",
			err, stdout.String(), stderr.String())
	}
	return nil
}

// PostProcess reads raw json_line output, normalizes events, adds device names,
// and writes the result to finalPath. Oversized lines are skipped and logged to errorLinesPath.
// Returns the number of events written and lines skipped.
func PostProcess(rawPath, finalPath, errorLinesPath, inputRoot, defaultDevice string) (count, skipped int, err error) {
	in, err := os.Open(rawPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", rawPath, err)
	}
	defer in.Close()

	out, err := os.Create(finalPath)
	if err != nil {
		return 0, 0, fmt.Errorf("create %s: %w", finalPath, err)
	}
	defer out.Close()

	errOut, err := os.Create(errorLinesPath)
	if err != nil {
		return 0, 0, fmt.Errorf("create %s: %w", errorLinesPath, err)
	}
	defer errOut.Close()

	root := strings.TrimSuffix(inputRoot, "/")

	reader := bufio.NewReaderSize(in, 64*1024)
	writer := bufio.NewWriter(out)
	defer writer.Flush()
	errWriter := bufio.NewWriter(errOut)
	defer errWriter.Flush()

	lineNum := 0
	for {
		lineNum++
		line, oversized, readErr := readLine(reader, maxLineBytes)
		if readErr != nil && readErr != io.EOF {
			return count, skipped, fmt.Errorf("reading %s: %w", rawPath, readErr)
		}

		switch {
		case oversized:
			skipped++
			if writeErr := writeSkippedLineSummary(errWriter, lineNum); writeErr != nil {
				return count, skipped, fmt.Errorf("writing error-line summary for line %d: %w", lineNum, writeErr)
			}
		case len(bytes.TrimSpace(line)) == 0:
			// Blank line: nothing to process.
		default:
			var event map[string]interface{}
			if err := json.Unmarshal(line, &event); err != nil {
				return count, skipped, fmt.Errorf("parsing event %d: %w", lineNum, err)
			}

			normalizeEvent(event)
			device := applyDeviceAndCleanPath(event, root, defaultDevice)
			event["device_name"] = device
			event["event_uuid"] = hashRawLine(line)

			encoded, err := json.Marshal(event)
			if err != nil {
				return count, skipped, fmt.Errorf("encoding event %d: %w", lineNum, err)
			}
			if _, err := writer.Write(encoded); err != nil {
				return count, skipped, fmt.Errorf("writing event %d: %w", lineNum, err)
			}
			if err := writer.WriteByte('\n'); err != nil {
				return count, skipped, fmt.Errorf("writing event %d: %w", lineNum, err)
			}
			count++
		}

		if readErr == io.EOF {
			break
		}
	}

	return count, skipped, nil
}

// skippedLine represents a JSON summary for a dropped oversized line.
type skippedLine struct {
	LineNumber int    `json:"line_number"`
	Reason     string `json:"reason"`
}

// writeSkippedLineSummary writes a summary of the skipped line to the error writer.
func writeSkippedLineSummary(w *bufio.Writer, lineNum int) error {
	encoded, err := json.Marshal(skippedLine{
		LineNumber: lineNum,
		Reason:     fmt.Sprintf("line exceeds %d byte limit", maxLineBytes),
	})
	if err != nil {
		return err
	}
	if _, err := w.Write(encoded); err != nil {
		return err
	}
	return w.WriteByte('\n')
}

// readLine reads the next line from r, reporting if it exceeds maxLineBytes.
func readLine(r *bufio.Reader, maxLineBytes int) (line []byte, oversized bool, err error) {
	for {
		chunk, readErr := r.ReadSlice('\n')
		line = append(line, chunk...)

		if readErr == bufio.ErrBufferFull {
			if len(line) > maxLineBytes {
				if discardErr := discardToNewline(r); discardErr != nil && discardErr != io.EOF {
					return nil, false, discardErr
				}
				return nil, true, nil
			}
			continue
		}

		if len(line) == 0 {
			return nil, false, readErr
		}
		if len(line) > maxLineBytes {
			return nil, true, readErr
		}
		return trimNewline(line), false, readErr
	}
}

// discardToNewline consumes bytes from r up to the next newline.
func discardToNewline(r *bufio.Reader) error {
	for {
		_, err := r.ReadSlice('\n')
		if err == nil {
			return nil
		}
		if err != bufio.ErrBufferFull {
			return err
		}
	}
}

// trimNewline strips trailing newline characters from line.
func trimNewline(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	return line
}

// hashRawLine returns the SHA256 hex digest of the raw JSON line bytes.
// This matches the network_events event_uuid scheme to support cross-table lookups.
func hashRawLine(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// normalizeEvent rewrites an event in place to match the target schema.
func normalizeEvent(event map[string]interface{}) {
	normalizeTimestamp(event)
	normalizeEventIdentifier(event)
}

// normalizeTimestamp converts Plaso's epoch-microseconds timestamp into
// an RFC3339 UTC string (event_timestamp) and removes the raw timestamp key.
func normalizeTimestamp(event map[string]interface{}) {
	raw, ok := event["timestamp"]
	if !ok || raw == nil {
		return
	}

	var us int64
	switch v := raw.(type) {
	case float64:
		us = int64(v)
	case string:
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return
		}
		us = parsed
	default:
		return
	}

	delete(event, "timestamp")
	event["event_timestamp"] = time.UnixMicro(us).UTC().Format(time.RFC3339Nano)
}

// normalizeEventIdentifier coerces event_identifier to a string in place.
func normalizeEventIdentifier(event map[string]interface{}) {
	v, ok := event["event_identifier"]
	if !ok || v == nil {
		return
	}

	switch n := v.(type) {
	case float64:
		event["event_identifier"] = strconv.FormatInt(int64(n), 10)
	case string:
		// Already a string.
	default:
		if encoded, err := json.Marshal(n); err == nil {
			event["event_identifier"] = string(encoded)
		}
	}
}

// applyDeviceAndCleanPath extracts the device name from display_name and
// cleans the path to standard Windows notation. Returns defaultDevice if extraction fails.
func applyDeviceAndCleanPath(event map[string]interface{}, root, defaultDevice string) string {
	display, ok := event["display_name"].(string)
	if !ok || root == "" {
		return defaultDevice
	}

	device, relPath, ok := deviceAndOriginalPath(display, root)
	if !ok {
		return defaultDevice
	}
	if relPath != "" {
		event["display_name"] = relPath
	}
	return device
}

// deviceAndOriginalPath splits display_name into the device name and the relative path.
func deviceAndOriginalPath(display, root string) (device, relPath string, ok bool) {
	idx := strings.Index(display, root)
	if idx == -1 {
		return "", "", false
	}
	rest := strings.TrimPrefix(display[idx+len(root):], "/")
	segEnd := strings.IndexByte(rest, '/')
	if segEnd == -1 {
		if rest == "" {
			return "", "", false
		}
		return rest, "", true
	}
	device = rest[:segEnd]
	if device == "" {
		return "", "", false
	}
	return device, rest[segEnd+1:], true
}
