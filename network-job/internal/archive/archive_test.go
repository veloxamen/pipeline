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

package archive

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"
)

type seenFile struct {
	name    string
	content string
}

func collect(t *testing.T, name string, r io.Reader) []seenFile {
	t.Helper()
	var got []seenFile
	err := Walk(context.Background(), name, r, func(_ context.Context, name string, r io.Reader) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		got = append(got, seenFile{name: name, content: string(b)})
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return got
}

func TestWalk_PlainFile(t *testing.T) {
	got := collect(t, "fortigate/events.log", bytes.NewReader([]byte("hello world")))
	if len(got) != 1 || got[0].content != "hello world" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got[0].name != "fortigate/events.log" {
		t.Fatalf("unexpected name: %q", got[0].name)
	}
}

func TestWalk_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	gzw.Write([]byte("gzipped content"))
	gzw.Close()

	got := collect(t, "aws/events.log.gz", &buf)
	if len(got) != 1 || got[0].content != "gzipped content" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got[0].name != "aws/events.log" {
		t.Fatalf("expected .gz suffix stripped, got %q", got[0].name)
	}
}

func TestWalk_Zip_MultipleEntries(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{"a.log", "content-a"},
		{"b.log", "content-b"},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f.body))
	}
	zw.Close()

	got := collect(t, "azure/bundle.zip", bytes.NewReader(buf.Bytes()))
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	byName := map[string]string{}
	for _, g := range got {
		byName[g.name] = g.content
	}
	if byName["a.log"] != "content-a" || byName["b.log"] != "content-b" {
		t.Fatalf("unexpected entries: %+v", byName)
	}
}

func TestWalk_TarGz(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	body := []byte("tarred content")
	if err := tw.WriteHeader(&tar.Header{Name: "c.log", Size: int64(len(body)), Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	gzw.Write(tarBuf.Bytes())
	gzw.Close()

	for _, name := range []string{"google/bundle.tar.gz", "google/bundle.tgz"} {
		got := collect(t, name, bytes.NewReader(gzBuf.Bytes()))
		if len(got) != 1 || got[0].content != "tarred content" || got[0].name != "c.log" {
			t.Fatalf("unexpected result for %q: %+v", name, got)
		}
	}
}

func TestWalk_ZipWithinTarGz(t *testing.T) {
	// Build an inner zip containing one file.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create("nested.log")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("nested content"))
	zw.Close()

	// Wrap the zip bytes inside a tar.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "inner.zip", Size: int64(zipBuf.Len()), Mode: 0644}); err != nil {
		t.Fatal(err)
	}
	tw.Write(zipBuf.Bytes())
	tw.Close()

	// Gzip the tar.
	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	gzw.Write(tarBuf.Bytes())
	gzw.Close()

	got := collect(t, "checkpoint/outer.tar.gz", bytes.NewReader(gzBuf.Bytes()))
	if len(got) != 1 || got[0].content != "nested content" || got[0].name != "nested.log" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestWalk_MaxDepthExceeded(t *testing.T) {
	// A gzip stream whose "inner name" still ends in .gz after stripping
	// one suffix will recurse; simulate exceeding maxDepth directly.
	err := walk(context.Background(), "a.gz", bytes.NewReader(nil), maxDepth+1, func(_ context.Context, _ string, _ io.Reader) error {
		t.Fatalf("handler should not be called")
		return nil
	})
	if err == nil {
		t.Fatalf("expected an error for exceeding max depth")
	}
}
