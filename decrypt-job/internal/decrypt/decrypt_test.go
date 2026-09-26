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

package decrypt_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/veloxamen/decrypt-job/internal/decrypt"
)

// buildEncryptedStream reproduces the collector's file format in memory so
// tests do not depend on the Windows-only encrypt.go binary.
//
// Format:
//
//	[Magic(8B)] [encKeyLen(4B)] [encKey(N B)]
//	  for each chunk: [chunkLen(4B)] [Nonce(12B)+Ciphertext]
//	[0x00000000]
//
// For tests the "encrypted" DEK is written as raw plaintext so we can skip
// KMS; the test exercises everything else end-to-end.
func buildEncryptedStream(t *testing.T, entries []entry) (encDEK, []byte []byte) {
	t.Helper()

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("rand: %v", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}

	// Build the plaintext entry stream first.
	var plain bytes.Buffer
	for _, e := range entries {
		nameBytes := []byte(e.name)
		var hdr [12]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(nameBytes)))
		binary.BigEndian.PutUint64(hdr[4:12], uint64(len(e.data)))
		plain.Write(hdr[:])
		plain.Write(nameBytes)
		plain.Write(e.data)
	}

	// Encrypt the entire plaintext as a single chunk (mirrors ChunkSize behaviour
	// when data < 64 MB).
	var out bytes.Buffer
	out.WriteString("VXMN0001")

	// encKeyLen + encKey (plaintext aesKey — no KMS in unit tests).
	var kl [4]byte
	binary.BigEndian.PutUint32(kl[:], uint32(len(aesKey)))
	out.Write(kl[:])
	out.Write(aesKey) // raw key; tests bypass KMS

	encryptChunk := func(pt []byte) {
		nonce := make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("nonce: %v", err)
		}
		ct := gcm.Seal(nonce, nonce, pt, nil)
		var cl [4]byte
		binary.BigEndian.PutUint32(cl[:], uint32(len(ct)))
		out.Write(cl[:])
		out.Write(ct)
	}

	encryptChunk(plain.Bytes())

	// Termination marker.
	out.Write([]byte{0, 0, 0, 0})

	return aesKey, out.Bytes()
}

type entry struct {
	name string
	data []byte
}

// TestDecryptChunks_RoundTrip verifies that decryptChunks correctly decrypts
// what the collector's flush() would have produced.
func TestDecryptChunks_RoundTrip(t *testing.T) {
	aesKey, stream := buildEncryptedStream(t, []entry{
		{name: "memory/ram.bin", data: []byte("hello forensics")},
		{name: "disk/mft.bin", data: bytes.Repeat([]byte{0xAB}, 1024)},
	})

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	// Skip past header (magic + encKeyLen + encKey).
	r := bytes.NewReader(stream)
	magic := make([]byte, 8)
	io.ReadFull(r, magic)
	var kl [4]byte
	io.ReadFull(r, kl[:])
	keyLen := binary.BigEndian.Uint32(kl[:])
	io.ReadFull(r, make([]byte, keyLen))

	var plain bytes.Buffer
	if err := decrypt.ExportedDecryptChunks(r, gcm, &plain); err != nil {
		t.Fatalf("decryptChunks: %v", err)
	}

	// The plaintext must contain the entry names.
	got := plain.String()
	for _, name := range []string{"memory/ram.bin", "disk/mft.bin"} {
		if !bytes.Contains(plain.Bytes(), []byte(name)) {
			t.Errorf("expected entry name %q in plaintext, got: %q", name, got)
		}
	}
}

// TestDecryptChunks_CorruptedCiphertext verifies that tampering is detected.
func TestDecryptChunks_CorruptedCiphertext(t *testing.T) {
	aesKey, stream := buildEncryptedStream(t, []entry{
		{name: "test.bin", data: []byte("sensitive data")},
	})

	// Flip a byte in the ciphertext region (after header: 8+4+32 = 44 bytes,
	// then 4 bytes chunkLen, then ciphertext starts).
	headerEnd := 8 + 4 + 32 + 4 + 12 // magic+kl+key+chunkLen+nonce
	stream[headerEnd+5] ^= 0xFF

	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)

	r := bytes.NewReader(stream)
	io.ReadFull(r, make([]byte, 8+4+32))

	var plain bytes.Buffer
	err := decrypt.ExportedDecryptChunks(r, gcm, &plain)
	if err == nil {
		t.Fatal("expected error on corrupted ciphertext, got nil")
	}
}
