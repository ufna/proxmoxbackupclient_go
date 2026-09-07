package pbscommon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// decodeBlob reverses EncodeChunk: parse magic|crc|iv|tag|ciphertext, verify
// crc, AES-256-GCM-decrypt, and zstd-decompress if the magic says so. This is
// what the official PBS client does, so a round-trip through it proves the
// on-disk layout is correct.
func (c *CryptConfig) decodeBlob(t *testing.T, blob []byte) []byte {
	t.Helper()
	if len(blob) < 44 {
		t.Fatalf("blob too short: %d", len(blob))
	}
	magic := blob[0:8]
	crc := binary.LittleEndian.Uint32(blob[8:12])
	iv := blob[12:28]
	tag := blob[28:44]
	ciphertext := blob[44:]

	if got := crc32.ChecksumIEEE(ciphertext); got != crc {
		t.Fatalf("crc mismatch: header %08x, computed %08x", crc, got)
	}

	compressed := bytes.Equal(magic, encrComprBlobMagic)
	if !compressed && !bytes.Equal(magic, encryptedBlobMagic) {
		t.Fatalf("unexpected magic %v", magic)
	}

	block, err := aes.NewCipher(c.encKey[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gcm.Open(nil, iv, append(append([]byte{}, ciphertext...), tag...), nil)
	if err != nil {
		t.Fatalf("gcm open: %v", err)
	}
	if !compressed {
		return plain
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	out, err := dec.DecodeAll(plain, nil)
	if err != nil {
		t.Fatalf("zstd decode: %v", err)
	}
	return out
}

func testKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

// TestEncodeChunkRoundTrip covers compressible, incompressible and empty data —
// exercising both the ENCR_COMPR and ENCRYPTED (compression-skipped) magics.
func TestEncodeChunkRoundTrip(t *testing.T) {
	c := NewCryptConfig(testKey())
	cases := map[string][]byte{
		"compressible":   bytes.Repeat([]byte("proxmox backup "), 4096),
		"incompressible": incompressible(t, 50000),
		"empty":          {},
		"tiny":           []byte("x"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			blob, err := c.EncodeChunk(data, true)
			if err != nil {
				t.Fatal(err)
			}
			got := c.decodeBlob(t, blob)
			if !bytes.Equal(got, data) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(data))
			}
		})
	}
}

// TestEncodeChunkSkipsCompressionWhenLarger: incompressible data must use the
// non-compressed encrypted magic (PBS keeps compression only when it shrinks).
func TestEncodeChunkSkipsCompressionWhenLarger(t *testing.T) {
	c := NewCryptConfig(testKey())
	blob, err := c.EncodeChunk(incompressible(t, 20000), true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[0:8], encryptedBlobMagic) {
		t.Fatalf("expected ENCRYPTED magic for incompressible data, got %v", blob[0:8])
	}
}

// TestComputeDigestKeyed: the digest is SHA256(data || id_key), so it depends on
// the key and differs from a plain SHA256. Two configs with different keys must
// produce different digests for the same data (this is what key-scopes dedup).
func TestComputeDigestKeyed(t *testing.T) {
	k1 := testKey()
	a := NewCryptConfig(k1)
	k2 := k1
	k2[0] ^= 0xFF
	b := NewCryptConfig(k2)

	data := []byte("some chunk data")
	if a.ComputeDigest(data) == b.ComputeDigest(data) {
		t.Fatal("digests under different keys must differ")
	}
	if a.ComputeDigest(data) != a.ComputeDigest(data) {
		t.Fatal("digest must be deterministic")
	}
}

func incompressible(t *testing.T, n int) []byte {
	t.Helper()
	// LCG-generated pseudo-random bytes: deterministic (stable test) but not
	// zstd-compressible.
	out := make([]byte, n)
	x := uint64(0x9E3779B97F4A7C15)
	for i := range out {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = byte(x >> 33)
	}
	return out
}
