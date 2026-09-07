package pbscommon

// Client-side encryption for the PBS backup protocol, reimplemented to match
// proxmox-backup's pbs-tools/src/crypt_config.rs and
// pbs-datastore/src/{file_formats,data_blob}.rs byte-for-byte, so that
// snapshots written by this client can be restored/verified by the official
// proxmox-backup-client with the same keyfile.
//
// Cipher is AES-256-GCM (16-byte IV, empty AAD). Chunk digests are keyed with a
// PBKDF2-derived id_key so they do not collide across keys — this is what makes
// dedup key-scoped, and it is mandatory: the digest is both the chunk name and
// the index entry.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"

	"github.com/klauspost/compress/zstd"
)

// DataBlob magic numbers — verbatim from pbs-datastore/src/file_formats.rs.
var (
	encryptedBlobMagic      = []byte{123, 103, 133, 190, 34, 45, 76, 240}
	encrComprBlobMagic      = []byte{230, 89, 27, 191, 11, 191, 216, 11}
)

// fingerprintInput is openssl::sha::sha256(b"Proxmox Backup Encryption Key
// Fingerprint"), verbatim from crypt_config.rs. compute_digest over it yields
// the key fingerprint the official client shows.
var fingerprintInput = [32]byte{
	110, 208, 239, 119, 71, 31, 255, 77, 85, 199, 168, 254, 74, 157, 182, 33,
	97, 64, 127, 19, 76, 114, 93, 223, 48, 153, 45, 37, 236, 69, 237, 38,
}

// CryptConfig mirrors PBS CryptConfig: an enc_key for AES-256-GCM and a
// PBKDF2-derived id_key used to namespace chunk digests.
type CryptConfig struct {
	encKey [32]byte
	idKey  [32]byte
}

// keyConfigFile is the on-disk keyfile JSON (proxmox-backup-client key create).
// For --kdf none, "data" holds the raw 32-byte key, base64-encoded.
type keyConfigFile struct {
	Kdf         interface{} `json:"kdf"`
	Data        string      `json:"data"`
	Fingerprint string      `json:"fingerprint"`
}

// NewCryptConfig derives the id_key exactly as CryptConfig::new:
// pbkdf2_hmac(enc_key, salt=b"_id_key", iters=10, sha256, dklen=32).
func NewCryptConfig(encKey [32]byte) *CryptConfig {
	c := &CryptConfig{encKey: encKey}
	c.idKey = pbkdf2SHA256OneBlock(encKey[:], []byte("_id_key"), 10)
	return c
}

// LoadCryptConfigFromKeyfile parses a PBS keyfile (kdf=none) and returns a
// CryptConfig. Password-wrapped keyfiles (kdf=scrypt/pbkdf2) are rejected: this
// client is unattended and only supports raw keys, same as our Ansible role.
func LoadCryptConfigFromKeyfile(path string) (*CryptConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read keyfile: %w", err)
	}
	var kc keyConfigFile
	if err := json.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("parse keyfile JSON: %w", err)
	}
	// kdf may be the string "none", or absent/null. Anything else means the key
	// material is wrapped and we cannot use it unattended.
	if s, ok := kc.Kdf.(string); ok && s != "" && s != "none" {
		return nil, fmt.Errorf("keyfile uses kdf %q; only raw (kdf=none) keys are supported", s)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(kc.Data)
	if err != nil {
		return nil, fmt.Errorf("decode keyfile data (base64): %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("keyfile holds a %d-byte key, expected 32", len(keyBytes))
	}
	var enc [32]byte
	copy(enc[:], keyBytes)
	return NewCryptConfig(enc), nil
}

// ComputeDigest is CryptConfig::compute_digest: SHA256(data || id_key). id_key
// is appended (not prepended) to avoid length-extension attacks — matching PBS.
func (c *CryptConfig) ComputeDigest(data []byte) [32]byte {
	h := sha256.New()
	h.Write(data)
	h.Write(c.idKey[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Fingerprint is the key fingerprint the official client displays: the keyed
// digest of the fixed fingerprint input.
func (c *CryptConfig) Fingerprint() [32]byte {
	return c.ComputeDigest(fingerprintInput[:])
}

// EncodeChunk builds an encrypted DataBlob equivalent to
// DataBlob::encode(data, Some(config), compress=true). Layout:
//
//	magic[8] | crc[4 LE] | iv[16] | tag[16] | ciphertext
//
// crc32 (IEEE) covers the ciphertext only (raw_data[44..]). zstd runs before
// encryption, and is kept only if it actually shrinks the data — otherwise the
// plaintext is encrypted as-is and the non-compressed magic is used, matching
// PBS.
func (c *CryptConfig) EncodeChunk(data []byte, compress bool) ([]byte, error) {
	magic := encryptedBlobMagic
	source := data

	if compress {
		enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			return nil, fmt.Errorf("zstd writer: %w", err)
		}
		compressed := enc.EncodeAll(data, nil)
		enc.Close()
		// PBS keeps compression only when size <= original.
		if len(compressed) <= len(data) {
			magic = encrComprBlobMagic
			source = compressed
		}
	}

	block, err := aes.NewCipher(c.encKey[:])
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	// PBS uses a 16-byte IV (not the GCM-standard 12). Go implements the GCM
	// spec for non-12-byte nonces (GHASH-derived J0), interoperable with OpenSSL.
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("iv: %w", err)
	}
	// Seal appends the 16-byte tag after the ciphertext; PBS stores them
	// separately (tag in the header), so split them back out.
	sealed := gcm.Seal(nil, iv, source, nil)
	ciphertext := sealed[:len(sealed)-16]
	tag := sealed[len(sealed)-16:]

	out := make([]byte, 0, 44+len(ciphertext))
	out = append(out, magic...)
	crcPos := len(out)
	out = append(out, 0, 0, 0, 0) // crc placeholder
	out = append(out, iv...)
	out = append(out, tag...)
	out = append(out, ciphertext...)

	crc := crc32.ChecksumIEEE(ciphertext)
	binary.LittleEndian.PutUint32(out[crcPos:crcPos+4], crc)

	return out, nil
}

// pbkdf2SHA256OneBlock computes PBKDF2-HMAC-SHA256 for a 32-byte output (exactly
// one block, since dklen == hashlen). T = U1 ^ U2 ^ ... ^ U_iters,
// U1 = HMAC(pw, salt || 0x00000001), U_i = HMAC(pw, U_{i-1}).
func pbkdf2SHA256OneBlock(password, salt []byte, iters int) [32]byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1}) // block index 1, big-endian
	u := mac.Sum(nil)

	var out [32]byte
	copy(out[:], u)
	for i := 1; i < iters; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(nil)
		for j := 0; j < 32; j++ {
			out[j] ^= u[j]
		}
	}
	return out
}
