package spacepow

import (
	"crypto/sha256"
	"encoding/binary"
)

func powDigest(payload []byte, nonce uint64) [32]byte {
	h := sha256.New()
	h.Write(payload)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], nonce)
	h.Write(n[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func meetsDifficulty(digest [32]byte, bits int) bool {
	if bits <= 0 {
		return true
	}
	full := bits / 8
	rem := bits % 8
	for i := 0; i < full; i++ {
		if digest[i] != 0 {
			return false
		}
	}
	if rem == 0 {
		return true
	}
	mask := byte(0xFF << (8 - rem))
	return digest[full]&mask == 0
}
