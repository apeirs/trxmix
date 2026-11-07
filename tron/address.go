package tron

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// AddressPrefix is the first byte of every TRON address (mainnet and testnets).
const AddressPrefix = 0x41

// Address is a 21-byte TRON address: 0x41 followed by the 20-byte account id.
type Address [21]byte

const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func checksum(b []byte) []byte {
	h := sha256.Sum256(b)
	h = sha256.Sum256(h[:])
	return h[:4]
}

// Base58 encodes b with the Bitcoin alphabet.
func Base58(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var out []byte
	mod, base := new(big.Int), big.NewInt(58)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// DecodeBase58 is the inverse of Base58.
func DecodeBase58(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range []byte(s) {
		i := strings.IndexByte(b58, c)
		if i < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(i)))
	}
	out := n.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	return append(make([]byte, zeros), out...), nil
}

// String is the base58check form (T...).
func (a Address) String() string {
	return Base58(append(a[:], checksum(a[:])...))
}

// Hex is the 41-prefixed hex form the node uses when visible=false.
func (a Address) Hex() string { return hex.EncodeToString(a[:]) }

// Word is the address as a 32-byte ABI word (the 20-byte id, left padded).
func (a Address) Word() []byte {
	w := make([]byte, 32)
	copy(w[12:], a[1:])
	return w
}

// ParseAddress accepts a base58check address (T...), the 41-prefixed hex
// form, or a 0x-prefixed 20-byte EVM-style id.
func ParseAddress(s string) (Address, error) {
	var a Address
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		b, err := hex.DecodeString(s[2:])
		if err != nil || len(b) != 20 {
			return a, fmt.Errorf("%q: want 0x and 40 hex digits", s)
		}
		a[0] = AddressPrefix
		copy(a[1:], b)
		return a, nil
	case len(s) == 42 && strings.HasPrefix(s, "41"):
		b, err := hex.DecodeString(s)
		if err != nil {
			return a, fmt.Errorf("%q: bad hex address", s)
		}
		copy(a[:], b)
		return a, nil
	}
	b, err := DecodeBase58(s)
	if err != nil {
		return a, fmt.Errorf("%q is not a TRON address: %w", s, err)
	}
	if len(b) != 25 {
		return a, fmt.Errorf("%q is not a TRON address (decodes to %d bytes, want 25)", s, len(b))
	}
	if !bytes.Equal(checksum(b[:21]), b[21:]) {
		return a, fmt.Errorf("%q: bad checksum (a typo?)", s)
	}
	if b[0] != AddressPrefix {
		return a, fmt.Errorf("%q: version byte 0x%02x, want 0x41 (a TRON address starts with T)", s, b[0])
	}
	copy(a[:], b)
	return a, nil
}

// AddressFromHex converts the node's hex form (41...) to an Address.
func AddressFromHex(h string) (Address, error) {
	var a Address
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 21 || b[0] != AddressPrefix {
		return a, errors.New("not a 41-prefixed hex address")
	}
	copy(a[:], b)
	return a, nil
}
