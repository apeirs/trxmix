package tron

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// The node computes the function selector from the signature
// (function_selector), so trxmix only encodes and decodes ABI words.

// ParseSignature splits "transfer(address,uint256)" into its name and types,
// normalising uint/int to uint256/int256.
func ParseSignature(sig string) (name string, types []string, err error) {
	sig = strings.ReplaceAll(sig, " ", "")
	open := strings.IndexByte(sig, '(')
	if open <= 0 || !strings.HasSuffix(sig, ")") {
		return "", nil, fmt.Errorf("%q: want name(type,...), e.g. balanceOf(address)", sig)
	}
	name = sig[:open]
	if !validMethod(name, 64) || (name[0] >= '0' && name[0] <= '9') {
		return "", nil, fmt.Errorf("bad function name %q", name)
	}
	inner := sig[open+1 : len(sig)-1]
	if inner != "" {
		for _, t := range strings.Split(inner, ",") {
			t = canonType(t)
			if err := checkType(t, false); err != nil {
				return "", nil, err
			}
			types = append(types, t)
		}
	}
	return name, types, nil
}

func canonType(t string) string {
	switch t {
	case "uint":
		return "uint256"
	case "int":
		return "int256"
	}
	return t
}

func typeBits(t, prefix string, step, max int) (int, bool) {
	if !strings.HasPrefix(t, prefix) {
		return 0, false
	}
	n, err := strconv.Atoi(t[len(prefix):])
	if err != nil || n < step || n > max || n%step != 0 {
		return 0, false
	}
	return n, true
}

// checkType accepts the static types (address, bool, uintN, intN, bytesN),
// and string and bytes too where dynamic is allowed (return values).
func checkType(t string, dynamic bool) error {
	switch {
	case t == "address" || t == "bool":
		return nil
	case dynamic && (t == "string" || t == "bytes"):
		return nil
	}
	if strings.HasPrefix(t, "uint") {
		if _, ok := typeBits(t, "uint", 8, 256); ok {
			return nil
		}
	} else if strings.HasPrefix(t, "int") {
		if _, ok := typeBits(t, "int", 8, 256); ok {
			return nil
		}
	} else if strings.HasPrefix(t, "bytes") {
		if _, ok := typeBits(t, "bytes", 1, 32); ok {
			return nil
		}
	}
	if t == "string" || t == "bytes" || strings.HasSuffix(t, "]") || strings.HasPrefix(t, "(") {
		return fmt.Errorf("argument type %s is dynamic: pass the encoded parameters with --data", t)
	}
	return fmt.Errorf("unknown ABI type %q", t)
}

// EncodeArgs ABI-encodes values for static types, as hex without 0x.
func EncodeArgs(types, vals []string) (string, error) {
	if len(types) != len(vals) {
		return "", fmt.Errorf("the signature has %d arguments, got %d", len(types), len(vals))
	}
	var out []byte
	for i, t := range types {
		w, err := encodeWord(t, vals[i])
		if err != nil {
			return "", fmt.Errorf("argument %d (%s): %w", i+1, t, err)
		}
		out = append(out, w...)
	}
	return hex.EncodeToString(out), nil
}

func parseInt(v string) (*big.Int, bool) {
	v = strings.ReplaceAll(v, "_", "")
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "-0x") {
		neg := strings.HasPrefix(v, "-")
		n, ok := new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(v, "-"), "0x"), 16)
		if ok && neg {
			n.Neg(n)
		}
		return n, ok
	}
	return new(big.Int).SetString(v, 10)
}

func encodeWord(t, v string) ([]byte, error) {
	w := make([]byte, 32)
	switch {
	case t == "address":
		a, err := ParseAddress(v)
		if err != nil {
			return nil, err
		}
		return a.Word(), nil
	case t == "bool":
		switch v {
		case "true", "1":
			w[31] = 1
		case "false", "0":
		default:
			return nil, fmt.Errorf("want true or false, got %q", v)
		}
		return w, nil
	case strings.HasPrefix(t, "uint"):
		bits, _ := typeBits(t, "uint", 8, 256)
		n, ok := parseInt(v)
		if !ok || n.Sign() < 0 || n.BitLen() > bits {
			return nil, fmt.Errorf("%q is not a %s", v, t)
		}
		n.FillBytes(w)
		return w, nil
	case strings.HasPrefix(t, "int"):
		bits, _ := typeBits(t, "int", 8, 256)
		n, ok := parseInt(v)
		lim := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		if !ok || n.Cmp(lim) >= 0 || n.Cmp(new(big.Int).Neg(lim)) < 0 {
			return nil, fmt.Errorf("%q is not an %s", v, t)
		}
		if n.Sign() < 0 {
			n.Add(n, new(big.Int).Lsh(big.NewInt(1), 256))
		}
		n.FillBytes(w)
		return w, nil
	case strings.HasPrefix(t, "bytes"):
		size, _ := typeBits(t, "bytes", 1, 32)
		b, err := hex.DecodeString(strings.TrimPrefix(v, "0x"))
		if err != nil || len(b) != size {
			return nil, fmt.Errorf("want 0x and %d hex bytes", size)
		}
		copy(w, b)
		return w, nil
	}
	return nil, fmt.Errorf("unsupported type %s", t)
}

// DecodeResults decodes a constant_result hex string for the given return
// types (static types, string and bytes).
func DecodeResults(types []string, resHex string) ([]string, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(resHex, "0x"))
	if err != nil {
		return nil, errors.New("result is not hex")
	}
	word := func(i int) ([]byte, error) {
		if i < 0 || (i+1)*32 > len(b) {
			return nil, fmt.Errorf("result too short (%d bytes) for %s", len(b), strings.Join(types, ","))
		}
		return b[i*32 : (i+1)*32], nil
	}
	var out []string
	for i, t := range types {
		t = canonType(t)
		if err := checkType(t, true); err != nil {
			return nil, err
		}
		w, err := word(i)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(w)
		switch {
		case t == "address":
			var a Address
			a[0] = AddressPrefix
			copy(a[1:], w[12:])
			out = append(out, a.String())
		case t == "bool":
			out = append(out, strconv.FormatBool(n.Sign() != 0))
		case strings.HasPrefix(t, "uint"):
			out = append(out, n.String())
		case strings.HasPrefix(t, "int"):
			if w[0]&0x80 != 0 {
				n.Sub(n, new(big.Int).Lsh(big.NewInt(1), 256))
			}
			out = append(out, n.String())
		case t == "string" || t == "bytes":
			if !n.IsInt64() || n.Int64()%32 != 0 {
				return nil, fmt.Errorf("bad offset for %s", t)
			}
			off := int(n.Int64())
			if off+32 > len(b) {
				return nil, fmt.Errorf("result too short for %s", t)
			}
			ln := new(big.Int).SetBytes(b[off : off+32])
			if !ln.IsInt64() || off+32+int(ln.Int64()) > len(b) {
				return nil, fmt.Errorf("bad length for %s", t)
			}
			data := b[off+32 : off+32+int(ln.Int64())]
			if t == "string" {
				out = append(out, strconv.Quote(string(data)))
			} else {
				out = append(out, "0x"+hex.EncodeToString(data))
			}
		case strings.HasPrefix(t, "bytes"):
			size, _ := typeBits(t, "bytes", 1, 32)
			out = append(out, "0x"+hex.EncodeToString(w[:size]))
		}
	}
	return out, nil
}

// Units renders an integer amount with decimals (sun -> TRX with 6).
func Units(v *big.Int, decimals int) string {
	if decimals == 0 {
		return v.String()
	}
	r := new(big.Rat).SetFrac(v, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)).FloatString(decimals)
	if strings.Contains(r, ".") {
		r = strings.TrimRight(strings.TrimRight(r, "0"), ".")
	}
	return r
}
