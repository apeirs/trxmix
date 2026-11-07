package tron

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tx is the part of a serialized protocol.Transaction that trxmix checks
// before it broadcasts: trxmix never builds or signs one.
type Tx struct {
	Raw          []byte   // raw_data, exactly as serialized (the txid is its sha256)
	Signatures   [][]byte // 65-byte secp256k1 signatures
	Contracts    []string // contract types, e.g. "TransferContract"
	RefBlockHash []byte   // bytes 8..16 of the referenced block id
	Expiration   time.Time
}

// ID is the transaction id: sha256 of raw_data.
func (t *Tx) ID() string {
	h := sha256.Sum256(t.Raw)
	return hex.EncodeToString(h[:])
}

// CheckBroadcastable refuses, before anything is sent, a transaction that
// no node would accept: unsigned, with a malformed signature, or expired.
func (t *Tx) CheckBroadcastable(now time.Time) error {
	if len(t.Signatures) == 0 {
		return fmt.Errorf("transaction %s is not signed: trxmix only forwards signed transactions (it holds no keys)", t.ID())
	}
	for _, s := range t.Signatures {
		if len(s) != 65 {
			return fmt.Errorf("transaction %s has a %d-byte signature, want 65", t.ID(), len(s))
		}
	}
	if !t.Expiration.IsZero() && now.After(t.Expiration) {
		return fmt.Errorf("transaction %s expired at %s (%s ago); sign a new one", t.ID(), t.Expiration.Format(time.RFC3339), now.Sub(t.Expiration).Round(time.Second))
	}
	return nil
}

// Bytes re-serializes the transaction (raw_data and signatures only).
func (t *Tx) Bytes() []byte {
	out := appendField(nil, 1, t.Raw)
	for _, s := range t.Signatures {
		out = appendField(out, 2, s)
	}
	return out
}

func appendField(b []byte, field int, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

// pbField is one protobuf field: a varint or a length-delimited value.
type pbField struct {
	num    int
	wire   int
	varint uint64
	bytes  []byte
}

func pbParse(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, errors.New("bad field key")
		}
		b = b[n:]
		f := pbField{num: int(key >> 3), wire: int(key & 7)}
		if f.num == 0 {
			return nil, errors.New("field number 0")
		}
		switch f.wire {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return nil, errors.New("bad varint")
			}
			f.varint, b = v, b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errors.New("truncated fixed64")
			}
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return nil, errors.New("truncated field")
			}
			f.bytes, b = b[n:n+int(l)], b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errors.New("truncated fixed32")
			}
			b = b[4:]
		default:
			return nil, fmt.Errorf("unsupported wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out, nil
}

// ParseTx decodes a serialized protocol.Transaction.
func ParseTx(b []byte) (*Tx, error) {
	fields, err := pbParse(b)
	if err != nil {
		return nil, fmt.Errorf("not a TRON transaction: %w", err)
	}
	t := &Tx{}
	for _, f := range fields {
		switch {
		case f.num == 1 && f.wire == 2:
			if t.Raw != nil {
				return nil, errors.New("not a TRON transaction: two raw_data fields")
			}
			t.Raw = f.bytes
		case f.num == 2 && f.wire == 2:
			t.Signatures = append(t.Signatures, f.bytes)
		case f.num == 5:
			// ret: results, set by nodes on returned transactions
		default:
			return nil, fmt.Errorf("not a TRON transaction: unexpected field %d", f.num)
		}
	}
	if t.Raw == nil {
		return nil, errors.New("not a TRON transaction: no raw_data")
	}
	raw, err := pbParse(t.Raw)
	if err != nil {
		return nil, fmt.Errorf("not a TRON transaction: raw_data: %w", err)
	}
	for _, f := range raw {
		switch {
		case f.num == 4 && f.wire == 2:
			t.RefBlockHash = f.bytes
		case f.num == 8 && f.wire == 0:
			t.Expiration = time.UnixMilli(int64(f.varint)).UTC()
		case f.num == 11 && f.wire == 2:
			t.Contracts = append(t.Contracts, contractType(f.bytes))
		}
	}
	if len(t.Contracts) == 0 {
		return nil, errors.New("not a TRON transaction: no contract in raw_data")
	}
	return t, nil
}

// contractType reads the type name from a Contract's parameter (a
// google.protobuf.Any with type_url type.googleapis.com/protocol.X).
func contractType(b []byte) string {
	fields, err := pbParse(b)
	if err != nil {
		return "?"
	}
	for _, f := range fields {
		if f.num == 2 && f.wire == 2 {
			any, err := pbParse(f.bytes)
			if err != nil {
				return "?"
			}
			for _, a := range any {
				if a.num == 1 && a.wire == 2 {
					s := string(a.bytes)
					if i := strings.LastIndexByte(s, '.'); i >= 0 {
						s = s[i+1:]
					}
					if validMethod(s, 64) {
						return s
					}
				}
			}
		}
	}
	return "?"
}

// ParseTxInput reads a transaction as protobuf hex (what broadcasthex takes)
// or as the JSON object TronWeb and tronpy produce ({"txID", "raw_data_hex",
// "signature": [...]}). For JSON, a txID that is not sha256(raw_data) is an
// error.
func ParseTxInput(s string) (*Tx, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		var j struct {
			TxID       string   `json:"txID"`
			RawDataHex string   `json:"raw_data_hex"`
			Signature  []string `json:"signature"`
		}
		if err := json.Unmarshal([]byte(s), &j); err != nil {
			return nil, fmt.Errorf("transaction JSON: %w", err)
		}
		raw, err := hex.DecodeString(j.RawDataHex)
		if err != nil || len(raw) == 0 {
			return nil, errors.New("transaction JSON has no raw_data_hex")
		}
		t := &Tx{Raw: raw}
		for _, sh := range j.Signature {
			sig, err := hex.DecodeString(sh)
			if err != nil {
				return nil, errors.New("transaction JSON: signature is not hex")
			}
			t.Signatures = append(t.Signatures, sig)
		}
		t2, err := ParseTx(t.Bytes())
		if err != nil {
			return nil, err
		}
		if j.TxID != "" && !strings.EqualFold(j.TxID, t2.ID()) {
			return nil, fmt.Errorf("txID %s is not sha256(raw_data_hex) = %s: the JSON was edited after it was built", j.TxID, t2.ID())
		}
		return t2, nil
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, errors.New("not hex and not transaction JSON")
	}
	return ParseTx(b)
}
