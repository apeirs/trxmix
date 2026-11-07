package tron

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// A real mainnet transaction body (a triggerconstantcontract answer for the
// USDT contract, 2026-11-07) and its txID as the node reported it.
const (
	vecRaw  = "0a02b67a22089b4aa1df8736387d40e8e49db89b345a6d081f12690a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412340a1541a614f803b6fd780986a42c78ec9c7f77e6ded13c121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2204f0d5889970c4a79ab89b34"
	vecTxID = "b54b213b4a98704ea92d7a76f0c257154976f679870cda4dc872d5ba2f4e74ea"
	usdt    = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	usdtHex = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
)

func TestAddress(t *testing.T) {
	a, err := ParseAddress(usdt)
	if err != nil || a.Hex() != usdtHex {
		t.Fatalf("%s -> %s %v", usdt, a.Hex(), err)
	}
	if a.String() != usdt {
		t.Fatalf("round trip: %s", a)
	}
	for _, s := range []string{usdtHex, "0x" + usdtHex[2:]} {
		if b, err := ParseAddress(s); err != nil || b != a {
			t.Fatalf("%s: %v %v", s, b, err)
		}
	}
	// The zero account (the "black hole" address) keeps its leading byte.
	z, _ := ParseAddress("410000000000000000000000000000000000000000")
	if z.String() != "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb" {
		t.Fatalf("zero address: %s", z)
	}
	for _, bad := range []string{
		"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u",         // checksum
		"1BoatSLRHtKNngkdXEeobR76b53LETtpyT",         // Bitcoin address (version 0x00)
		"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6",          // short
		"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj60",         // '0' is not base58
		"0x1234",                                     // short hex
		"42a614f803b6fd780986a42c78ec9c7f77e6ded13c", // not 41
	} {
		if _, err := ParseAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	w := a.Word()
	if hex.EncodeToString(w) != "000000000000000000000000"+usdtHex[2:] {
		t.Fatalf("word: %x", w)
	}
}

func TestParseTx(t *testing.T) {
	raw, _ := hex.DecodeString(vecRaw)
	sig := strings.Repeat("ab", 65)
	// field 1 (raw_data, length as a varint), field 2 (one 65-byte signature)
	signed := "0a" + hex.EncodeToString(binary.AppendUvarint(nil, uint64(len(raw)))) + vecRaw + "1241" + sig
	tx, err := ParseTxInput(signed)
	if err != nil {
		t.Fatal(err)
	}
	if tx.ID() != vecTxID || len(tx.Signatures) != 1 || len(tx.Contracts) != 1 || tx.Contracts[0] != "TriggerSmartContract" {
		t.Fatalf("%s %d %v", tx.ID(), len(tx.Signatures), tx.Contracts)
	}
	if hex.EncodeToString(tx.RefBlockHash) != "9b4aa1df8736387d" || tx.Expiration.UnixMilli() != 1794072081000 {
		t.Fatalf("ref %x exp %v", tx.RefBlockHash, tx.Expiration)
	}
	if hex.EncodeToString(tx.Bytes()) != signed {
		t.Fatal("re-serialization differs")
	}
	before := tx.Expiration.Add(-time.Minute)
	if err := tx.CheckBroadcastable(before); err != nil {
		t.Fatalf("signed, unexpired: %v", err)
	}
	if err := tx.CheckBroadcastable(tx.Expiration.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired accepted: %v", err)
	}
	short := &Tx{Raw: tx.Raw, Signatures: [][]byte{make([]byte, 64)}}
	if err := short.CheckBroadcastable(before); err == nil {
		t.Fatal("64-byte signature accepted")
	}
	// TronWeb's JSON form gives the same bytes; an edited one is caught.
	js := `{"visible":false,"txID":"` + vecTxID + `","raw_data":{},"raw_data_hex":"` + vecRaw + `","signature":["` + sig + `"]}`
	tj, err := ParseTxInput(js)
	if err != nil || hex.EncodeToString(tj.Bytes()) != signed {
		t.Fatalf("json: %v", err)
	}
	if _, err := ParseTxInput(strings.Replace(js, vecTxID, strings.Repeat("0", 64), 1)); err == nil {
		t.Fatal("txID mismatch accepted")
	}
	// Unsigned: parses, no signatures (the CLI refuses it).
	u, err := ParseTxInput(`{"txID":"` + vecTxID + `","raw_data_hex":"` + vecRaw + `"}`)
	if err != nil || len(u.Signatures) != 0 {
		t.Fatalf("unsigned: %v", err)
	}
	if err := u.CheckBroadcastable(before); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned accepted: %v", err)
	}
	// A transaction followed by a field Transaction doesn't have is not one.
	for _, junk := range []string{"0a02dead", "deadbeef", "zz", "", "0a00", "{}", "1203abcdef", signed + "1801", signed + "2a00ff"} {
		if _, err := ParseTxInput(junk); err == nil {
			t.Errorf("junk %q accepted", junk)
		}
	}
}

func TestABI(t *testing.T) {
	name, types, err := ParseSignature("transfer(address, uint)")
	if err != nil || name != "transfer" || strings.Join(types, ",") != "address,uint256" {
		t.Fatalf("%s %v %v", name, types, err)
	}
	p, err := EncodeArgs(types, []string{usdt, "1000000"})
	if err != nil || p != "000000000000000000000000"+usdtHex[2:]+"00000000000000000000000000000000000000000000000000000000000f4240" {
		t.Fatalf("%s %v", p, err)
	}
	if p, _ := EncodeArgs([]string{"int256", "bool", "bytes4"}, []string{"-1", "true", "0xdeadbeef"}); p != strings.Repeat("f", 64)+strings.Repeat("0", 63)+"1"+"deadbeef"+strings.Repeat("0", 56) {
		t.Fatalf("int/bool/bytes4: %s", p)
	}
	for _, c := range [][2]string{{"uint8", "256"}, {"uint256", "-1"}, {"int8", "128"}, {"bool", "yes"}, {"bytes4", "0xdead"}, {"address", "Tnope"}} {
		if _, err := EncodeArgs([]string{c[0]}, []string{c[1]}); err == nil {
			t.Errorf("%s %s accepted", c[0], c[1])
		}
	}
	for _, s := range []string{"f(string)", "f(uint256[])", "1f()", "f", "f(uint7)", "f(bytes33)"} {
		if _, _, err := ParseSignature(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
	// symbol() of USDT, as the node returned it.
	sym := "0000000000000000000000000000000000000000000000000000000000000020" + "0000000000000000000000000000000000000000000000000000000000000004" + "5553445400000000000000000000000000000000000000000000000000000000"
	v, err := DecodeResults([]string{"string"}, sym)
	if err != nil || v[0] != `"USDT"` {
		t.Fatalf("string: %v %v", v, err)
	}
	v, err = DecodeResults([]string{"address", "uint256", "int256", "bool"}, "000000000000000000000000"+usdtHex[2:]+"00000000000000000000000000000000000000000000000000000000000f4240"+strings.Repeat("f", 64)+strings.Repeat("0", 63)+"1")
	if err != nil || strings.Join(v, " ") != usdt+" 1000000 -1 true" {
		t.Fatalf("static: %v %v", v, err)
	}
	if _, err := DecodeResults([]string{"uint256", "uint256"}, strings.Repeat("0", 64)); err == nil {
		t.Fatal("short result decoded")
	}
	if Units(big.NewInt(773688608175), 6) != "773688.608175" || Units(big.NewInt(1000000), 6) != "1" || Units(big.NewInt(0), 6) != "0" {
		t.Fatal("units")
	}
}

// lettersOnly finds a valid address with no digits (about 1 in 260 are), so
// it passes the method-name shape test and only the address check stops it.
func lettersOnly(t *testing.T) string {
	for i := 0; i < 100000; i++ {
		h := sha256.Sum256([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
		var a Address
		a[0] = AddressPrefix
		copy(a[1:], h[:20])
		if s := a.String(); strings.Trim(s, "0123456789") == s && !strings.ContainsAny(s, "0123456789") {
			return s
		}
	}
	t.Fatal("no letters-only address found")
	return ""
}

func TestLabel(t *testing.T) {
	for _, c := range [][3]string{
		{"/wallet/getaccount", "", "/wallet/getaccount"},
		{"/wallet/getReward", "", "/wallet/getReward"},
		{"/walletsolidity/getdelegatedresourcev2", "", "/walletsolidity/getdelegatedresourcev2"},
		{"/wallet/" + usdt, "", "/wallet/*"},
		{"/wallet/getaccount/" + usdt, "", "/wallet/getaccount/*"},
		{"/wallet/get_account", "", "/wallet/*"},
		{"/wallet/" + lettersOnly(t), "", "/wallet/*"},
		{"/v1/accounts/" + usdt + "/transactions/trc20", "", "/v1/accounts/*/transactions/trc20"},
		{"/v1/transactions/" + vecTxID + "/events", "", "/v1/transactions/*/events"},
		{"/jsonrpc", `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0x` + usdtHex[2:] + `","latest"]}`, "/jsonrpc eth_getBalance"},
		{"/jsonrpc", `[{"method":"eth_call","params":[]},{"method":"eth_call"},{"method":"eth_chainId"}]`, "/jsonrpc batch of 3 (eth_call x2, eth_chainId x1)"},
		{"/jsonrpc", `{"method":"` + usdt + `x/y"}`, "/jsonrpc *"},
		{"/elsewhere/x", "", "/*/*"},
	} {
		if got := Label("POST", c[0], []byte(c[1])); got != c[2] {
			t.Errorf("Label(%s, %s) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	for p, want := range map[string]bool{"/wallet/getnowblock": true, "/walletsolidity/x": true, "/jsonrpc": true, "/v1/accounts/x": true,
		"/wallet": false, "/jsonrpc/x": false, "/v1": false, "/": false, "/healthcheck": false, "/wallet2/x": false, "/admin": false} {
		if Allowed(p) != want {
			t.Errorf("Allowed(%s) = %v", p, !want)
		}
	}
}

func TestNetworks(t *testing.T) {
	reg := NewRegistry()
	for _, name := range []string{"mainnet", "nile", "shasta"} {
		n, ok := reg.Get(name)
		if !ok || len(n.Genesis) != 64 || len(n.Upstreams) == 0 {
			t.Fatalf("%s: %+v", name, n)
		}
		for _, u := range n.Upstreams {
			if err := CheckURL(u.URL); err != nil {
				t.Error(err)
			}
		}
	}
	m, _ := reg.Get("mainnet")
	if len(m.Upstreams) < 3 || len(m.For("/v1/accounts/x")) != 1 || len(m.For("/jsonrpc")) != 2 || len(m.For("/wallet/getnowblock")) != 3 {
		t.Fatalf("mainnet routing: %+v", m.Upstreams)
	}
	if err := m.CheckGenesis(strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong genesis accepted")
	}
	if err := m.CheckGenesis("0x" + strings.ToUpper(m.Genesis)); err != nil {
		t.Fatal(err)
	}
	if err := reg.ParseAdd("private=https://node.example|https://node2.example"); err != nil {
		t.Fatal(err)
	}
	p, _ := reg.Get("private")
	if p.GenesisPinned() != "" || p.CheckGenesis("AB") != nil || p.GenesisPinned() != "ab" || p.CheckGenesis("cd") == nil {
		t.Fatal("custom network must pin its genesis on first use")
	}
	for _, spec := range []string{"x=http://node.example", "x=https://u:p@node.example", "wallet=https://node.example", "x=https://node.example?apikey=1", "Bad Name=https://a"} {
		if err := reg.ParseAdd(spec); err == nil {
			t.Errorf("--add %s accepted", spec)
		}
	}
	// --add mainnet=... replaces the upstreams and keeps the genesis.
	reg.ParseAdd("mainnet=https://my-node.example")
	if m, _ := reg.Get("mainnet"); len(m.Upstreams) != 1 || m.Genesis != Networks[0].Genesis {
		t.Fatalf("mainnet after --add: %+v", m)
	}
	if !IsTronGrid("api.trongrid.io") || !IsTronGrid("NILE.trongrid.io.") || IsTronGrid("trongrid.io.evil.example") || IsTronGrid("faketrongrid.io") {
		t.Fatal("IsTronGrid")
	}
	if HexText("5369676e6174757265206572726f72") != "Signature error" {
		t.Fatal("HexText")
	}
	if HexText("not hex") != "not hex" || HexText("00ff") != "00ff" {
		t.Fatal("HexText passthrough")
	}
}
