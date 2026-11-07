package tron

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Allowed reports whether a gateway path (cleaned, below the network prefix)
// is one of the TRON API routes trxmix forwards: java-tron's /wallet,
// /walletsolidity, /walletpbft and /jsonrpc, and TronGrid's /v1. Nothing else
// on an upstream host is reachable through the gateway.
func Allowed(path string) bool {
	first, rest, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	switch first {
	case "wallet", "walletsolidity", "walletpbft":
		return rest != ""
	case "jsonrpc":
		return rest == ""
	case "v1":
		return rest != ""
	}
	return false
}

// v1Words are TronGrid /v1 path segments that are route names, never
// parameters. Every other segment is logged as "*", so an address, contract,
// txid or block number never reaches a log line.
var v1Words = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`v1 accounts transactions trc20 trc10 contracts events blocks assets tokens
		transaction internal-transactions latest list name info balances-history`) {
		v1Words[w] = true
	}
}

func validMethod(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == ""
}

// walletMethod: java-tron method names are letters with an optional version
// suffix (getaccount, getReward, getdelegatedresourcev2). A segment that
// parses as an address is never one.
func walletMethod(s string) bool {
	letters := strings.TrimRight(s, "0123456789")
	if len(s)-len(letters) > 2 || letters == "" || len(s) > 48 {
		return false
	}
	if strings.Trim(letters, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		return false
	}
	_, err := ParseAddress(s)
	return err != nil
}

// Label turns a request into a log-safe template: the java-tron method name
// (/wallet/getaccount), the JSON-RPC method (/jsonrpc eth_call) or the /v1
// route (/v1/accounts/*/transactions/trc20). Addresses, amounts, txids,
// query strings and bodies never appear.
func Label(method, path string, body []byte) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	switch segs[0] {
	case "wallet", "walletsolidity", "walletpbft":
		for i := 1; i < len(segs); i++ {
			if i > 1 || !walletMethod(segs[i]) {
				segs[i] = "*"
			}
		}
		return "/" + strings.Join(segs, "/")
	case "jsonrpc":
		return "/jsonrpc" + rpcMethods(body)
	case "v1":
		for i, s := range segs {
			if !v1Words[s] {
				segs[i] = "*"
			}
		}
		return "/" + strings.Join(segs, "/")
	}
	for i := range segs {
		segs[i] = "*"
	}
	return "/" + strings.Join(segs, "/")
}

// rpcMethods names the JSON-RPC method(s) of a body, never their params.
func rpcMethods(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	name := func(raw json.RawMessage) string {
		var m struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(raw, &m) != nil || !validMethod(m.Method, 48) {
			return "*"
		}
		return m.Method
	}
	var batch []json.RawMessage
	if json.Unmarshal(body, &batch) == nil {
		counts := map[string]int{}
		var order []string
		for _, r := range batch {
			n := name(r)
			if counts[n] == 0 {
				order = append(order, n)
			}
			counts[n]++
		}
		var parts []string
		for i, n := range order {
			if i == 4 {
				parts = append(parts, "...")
				break
			}
			parts = append(parts, fmt.Sprintf("%s x%d", n, counts[n]))
		}
		return fmt.Sprintf(" batch of %d (%s)", len(batch), strings.Join(parts, ", "))
	}
	return " " + name(body)
}
