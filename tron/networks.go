// Package tron talks to public TRON full-node HTTP APIs (java-tron's
// /wallet, /walletsolidity, /jsonrpc, and TronGrid's /v1) through the Nym
// mixnet.
package tron

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Upstream is one public API endpoint and what it serves besides java-tron's
// /wallet and /walletsolidity routes (which every full node has).
type Upstream struct {
	URL     string
	JSONRPC bool // /jsonrpc (Ethereum-style JSON-RPC)
	V1      bool // TronGrid's indexed /v1/... API
}

// Token is a TRC20 token that `balance` reports.
type Token struct {
	Symbol   string
	Contract string // base58
	Decimals int
}

// Network is a TRON network with public, keyless upstreams (tried in order).
type Network struct {
	Name string
	// Genesis is the block-0 blockID. Every upstream is checked against it
	// before it gets a request; a custom network pins it on first use.
	Genesis   string
	Upstreams []Upstream
	Tokens    []Token
}

// Networks are the built-in networks (checked 2026-11-07). Any other one (a
// private net, your own node) can be added with --add name=https://host.
var Networks = []Network{
	{"mainnet", "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc",
		[]Upstream{
			{"https://api.trongrid.io", true, true},          // TRON DAO
			{"https://tron-rpc.publicnode.com", true, false}, // Allnodes
			{"https://api.tronstack.io", false, false},       // TronStack
		},
		[]Token{{"USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 6}, {"USDC", "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", 6}}},
	{"nile", "0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc",
		[]Upstream{{"https://nile.trongrid.io", true, true}},
		[]Token{{"USDT", "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf", 6}}},
	{"shasta", "0000000000000000de1aa88295e1fcf982742f773e0419c5a9c134c994a9059e",
		[]Upstream{{"https://api.shasta.trongrid.io", true, true}},
		nil},
}

// reserved names can't be network names: they are first path segments of
// the API served at the gateway root.
var reserved = map[string]bool{"wallet": true, "walletsolidity": true, "walletpbft": true, "jsonrpc": true,
	"v1": true, "all": true, "custom": true, "healthcheck": true}

var genesisMu sync.Mutex

// CheckGenesis compares an upstream's block-0 id with the network's. A
// network without one pins it.
func (n *Network) CheckGenesis(got string) error {
	got = strings.ToLower(strings.TrimPrefix(got, "0x"))
	genesisMu.Lock()
	defer genesisMu.Unlock()
	if n.Genesis == "" {
		n.Genesis = got
		return nil
	}
	if !strings.EqualFold(n.Genesis, got) {
		return fmt.Errorf("serves a different chain (genesis %.20s..., want %.20s...)", got, n.Genesis)
	}
	return nil
}

// GenesisPinned returns the network's genesis id ("" before first use of a
// custom network).
func (n *Network) GenesisPinned() string {
	genesisMu.Lock()
	defer genesisMu.Unlock()
	return n.Genesis
}

// URLs lists the upstream base URLs.
func (n *Network) URLs() []string {
	var out []string
	for _, u := range n.Upstreams {
		out = append(out, u.URL)
	}
	return out
}

// For returns the upstreams that serve path, in order: /jsonrpc and /v1/ are
// not on every node.
func (n *Network) For(path string) []Upstream {
	var out []Upstream
	for _, u := range n.Upstreams {
		switch {
		case path == "/jsonrpc" || strings.HasPrefix(path, "/jsonrpc/"):
			if !u.JSONRPC {
				continue
			}
		case strings.HasPrefix(path, "/v1/"):
			if !u.V1 {
				continue
			}
		}
		out = append(out, u)
	}
	return out
}

// Registry holds the built-in networks plus custom ones.
type Registry struct {
	m map[string]*Network
}

// NewRegistry returns a registry with the built-in networks.
func NewRegistry() *Registry {
	r := &Registry{m: map[string]*Network{}}
	for i := range Networks {
		n := Networks[i]
		n.Upstreams = append([]Upstream(nil), n.Upstreams...)
		r.m[n.Name] = &n
	}
	return r
}

// ValidName reports whether s can name a network in gateway paths.
func ValidName(s string) error {
	if s == "" || len(s) > 40 || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return fmt.Errorf("network name %q: use lowercase letters, digits, - and _", s)
	}
	if reserved[s] {
		return fmt.Errorf("network name %q is reserved (it is an API route at the gateway root)", s)
	}
	return nil
}

// CheckURL accepts only https URLs without credentials, query or fragment.
func CheckURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s: only https upstreams are allowed", s)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s: no credentials, query or fragment in upstream URLs", s)
	}
	return nil
}

// Add sets the upstreams of a network, creating it if new. Custom upstreams
// replace the built-in list (so --add mainnet=https://my-node works too) and
// are assumed to serve /jsonrpc and /v1 as well. A new network has no
// genesis yet: the first upstream that answers pins it.
func (r *Registry) Add(name string, urls []string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if err := ValidName(name); err != nil {
		return err
	}
	var ups []Upstream
	for _, u := range urls {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u == "" {
			continue
		}
		if err := CheckURL(u); err != nil {
			return err
		}
		ups = append(ups, Upstream{URL: u, JSONRPC: true, V1: true})
	}
	if len(ups) == 0 {
		return fmt.Errorf("network %q: no upstream URL", name)
	}
	n, ok := r.m[name]
	if !ok {
		n = &Network{Name: name}
		r.m[name] = n
	}
	n.Upstreams = ups
	return nil
}

// ParseAdd parses "name=https://a|https://b" into the registry.
func (r *Registry) ParseAdd(spec string) error {
	n, u, ok := strings.Cut(spec, "=")
	if !ok {
		return fmt.Errorf("want name=https://url[|https://url2], got %q", spec)
	}
	return r.Add(n, strings.Split(u, "|"))
}

// Get finds a network by name (case-insensitive).
func (r *Registry) Get(name string) (*Network, bool) {
	n, ok := r.m[strings.ToLower(strings.TrimSpace(name))]
	return n, ok
}

// All returns the networks, built-ins first, then custom ones by name.
func (r *Registry) All() []*Network {
	var out []*Network
	seen := map[string]bool{}
	for _, b := range Networks {
		out = append(out, r.m[b.Name])
		seen[b.Name] = true
	}
	var extra []string
	for n := range r.m {
		if !seen[n] {
			extra = append(extra, n)
		}
	}
	sort.Strings(extra)
	for _, n := range extra {
		out = append(out, r.m[n])
	}
	return out
}
