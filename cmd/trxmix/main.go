// Command trxmix: the TRON HTTP API (java-tron + TronGrid) over the Nym mixnet.
//
//	trxmix nym setup         start nym-socks5-client on a random active exit gateway
//	trxmix serve             local gateway: http://127.0.0.1:8090 (mainnet), /nile, /shasta
//	trxmix info|balance|call|broadcast   talk to a public API directly over the mixnet
//	trxmix probe             which public upstreams answer Nym exit traffic, and how fast
//	trxmix ip                which IP do upstreams see? (a Nym exit gateway)
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/apeirs/trxmix/gateway"
	"github.com/apeirs/trxmix/mixnet"
	"github.com/apeirs/trxmix/tron"
)

const version = "0.1.0"

var start = time.Now()

func tracef(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%7.2fs] "+format+"\n", append([]any{time.Since(start).Seconds()}, args...)...)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "%s "+format+"\n", append([]any{time.Now().Format("15:04:05")}, args...)...)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "trxmix:", err)
	os.Exit(1)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error {
	if s = strings.TrimSpace(s); s != "" {
		*m = append(*m, s)
	}
	return nil
}

type common struct {
	proxy, dns, network, apiURL string
	add                         multi
	verbose, jsonOut            bool
	timeout                     time.Duration
	reg                         *tron.Registry
	nw                          *tron.Network
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.proxy, "proxy", envOr("TRXMIX_PROXY", "127.0.0.1:1090"), "nym-socks5-client SOCKS5 address ($TRXMIX_PROXY)")
	fs.StringVar(&c.dns, "dns", envOr("TRXMIX_DNS", mixnet.DNSDoH), "name resolution: doh (DoH over the mixnet, connect by IPv4) or exit")
	fs.StringVar(&c.network, "network", envOr("TRXMIX_NETWORK", "mainnet"), "mainnet, nile, shasta, or one added with --add")
	fs.StringVar(&c.apiURL, "api", "", "use this https node URL instead of the network's list (still genesis checked)")
	fs.Var(&c.add, "add", "network upstreams: name=https://node[|https://node2] (repeatable; mainnet=... replaces the built-in list)")
	fs.BoolVar(&c.verbose, "v", false, "trace every mixnet step to stderr")
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Minute, "overall timeout for the command")
}

func (c *common) registry() *tron.Registry {
	if c.reg != nil {
		return c.reg
	}
	c.reg = tron.NewRegistry()
	for _, a := range c.add {
		if err := c.reg.ParseAdd(a); err != nil {
			die(fmt.Errorf("--add: %w", err))
		}
	}
	return c.reg
}

func (c *common) dialer() *mixnet.Dialer {
	proxy, err := mixnet.ParseProxy(c.proxy)
	if err != nil {
		die(err)
	}
	if c.dns != mixnet.DNSDoH && c.dns != mixnet.DNSExit {
		die(fmt.Errorf("--dns must be doh or exit"))
	}
	d := &mixnet.Dialer{Proxy: proxy, DNS: c.dns}
	if c.verbose {
		d.Trace = tracef
	}
	return d
}

func (c *common) client() *tron.Client {
	// The key comes only from the environment, never from a flag, so it stays
	// out of shell history and the process list.
	cl := &tron.Client{D: c.dialer(), APIKey: strings.TrimSpace(os.Getenv("TRXMIX_TRONGRID_KEY"))}
	if c.verbose {
		cl.Log = tracef
	}
	return cl
}

// net is the selected network; with --api, the same network (and genesis)
// with that one upstream.
func (c *common) net() *tron.Network {
	if c.nw != nil {
		return c.nw
	}
	n, ok := c.registry().Get(c.network)
	if c.apiURL != "" {
		u := strings.TrimRight(c.apiURL, "/")
		if err := tron.CheckURL(u); err != nil {
			die(err)
		}
		cp := &tron.Network{Name: c.network, Upstreams: []tron.Upstream{{URL: u, JSONRPC: true, V1: true}}}
		if ok {
			cp.Genesis, cp.Tokens = n.GenesisPinned(), n.Tokens
		}
		c.nw = cp
		return cp
	}
	if !ok {
		die(fmt.Errorf("unknown network %q (see `trxmix networks`), or pass --api URL", c.network))
	}
	if len(n.Upstreams) == 0 {
		die(fmt.Errorf("network %s has no upstream; pass --api URL", n.Name))
	}
	c.nw = n
	return n
}

// only is n restricted to the upstream that already answered, so follow-up
// calls of one command see one consistent node. It shares n's name, so the
// genesis check is not repeated.
func only(n *tron.Network, used string) *tron.Network {
	cp := &tron.Network{Name: n.Name, Genesis: n.GenesisPinned(), Tokens: n.Tokens}
	for _, u := range n.Upstreams {
		if u.URL == used {
			cp.Upstreams = []tron.Upstream{u}
		}
	}
	if cp.Upstreams == nil {
		cp.Upstreams = n.Upstreams
	}
	return cp
}

func (c *common) ctx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	return ctx, func() { stop(); cancel() }
}

func (c *common) out(v any, human string) {
	if c.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	fmt.Println(human)
}

// parse allows flags after positional arguments. A lone "-" is positional.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `trxmix `+version+`: the TRON HTTP API (java-tron + TronGrid) through the Nym mixnet

Mixnet client (official nym-socks5-client):
  trxmix nym setup [--binary PATH] [--port 1090]   init on a random active exit gateway, then start
  trxmix nym start | stop | status | exits

Local gateway for wallets and tools (TronWeb, tronpy, curl ...):
  trxmix serve [--listen 127.0.0.1:8090] [--default mainnet] [--listen-net nile=127.0.0.1:8091]
               [--add name=https://node|https://node2] [--allow-origin https://app.example]
     mainnet  http://127.0.0.1:8090           (/wallet/..., /walletsolidity/..., /jsonrpc, /v1/...)
     nile     http://127.0.0.1:8090/nile      (also /shasta, /mainnet, or the root of a --listen-net)

Talk to a public TRON API directly over the mixnet:
  trxmix info                                   latest and solidified block, genesis check
  trxmix balance ADDRESS [--token T...]         TRX, staked TRX, bandwidth, energy, USDT/USDC
  trxmix call CONTRACT 'fn(types)' [ARG...]     constant (read-only) call [--returns uint256,...]
                                                [--from ADDRESS] [--data HEX]
  trxmix broadcast TX_HEX|TX_JSON|FILE|-        forward a signed tx (broadcasthex); holds no keys
  trxmix networks                               built-in networks and upstreams
  trxmix probe [--network all]                  which upstreams work through the mixnet, and how fast
  trxmix ip                                     which IP do upstreams see? (should be a Nym exit gateway)

Common flags: --network mainnet|nile|shasta --api URL --proxy 127.0.0.1:1090 --dns doh|exit -v --json --timeout 5m
Optional TronGrid API key for higher rate limits: TRXMIX_TRONGRID_KEY (sent to *.trongrid.io only, never logged).
trxmix never holds a private key, and there is no clearnet fallback: if the
mixnet client is down, trxmix refuses to connect.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "nym":
		cmdNym(args)
	case "serve":
		cmdServe(args)
	case "info":
		cmdInfo(args)
	case "balance":
		cmdBalance(args)
	case "call":
		cmdCall(args)
	case "broadcast":
		cmdBroadcast(args)
	case "networks":
		cmdNetworks(args)
	case "probe":
		cmdProbe(args)
	case "ip":
		cmdIP(args)
	case "version", "-version", "--version":
		fmt.Println("trxmix", version)
	default:
		usage()
		os.Exit(2)
	}
}

func cmdNetworks(args []string) {
	var c common
	fs := flag.NewFlagSet("networks", flag.ExitOnError)
	c.register(fs)
	parse(fs, args)
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NETWORK\tGENESIS BLOCK ID\tGATEWAY PATH\tUPSTREAMS (in order; +rpc = /jsonrpc, +v1 = TronGrid /v1)")
	for _, n := range c.registry().All() {
		g := n.GenesisPinned()
		if g == "" {
			g = "(pinned on first use)"
		} else {
			g = g[:16] + "..." + g[len(g)-8:]
		}
		var ups []string
		for _, u := range n.Upstreams {
			s := strings.TrimPrefix(u.URL, "https://")
			if u.JSONRPC {
				s += " +rpc"
			}
			if u.V1 {
				s += " +v1"
			}
			ups = append(ups, s)
		}
		fmt.Fprintf(tw, "%s\t%s\t/%s\t%s\n", n.Name, g, n.Name, strings.Join(ups, ", "))
	}
	tw.Flush()
	if os.Getenv("TRXMIX_TRONGRID_KEY") != "" {
		fmt.Fprintln(os.Stderr, "TronGrid API key: set (TRXMIX_TRONGRID_KEY, sent to *.trongrid.io only)")
	}
}

func loopback(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

func cmdServe(args []string) {
	var c common
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	c.register(fs)
	listen := fs.String("listen", "127.0.0.1:8090", "local address: the default network at /, every network at /<name>/")
	var extra multi
	fs.Var(&extra, "listen-net", "another listener with that network at the root: name=127.0.0.1:8091 (repeatable; for clients that drop a base path, e.g. tronpy)")
	def := fs.String("default", "mainnet", "network served at the root (\"\" = none)")
	hosts := fs.String("allow-host", "", "extra Host header values to accept (comma separated)")
	origins := fs.String("allow-origin", "", "web origins allowed to use the gateway, comma separated (\"*\" = any page; browser extensions and non-browser clients are always allowed)")
	parse(fs, args)
	reg := c.registry()
	if *def != "" {
		if _, ok := reg.Get(*def); !ok {
			die(fmt.Errorf("unknown --default network %q", *def))
		}
	}
	type listener struct{ addr, net string }
	ls := []listener{{*listen, *def}}
	for _, e := range extra {
		name, addr, ok := strings.Cut(e, "=")
		if !ok {
			die(fmt.Errorf("--listen-net: want name=host:port, got %q", e))
		}
		if _, found := reg.Get(name); !found {
			die(fmt.Errorf("--listen-net: unknown network %q", name))
		}
		ls = append(ls, listener{addr, strings.ToLower(name)})
	}
	cl := c.client()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	key := "none (keyless: TronGrid's per-IP limits apply to the exit IP, other upstreams take over on 429)"
	if cl.APIKey != "" {
		key = "set, sent to *.trongrid.io only"
	}
	var wg sync.WaitGroup
	for _, l := range ls {
		g := &gateway.Gateway{Client: cl, Nets: reg, Default: l.net, Log: logf}
		if *hosts != "" {
			g.Hosts = strings.Split(*hosts, ",")
		}
		if *origins != "" {
			g.Origins = strings.Split(*origins, ",")
		}
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			die(err)
		}
		if !loopback(l.addr) {
			fmt.Fprintf(os.Stderr, "WARNING: %s is not bound to loopback; anyone who can reach it can use your mixnet client\n", l.addr)
		}
		logf("trxmix gateway on http://%s  (root = %s; SOCKS5 %s; TronGrid API key: %s)", ln.Addr(), l.net, c.proxy, key)
		srv := &http.Server{Handler: g, ReadHeaderTimeout: 30 * time.Second}
		go func() { <-ctx.Done(); srv.Close() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				die(err)
			}
		}()
	}
	wg.Wait()
}

func age(t time.Time) string {
	d := time.Since(t).Round(time.Second)
	if d < 0 {
		d = 0
	}
	return d.String()
}

type block struct {
	BlockID string `json:"blockID"`
	Header  struct {
		Raw struct {
			Number    int64  `json:"number"`
			Timestamp int64  `json:"timestamp"`
			Witness   string `json:"witness_address"`
			Version   int64  `json:"version"`
		} `json:"raw_data"`
	} `json:"block_header"`
}

func witness(h string) string {
	if a, err := tron.AddressFromHex(h); err == nil {
		return a.String()
	}
	return h
}

func cmdInfo(args []string) {
	var c common
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	c.register(fs)
	parse(fs, args)
	ctx, cancel := c.ctx()
	defer cancel()
	cl := c.client()
	n := c.net()
	var b block
	used, err := cl.Post(ctx, n, "/wallet/getnowblock", struct{}{}, &b)
	if err != nil {
		die(err)
	}
	if b.BlockID == "" || b.Header.Raw.Number == 0 {
		die(fmt.Errorf("unexpected getnowblock answer from %s", tron.HostOf(used)))
	}
	t := time.UnixMilli(b.Header.Raw.Timestamp).UTC()
	res := map[string]any{"network": n.Name, "block": b.Header.Raw.Number, "block_id": b.BlockID, "block_time": t,
		"witness": witness(b.Header.Raw.Witness), "genesis": n.GenesisPinned(), "genesis_verified": cl.Verified(n, used), "upstream": used}
	human := fmt.Sprintf("%s: block #%d at %s (%s old), produced by %s", n.Name, b.Header.Raw.Number, t.Format(time.RFC3339), age(t), witness(b.Header.Raw.Witness))
	var sb block
	if _, err := cl.Post(ctx, only(n, used), "/walletsolidity/getnowblock", struct{}{}, &sb); err == nil && sb.Header.Raw.Number > 0 {
		res["solidified_block"] = sb.Header.Raw.Number
		human += fmt.Sprintf("\n  solidified #%d (%d blocks behind)", sb.Header.Raw.Number, b.Header.Raw.Number-sb.Header.Raw.Number)
	}
	human += fmt.Sprintf("\n  block id %s\n  genesis %s verified (via %s over the mixnet)", b.BlockID, n.GenesisPinned(), tron.HostOf(used))
	c.out(res, human)
}

func parseAddr(s string) tron.Address {
	a, err := tron.ParseAddress(s)
	if err != nil {
		die(err)
	}
	return a
}

func trx(sun int64) string { return tron.Units(big.NewInt(sun), 6) + " TRX" }

// constCall runs triggerconstantcontract and returns constant_result[0].
func constCall(ctx context.Context, cl *tron.Client, n *tron.Network, owner, contract tron.Address, sig, param string) (string, string, int64, error) {
	body := map[string]any{"owner_address": owner.String(), "contract_address": contract.String(),
		"function_selector": sig, "visible": true}
	if param != "" {
		body["parameter"] = param
	}
	var r struct {
		Result struct {
			Result  bool   `json:"result"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"result"`
		Constant   []string `json:"constant_result"`
		EnergyUsed int64    `json:"energy_used"`
		Tx         struct {
			Ret []struct {
				Ret string `json:"ret"`
			} `json:"ret"`
		} `json:"transaction"`
	}
	used, err := cl.Post(ctx, n, "/wallet/triggerconstantcontract", body, &r)
	if err != nil {
		return "", used, 0, err
	}
	out := ""
	if len(r.Constant) > 0 {
		out = r.Constant[0]
	}
	failed := !r.Result.Result || (len(r.Tx.Ret) > 0 && r.Tx.Ret[0].Ret == "FAILED")
	if failed {
		msg := tron.HexText(r.Result.Message)
		if msg == "" {
			msg = r.Result.Code
		}
		if reason := revertReason(out); reason != "" {
			msg += ": " + reason
		}
		return out, used, r.EnergyUsed, fmt.Errorf("call failed: %s", msg)
	}
	return out, used, r.EnergyUsed, nil
}

// revertReason decodes Error(string) revert data.
func revertReason(h string) string {
	if !strings.HasPrefix(h, "08c379a0") {
		return ""
	}
	v, err := tron.DecodeResults([]string{"string"}, h[8:])
	if err != nil {
		return ""
	}
	return v[0]
}

func tokenBalance(ctx context.Context, cl *tron.Client, n *tron.Network, holder, contract tron.Address) (*big.Int, error) {
	out, _, _, err := constCall(ctx, cl, n, contract, contract, "balanceOf(address)", hex.EncodeToString(holder.Word()))
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(out)
	if err != nil || len(b) < 32 {
		return nil, fmt.Errorf("balanceOf answer is not a uint256")
	}
	return new(big.Int).SetBytes(b[:32]), nil
}

func cmdBalance(args []string) {
	var c common
	fs := flag.NewFlagSet("balance", flag.ExitOnError)
	c.register(fs)
	var extra multi
	fs.Var(&extra, "token", "another TRC20 contract to report (repeatable)")
	noTokens := fs.Bool("no-tokens", false, "skip the TRC20 balances")
	pos := parse(fs, args)
	if len(pos) != 1 {
		die(fmt.Errorf("usage: trxmix balance ADDRESS [--network mainnet] [--token T...]"))
	}
	addr := parseAddr(pos[0])
	ctx, cancel := c.ctx()
	defer cancel()
	cl := c.client()
	n := c.net()
	var acct struct {
		Address    string `json:"address"`
		Balance    int64  `json:"balance"`
		CreateTime int64  `json:"create_time"`
		FrozenV2   []struct {
			Amount int64  `json:"amount"`
			Type   string `json:"type"`
		} `json:"frozenV2"`
		Type string `json:"type"`
	}
	used, err := cl.Post(ctx, n, "/wallet/getaccount", map[string]any{"address": addr.String(), "visible": true}, &acct)
	if err != nil {
		die(err)
	}
	one := only(n, used)
	res := map[string]any{"address": addr.String(), "network": n.Name, "upstream": used}
	var lines []string
	if acct.Address == "" {
		res["exists"] = false
		lines = append(lines, "  no account on chain (it never received TRX or a token transfer that activates it)")
	} else {
		res["exists"], res["balance_sun"] = true, acct.Balance
		var staked int64
		for _, f := range acct.FrozenV2 {
			staked += f.Amount
		}
		res["staked_sun"] = staked
		l := "  " + trx(acct.Balance)
		if staked > 0 {
			l += fmt.Sprintf(" (plus %s staked)", trx(staked))
		}
		if acct.Type == "Contract" {
			l += ", a contract account"
		}
		lines = append(lines, l)
		var rs struct {
			FreeNetLimit int64 `json:"freeNetLimit"`
			FreeNetUsed  int64 `json:"freeNetUsed"`
			NetLimit     int64 `json:"NetLimit"`
			NetUsed      int64 `json:"NetUsed"`
			EnergyLimit  int64 `json:"EnergyLimit"`
			EnergyUsed   int64 `json:"EnergyUsed"`
		}
		if _, err := cl.Post(ctx, one, "/wallet/getaccountresource", map[string]any{"address": addr.String(), "visible": true}, &rs); err == nil {
			bw := rs.FreeNetLimit - rs.FreeNetUsed + rs.NetLimit - rs.NetUsed
			en := rs.EnergyLimit - rs.EnergyUsed
			res["bandwidth_left"], res["energy_left"] = bw, en
			lines = append(lines, fmt.Sprintf("  bandwidth %d left today (free %d/%d), energy %d left", bw, rs.FreeNetLimit-rs.FreeNetUsed, rs.FreeNetLimit, en))
		}
	}
	if !*noTokens {
		toks := append([]tron.Token(nil), n.Tokens...)
		for _, t := range extra {
			a := parseAddr(t)
			tok := tron.Token{Symbol: "?", Contract: a.String(), Decimals: 0}
			if out, _, _, err := constCall(ctx, cl, one, a, a, "decimals()", ""); err == nil {
				if v, err := tron.DecodeResults([]string{"uint8"}, out); err == nil {
					fmt.Sscan(v[0], &tok.Decimals)
				}
			}
			if out, _, _, err := constCall(ctx, cl, one, a, a, "symbol()", ""); err == nil {
				if v, err := tron.DecodeResults([]string{"string"}, out); err == nil {
					tok.Symbol = strings.Trim(v[0], `"`)
				}
			}
			toks = append(toks, tok)
		}
		tb := map[string]string{}
		for _, t := range toks {
			bal, err := tokenBalance(ctx, cl, one, addr, parseAddr(t.Contract))
			if err != nil {
				lines = append(lines, fmt.Sprintf("  %s (%s): %v", t.Symbol, t.Contract, err))
				continue
			}
			tb[t.Contract] = bal.String()
			lines = append(lines, fmt.Sprintf("  %s %s (TRC20 %s)", tron.Units(bal, t.Decimals), t.Symbol, t.Contract))
		}
		res["trc20"] = tb
	}
	c.out(res, fmt.Sprintf("%s on %s (via %s over the mixnet):\n%s", addr, n.Name, tron.HostOf(used), strings.Join(lines, "\n")))
}

func cmdCall(args []string) {
	var c common
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	c.register(fs)
	from := fs.String("from", "", "caller (owner_address) for the call (default: the contract itself)")
	returns := fs.String("returns", "", "return types to decode, e.g. uint256 or address,uint256 or string")
	data := fs.String("data", "", "ABI-encoded parameters in hex, instead of ARGs (for dynamic types)")
	pos := parse(fs, args)
	if len(pos) < 2 {
		die(fmt.Errorf("usage: trxmix call CONTRACT 'fn(types)' [ARG...] [--returns types]   e.g. trxmix call TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t 'totalSupply()' --returns uint256"))
	}
	contract := parseAddr(pos[0])
	name, types, err := tron.ParseSignature(pos[1])
	if err != nil && !(*data != "" && strings.Contains(err.Error(), "dynamic")) {
		die(err)
	}
	if *data != "" && len(pos) > 2 {
		die(fmt.Errorf("pass either ARGs or --data, not both"))
	}
	var rtypes []string
	if *returns != "" {
		for _, t := range strings.Split(strings.ReplaceAll(*returns, " ", ""), ",") {
			rtypes = append(rtypes, t)
		}
	}
	sig := strings.ReplaceAll(pos[1], " ", "")
	if err == nil {
		sig = name + "(" + strings.Join(types, ",") + ")"
	}
	param := strings.TrimPrefix(*data, "0x")
	if *data == "" {
		if param, err = tron.EncodeArgs(types, pos[2:]); err != nil {
			die(err)
		}
	} else if _, err := hex.DecodeString(param); err != nil || len(param)%64 != 0 {
		die(fmt.Errorf("--data must be hex in 32-byte words"))
	}
	owner := contract
	if *from != "" {
		owner = parseAddr(*from)
	}
	ctx, cancel := c.ctx()
	defer cancel()
	out, used, energy, err := constCall(ctx, c.client(), c.net(), owner, contract, sig, param)
	if err != nil {
		if used != "" {
			err = fmt.Errorf("%w (via %s over the mixnet)", err, tron.HostOf(used))
		}
		die(err)
	}
	res := map[string]any{"result": out, "energy_used": energy, "upstream": used}
	human := fmt.Sprintf("%s on %s -> ", sig, contract)
	if len(rtypes) > 0 {
		vals, err := tron.DecodeResults(rtypes, out)
		if err != nil {
			die(fmt.Errorf("decode: %w (raw %s)", err, out))
		}
		res["values"] = vals
		human += strings.Join(vals, ", ")
	} else {
		var words []string
		for i := 0; i+64 <= len(out); i += 64 {
			words = append(words, out[i:i+64])
		}
		if len(words) == 0 {
			words = []string{"(empty)"}
		}
		human += strings.Join(words, "\n    ") + "\n  (raw words; --returns uint256,... decodes them)"
	}
	human += fmt.Sprintf("\n  energy %d (via %s over the mixnet)", energy, tron.HostOf(used))
	c.out(res, human)
}

func cmdBroadcast(args []string) {
	var c common
	fs := flag.NewFlagSet("broadcast", flag.ExitOnError)
	c.register(fs)
	pos := parse(fs, args)
	if len(pos) != 1 {
		die(fmt.Errorf("usage: trxmix broadcast TX_HEX | TX_JSON | FILE | -   (a signed transaction: protobuf hex, or TronWeb/tronpy JSON)"))
	}
	raw := pos[0]
	if raw == "-" {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 16<<20))
		raw = string(b)
	} else if st, err := os.Stat(raw); err == nil && !st.IsDir() {
		b, err := os.ReadFile(raw)
		if err != nil {
			die(err)
		}
		raw = string(b)
	}
	tx, err := tron.ParseTxInput(raw)
	if err != nil {
		die(err)
	}
	if err := tx.CheckBroadcastable(time.Now()); err != nil {
		die(err)
	}
	ctx, cancel := c.ctx()
	defer cancel()
	n := c.net()
	body, _ := json.Marshal(map[string]string{"transaction": hex.EncodeToString(tx.Bytes())})
	status, rb, used, err := c.client().Fetch(ctx, n, tron.Request{Method: "POST", Path: "/wallet/broadcasthex", Body: body, ContentType: "application/json"})
	if err != nil {
		die(err)
	}
	var r struct {
		Result  bool   `json:"result"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Txid    string `json:"txid"`
		Error   string `json:"Error"`
	}
	_ = json.Unmarshal(rb, &r)
	kinds := strings.Join(tx.Contracts, ", ")
	if status == 200 && r.Result {
		c.out(map[string]any{"txid": tx.ID(), "contracts": tx.Contracts, "upstream": used},
			fmt.Sprintf("broadcast ok: %s (%s) via %s over the mixnet", tx.ID(), kinds, tron.HostOf(used)))
		return
	}
	msg := tron.ErrorText(rb)
	c.out(map[string]any{"status": status, "code": r.Code, "message": tron.HexText(r.Message), "error": r.Error, "txid": tx.ID(), "contracts": tx.Contracts, "upstream": used},
		fmt.Sprintf("rejected by the node: %s\n  txid %s (%s) via %s over the mixnet", msg, tx.ID(), kinds, tron.HostOf(used)))
	os.Exit(1)
}

type probeRow struct {
	network, upstream, wallet, rpc string
	walletS, rpcS                  float64
	ok                             bool
}

func cmdProbe(args []string) {
	var c common
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	c.register(fs)
	par := fs.Int("parallel", 3, "upstreams probed at once")
	parse(fs, args)
	if !flagSet(fs, "network") && os.Getenv("TRXMIX_NETWORK") == "" && c.apiURL == "" {
		c.network = "all"
	}
	ctx, cancel := c.ctx()
	defer cancel()
	cl := c.client()
	var nets []*tron.Network
	if c.network == "all" {
		nets = c.registry().All()
	} else {
		nets = []*tron.Network{c.net()}
	}
	type job struct {
		n  *tron.Network
		up tron.Upstream
		i  int
	}
	var jobs []job
	for _, n := range nets {
		for _, u := range n.Upstreams {
			jobs = append(jobs, job{n, u, len(jobs)})
		}
	}
	rows := make([]probeRow, len(jobs))
	sem := make(chan struct{}, max(1, *par))
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			one := &tron.Network{Name: j.n.Name, Genesis: j.n.GenesisPinned(), Upstreams: []tron.Upstream{j.up}}
			r := probeRow{network: j.n.Name, upstream: strings.TrimPrefix(j.up.URL, "https://")}
			t0 := time.Now()
			var b block
			if _, err := cl.Post(ctx, one, "/wallet/getnowblock", struct{}{}, &b); err != nil {
				r.wallet = short(err)
			} else if b.Header.Raw.Number == 0 {
				r.wallet = "FAIL not a getnowblock answer"
			} else {
				r.wallet = fmt.Sprintf("genesis ok, block #%d", b.Header.Raw.Number)
				r.ok = true
			}
			r.walletS = time.Since(t0).Seconds()
			if !j.up.JSONRPC {
				r.rpc = "-"
			} else {
				t1 := time.Now()
				var rr struct {
					Result string `json:"result"`
				}
				q := []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`)
				if _, err := cl.JSON(ctx, one, tron.Request{Method: "POST", Path: "/jsonrpc", Body: q, ContentType: "application/json"}, &rr); err != nil {
					r.rpc = short(err)
				} else if n, ok := new(big.Int).SetString(strings.TrimPrefix(rr.Result, "0x"), 16); ok {
					r.rpc = fmt.Sprintf("eth_blockNumber %d", n)
				} else {
					r.rpc = "FAIL no result"
				}
				r.rpcS = time.Since(t1).Seconds()
			}
			rows[j.i] = r
		}(j)
	}
	wg.Wait()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NETWORK\tUPSTREAM\tGENESIS CHECK + /wallet/getnowblock\tTIME\t/jsonrpc\tTIME")
	ok := 0
	for _, r := range rows {
		if r.ok {
			ok++
		}
		rs := "-"
		if r.rpc != "-" {
			rs = fmt.Sprintf("%.1fs", r.rpcS)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.1fs\t%s\t%s\n", r.network, r.upstream, r.wallet, r.walletS, r.rpc, rs)
	}
	tw.Flush()
	fmt.Fprintf(os.Stderr, "%d of %d upstreams passed the genesis check and answered through the mixnet\n", ok, len(rows))
}

func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func short(err error) string {
	var ae *tron.APIError
	e := err.Error()
	if errors.As(err, &ae) {
		e = fmt.Sprintf("HTTP %d %s", ae.Status, ae.Msg)
	}
	e = strings.ReplaceAll(e, "\n", "; ")
	if len(e) > 70 {
		e = e[:70]
	}
	return "FAIL " + e
}

func cmdIP(args []string) {
	var c common
	fs := flag.NewFlagSet("ip", flag.ExitOnError)
	c.register(fs)
	noLookup := fs.Bool("no-lookup", false, "don't look the IP up in the nym-api node list")
	parse(fs, args)
	d := c.dialer()
	ctx, cancel := c.ctx()
	defer cancel()
	showIP(ctx, &c, d, *noLookup)
}
