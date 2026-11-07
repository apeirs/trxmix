package trxmix_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apeirs/trxmix/gateway"
	"github.com/apeirs/trxmix/internal/fakes"
	"github.com/apeirs/trxmix/mixnet"
	"github.com/apeirs/trxmix/tron"
)

const (
	mainGenesis = "00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc"
	nileGenesis = "0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc"
	testAddr    = "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"
	testUSDT    = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	testParam   = "0000000000000000000000005a523b449890854c8fc460ab602df9f31fe4293f"
	testTxHex   = "0a8a010a02b67a22089b4aa1df8736387d40e8e49db89b34deadbeef"
	testTxID    = "feedface0123456789abcdef"
	testKey     = "trongrid-key-0123456789"
)

// seen is one request as a fake upstream received it.
type seen struct {
	Host, Method, Path, RawQuery, Body string
	Header                             http.Header
}

type world struct {
	socks *fakes.SOCKS
	d     *mixnet.Dialer
	cl    *tron.Client
	mu    sync.Mutex
	got   []seen
	logs  []string
}

func (w *world) record(r *http.Request) seen {
	b, _ := io.ReadAll(r.Body)
	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}
	s := seen{host, r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Clone()}
	w.mu.Lock()
	w.got = append(w.got, s)
	w.mu.Unlock()
	return s
}

func (w *world) last(host string) seen {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := len(w.got) - 1; i >= 0; i-- {
		if w.got[i].Host == host {
			return w.got[i]
		}
	}
	return seen{}
}

// paths lists every path host was asked for, in order.
func (w *world) paths(host string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, s := range w.got {
		if s.Host == host {
			out = append(out, s.Path)
		}
	}
	return out
}

func (w *world) logf(f string, a ...any) {
	w.mu.Lock()
	w.logs = append(w.logs, fmt.Sprintf(f, a...))
	w.mu.Unlock()
}

func (w *world) allLogs() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.logs, "\n")
}

// node is a fake java-tron + TronGrid HTTP API for the chain with genesis g.
// late503 makes it pass the genesis check and then fail everything else.
func (w *world) node(g string, late503 bool) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		s := w.record(r)
		rw.Header().Set("Set-Cookie", "track=1")
		rw.Header().Set("X-Upstream-Secret", "1")
		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		p := s.Path
		if p == "/wallet/getblockbynum" && s.Body == `{"num":0}` {
			fmt.Fprintf(rw, `{"blockID":"%s","block_header":{"raw_data":{"number":0}}}`, g)
			return
		}
		if late503 {
			http.Error(rw, "upstream overloaded", 503)
			return
		}
		switch {
		case p == "/wallet/getnowblock" || p == "/walletsolidity/getnowblock":
			fmt.Fprintf(rw, `{"blockID":"00000000053bb681aa","block_header":{"raw_data":{"number":87799425,"timestamp":1794071988000,"witness_address":"4170df4a99c7e3e249b290b43e11eb2368afd59899"}}}`)
		case p == "/wallet/getaccount":
			io.WriteString(rw, `{"address":"`+testAddr+`","balance":1100001}`)
		case p == "/wallet/triggerconstantcontract":
			io.WriteString(rw, `{"result":{"result":true},"constant_result":["00000000000000000000000000000000000000000000000000000000000f4240"],"energy_used":935}`)
		case p == "/wallet/broadcasthex":
			io.WriteString(rw, `{"result":false,"code":"SIGERROR","message":"56616c6964617465207369676e6174757265206572726f72"}`)
		case p == "/jsonrpc":
			io.WriteString(rw, `{"jsonrpc":"2.0","id":1,"result":"0x2b6653dc"}`)
		case strings.HasPrefix(p, "/v1/"):
			io.WriteString(rw, `{"data":[],"success":true,"meta":{"page_size":0}}`)
		case p == "/wallet/redirect":
			rw.Header().Set("Location", "http://plain.example/wallet/getnowblock")
			rw.WriteHeader(302)
		default:
			rw.WriteHeader(404)
			io.WriteString(rw, `{"Error":"not found"}`)
		}
	}
}

// The fake world. api.trongrid.io and other.example are good mainnet nodes,
// nile.trongrid.io is Nile, wrong.example is a Nile node posing as mainnet,
// bad.example answers 500, busy.trongrid.io 429, slow.example never answers,
// late.example passes the genesis check and then answers 503, drop.example
// passes it and then drops the connection, and redir.example redirects
// everything. All are TLS, reachable only through
// the fake SOCKS proxy, with names known only to the fake DoH resolver.
func newWorld(t *testing.T) *world {
	t.Helper()
	ca := fakes.NewCA()
	w := &world{}
	serve := func(h http.HandlerFunc, name string) string {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.Leaf(name)}, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: h}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return ln.Addr().String()
	}
	good := serve(w.node(mainGenesis, false), "api.trongrid.io")
	other := serve(w.node(mainGenesis, false), "other.example")
	nile := serve(w.node(nileGenesis, false), "nile.trongrid.io")
	wrong := serve(w.node(nileGenesis, false), "wrong.example")
	late := serve(w.node(mainGenesis, true), "late.example")
	bad := serve(func(rw http.ResponseWriter, r *http.Request) { w.record(r); http.Error(rw, "boom", 500) }, "bad.example")
	busy := serve(func(rw http.ResponseWriter, r *http.Request) {
		w.record(r)
		http.Error(rw, `{"Error":"request rate exceeded the allowed_rps(3)"}`, 429)
	}, "busy.trongrid.io")
	slow := serve(func(rw http.ResponseWriter, r *http.Request) {
		w.record(r)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}, "slow.example")
	drop := serve(func(rw http.ResponseWriter, r *http.Request) {
		s := w.record(r)
		if s.Path == "/wallet/getblockbynum" {
			fmt.Fprintf(rw, `{"blockID":"%s"}`, mainGenesis)
			return
		}
		conn, _, _ := rw.(http.Hijacker).Hijack()
		conn.Close()
	}, "drop.example")
	redir := serve(func(rw http.ResponseWriter, r *http.Request) {
		w.record(r)
		http.Redirect(rw, r, "https://other.example/wallet/getnowblock", http.StatusTemporaryRedirect)
	}, "redir.example")
	doh := fakes.DoH(ca, "1.1.1.1", map[string][]string{
		"api.trongrid.io": {"192.0.2.9"}, "other.example": {"192.0.2.10"}, "nile.trongrid.io": {"192.0.2.11"},
		"wrong.example": {"192.0.2.12"}, "late.example": {"192.0.2.13"}, "bad.example": {"192.0.2.8"},
		"busy.trongrid.io": {"192.0.2.7"}, "slow.example": {"192.0.2.6"}, "redir.example": {"192.0.2.14"}, "drop.example": {"192.0.2.15"}})
	w.socks = fakes.NewSOCKS(map[string]string{"1.1.1.1:443": doh, "192.0.2.9:443": good, "192.0.2.10:443": other,
		"192.0.2.11:443": nile, "192.0.2.12:443": wrong, "192.0.2.13:443": late, "192.0.2.8:443": bad,
		"192.0.2.7:443": busy, "192.0.2.6:443": slow, "192.0.2.14:443": redir, "192.0.2.15:443": drop})
	t.Cleanup(w.socks.Close)
	w.d = &mixnet.Dialer{Proxy: w.socks.Addr, DNS: mixnet.DNSDoH, RootCAs: ca.Pool, Resolvers: []string{"1.1.1.1"}, Timeout: 5 * time.Second}
	w.cl = &tron.Client{D: w.d, Timeout: 10 * time.Second, Log: w.logf}
	return w
}

// registry: mainnet = bad (500), then api.trongrid.io (TronGrid: +rpc +v1),
// then other.example (a plain node); nile = busy (429), then nile.trongrid.io.
func (w *world) registry(t *testing.T) *tron.Registry {
	reg := tron.NewRegistry()
	m, _ := reg.Get("mainnet")
	m.Upstreams = []tron.Upstream{{URL: "https://bad.example"}, {URL: "https://api.trongrid.io", JSONRPC: true, V1: true}, {URL: "https://other.example"}}
	n, _ := reg.Get("nile")
	n.Upstreams = []tron.Upstream{{URL: "https://busy.trongrid.io", JSONRPC: true, V1: true}, {URL: "https://nile.trongrid.io", JSONRPC: true, V1: true}}
	if err := reg.Add("private", []string{"https://other.example"}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func (w *world) gateway(t *testing.T, def string) *httptest.Server {
	g := &gateway.Gateway{Client: w.cl, Nets: w.registry(t), Default: def, Log: w.logf}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url string, hdr map[string]string, body string) (*http.Response, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, rd)
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// assertOnlyMixnet: every connection went through the SOCKS proxy, by IPv4
// literal after DoH over it; no hostname was resolved locally or handed to
// the exit (the fake names don't exist anywhere else).
func assertOnlyMixnet(t *testing.T, w *world, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, r := range w.socks.Seen() {
		got[r.Host] = true
		if r.ATYP != 1 {
			t.Errorf("SOCKS CONNECT %v: DoH mode must connect by IPv4 literal", r)
		}
	}
	for _, h := range append(want, "1.1.1.1") {
		if !got[h] {
			t.Errorf("SOCKS never saw %s (saw %v)", h, got)
		}
	}
}

// java-tron and TronGrid requests pass through untouched: a GET's path and
// query, a POST's body byte for byte. The first upstream answers 500, the
// second one serves; each serving upstream was genesis checked first.
func TestPassThroughOverMixnet(t *testing.T) {
	w := newWorld(t)
	srv := w.gateway(t, "mainnet")
	body := `{"address":"` + testAddr + `","visible":true}`
	resp, got := do(t, "POST", srv.URL+"/wallet/getaccount", map[string]string{"Content-Type": "application/json"}, body)
	if resp.StatusCode != 200 || !strings.Contains(got, `"balance":1100001`) {
		t.Fatalf("getaccount: %d %s", resp.StatusCode, got)
	}
	s := w.last("api.trongrid.io")
	if s.Body != body || s.Method != "POST" || s.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("upstream got %s %q %q", s.Method, s.Body, s.Header.Get("Content-Type"))
	}
	if p := w.paths("api.trongrid.io"); len(p) != 2 || p[0] != "/wallet/getblockbynum" || p[1] != "/wallet/getaccount" {
		t.Fatalf("api.trongrid.io saw %v, want the genesis check, then the request", p)
	}
	if len(w.paths("bad.example")) == 0 {
		t.Fatal("first upstream was never tried")
	}
	// A GET with a query string (java-tron accepts both), TronGrid /v1 too.
	resp, _ = do(t, "GET", srv.URL+"/wallet/getaccount?address="+testAddr+"&visible=true", nil, "")
	if s := w.last("api.trongrid.io"); resp.StatusCode != 200 || s.Method != "GET" || s.RawQuery != "address="+testAddr+"&visible=true" {
		t.Fatalf("GET: %d %s ? %s", resp.StatusCode, s.Path, s.RawQuery)
	}
	resp, _ = do(t, "GET", srv.URL+"/v1/accounts/"+testAddr+"/transactions/trc20?limit=20&contract_address="+testUSDT, nil, "")
	if s := w.last("api.trongrid.io"); resp.StatusCode != 200 || s.Path != "/v1/accounts/"+testAddr+"/transactions/trc20" || s.RawQuery != "limit=20&contract_address="+testUSDT {
		t.Fatalf("/v1: %d %s ? %s", resp.StatusCode, s.Path, s.RawQuery)
	}
	// The node's own error answer comes back as it is.
	bc := `{"transaction":"` + testTxHex + `"}`
	resp, got = do(t, "POST", srv.URL+"/wallet/broadcasthex", map[string]string{"Content-Type": "application/json;charset=utf-8"}, bc)
	if resp.StatusCode != 200 || !strings.Contains(got, "SIGERROR") || w.last("api.trongrid.io").Body != bc {
		t.Fatalf("broadcasthex: %d %s", resp.StatusCode, got)
	}
	// A JSON-RPC call; text/plain (what some fetch wrappers send) is kept.
	rpc := `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`
	resp, got = do(t, "POST", srv.URL+"/jsonrpc", map[string]string{"Content-Type": "text/plain"}, rpc)
	if s := w.last("api.trongrid.io"); resp.StatusCode != 200 || !strings.Contains(got, "0x2b6653dc") || s.Body != rpc || s.Header.Get("Content-Type") != "text/plain" {
		t.Fatalf("jsonrpc: %d %s / %q %q", resp.StatusCode, got, s.Body, s.Header.Get("Content-Type"))
	}
	// `curl -d` labels its JSON body a form; it goes up as JSON, unchanged.
	resp, _ = do(t, "POST", srv.URL+"/wallet/getaccount", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body)
	if s := w.last("api.trongrid.io"); resp.StatusCode != 200 || s.Body != body || s.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("curl -d: %d %q %q", resp.StatusCode, s.Body, s.Header.Get("Content-Type"))
	}
	// An empty POST (getnowblock with no body) goes up as JSON.
	resp, _ = do(t, "POST", srv.URL+"/wallet/getnowblock", nil, "")
	if resp.StatusCode != 200 || w.last("api.trongrid.io").Header.Get("Content-Type") != "application/json" {
		t.Fatalf("empty POST: %d", resp.StatusCode)
	}
	// An unsupported body type is refused before anything goes out.
	before := len(w.socks.Seen())
	for _, ct := range []string{"multipart/form-data; boundary=x", "application/octet-stream", "image/png"} {
		if resp, _ = do(t, "POST", srv.URL+"/wallet/broadcasthex", map[string]string{"Content-Type": ct}, "x=1"); resp.StatusCode != 415 {
			t.Fatalf("%s: %d", ct, resp.StatusCode)
		}
	}
	if len(w.socks.Seen()) != before {
		t.Fatal("refused body still opened a stream")
	}
	assertOnlyMixnet(t, w, "192.0.2.8", "192.0.2.9")
}

// /nile, /mainnet and custom networks on one port, a listener with Nile at
// the root, and nothing outside the TRON API routes.
func TestNetworkRoutes(t *testing.T) {
	w := newWorld(t)
	main := w.gateway(t, "mainnet")
	nileRoot := w.gateway(t, "nile")
	for _, c := range []struct{ url, host string }{
		{main.URL + "/wallet/getnowblock", "api.trongrid.io"},
		{main.URL + "/mainnet/wallet/getnowblock", "api.trongrid.io"},
		{main.URL + "/nile/wallet/getnowblock", "nile.trongrid.io"},
		{nileRoot.URL + "/wallet/getnowblock", "nile.trongrid.io"},
		{main.URL + "/private/walletsolidity/getnowblock", "other.example"},
	} {
		resp, body := do(t, "POST", c.url, nil, "{}")
		want := strings.TrimPrefix(c.url[strings.Index(c.url[7:], "/")+7:], "/mainnet")
		want = strings.TrimPrefix(strings.TrimPrefix(want, "/nile"), "/private")
		if resp.StatusCode != 200 || !strings.Contains(body, "87799425") || w.last(c.host).Path != want {
			t.Fatalf("%s: %d %s (upstream %s saw %q)", c.url, resp.StatusCode, body, c.host, w.last(c.host).Path)
		}
	}
	if len(w.paths("busy.trongrid.io")) == 0 {
		t.Fatal("nile 429 upstream never tried")
	}
	if _, body := do(t, "GET", main.URL+"/", nil, ""); !strings.Contains(body, "/nile/wallet/getnowblock") {
		t.Fatalf("help: %s", body)
	}
	n := len(w.got)
	for _, p := range []string{"/wallet/%2e%2e/admin", "/nile/%2E%2E/wallet/getnowblock", "/healthcheck", "/admin", "/nile",
		"/nile/", "/wallet", "/jsonrpc/x", "/v1", "/static/../../etc/passwd", "/nile/wallet/../../x", "/unknownnet/wallet/getnowblock"} {
		if resp, _ := do(t, "POST", main.URL+p, nil, "{}"); resp.StatusCode != 404 {
			t.Fatalf("%s: want 404, got %d", p, resp.StatusCode)
		}
	}
	if len(w.got) != n {
		t.Fatalf("a refused path was forwarded: %v", w.got[n:])
	}
	if resp, _ := do(t, "PUT", main.URL+"/wallet/getnowblock", nil, "x"); resp.StatusCode != 405 {
		t.Fatalf("PUT: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "GET", main.URL+"/wallet/getnowblock", map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, ""); resp.StatusCode != 400 {
		t.Fatalf("websocket upgrade: %d", resp.StatusCode)
	}
}

// An upstream of another chain is skipped after the genesis check and never
// sees the real request; a custom network pins the first genesis it sees.
func TestGenesisGuard(t *testing.T) {
	w := newWorld(t)
	reg := w.registry(t)
	m, _ := reg.Get("mainnet")
	m.Upstreams = []tron.Upstream{{URL: "https://wrong.example"}, {URL: "https://other.example"}}
	srv := httptest.NewServer(&gateway.Gateway{Client: w.cl, Nets: reg, Default: "mainnet", Log: w.logf})
	defer srv.Close()
	body := `{"address":"` + testAddr + `","visible":true}`
	resp, _ := do(t, "POST", srv.URL+"/wallet/getaccount", nil, body)
	if resp.StatusCode != 200 || w.last("other.example").Body != body {
		t.Fatalf("getaccount: %d", resp.StatusCode)
	}
	if p := w.paths("wrong.example"); len(p) != 1 || p[0] != "/wallet/getblockbynum" {
		t.Fatalf("wrong-chain upstream saw %v, want only the genesis check", p)
	}
	if !strings.Contains(w.allLogs(), "serves a different chain") {
		t.Fatalf("wrong chain not logged:\n%s", w.allLogs())
	}
	// Each upstream is checked once per network, not per request.
	do(t, "POST", srv.URL+"/wallet/getaccount", nil, body)
	if p := w.paths("wrong.example"); len(p) != 2 {
		t.Fatalf("wrong.example: %v (a failed upstream is re-checked, never trusted)", p)
	}
	if c := strings.Count(strings.Join(w.paths("other.example"), " "), "getblockbynum"); c != 1 {
		t.Fatalf("other.example genesis-checked %d times", c)
	}
	// Only a wrong-chain upstream left: no answer, and no request reached it.
	m.Upstreams = []tron.Upstream{{URL: "https://wrong.example"}}
	resp, got := do(t, "POST", srv.URL+"/wallet/broadcasthex", nil, `{"transaction":"`+testTxHex+`"}`)
	if resp.StatusCode != 502 || !strings.Contains(got, "different chain") {
		t.Fatalf("all wrong chain: %d %s", resp.StatusCode, got)
	}
	for _, p := range w.paths("wrong.example") {
		if p != "/wallet/getblockbynum" {
			t.Fatalf("wrong-chain upstream got %s", p)
		}
	}
	// A custom network pins the first genesis; a node of another chain added
	// later to it is refused.
	if err := reg.Add("mine", []string{"https://nile.trongrid.io", "https://wrong.example", "https://other.example"}); err != nil {
		t.Fatal(err)
	}
	mine, _ := reg.Get("mine")
	var v map[string]any
	if used, err := w.cl.JSON(context.Background(), mine, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err != nil || used != "https://nile.trongrid.io" {
		t.Fatalf("pin: %v %s", err, used)
	}
	if mine.GenesisPinned() != nileGenesis {
		t.Fatalf("pinned %q", mine.GenesisPinned())
	}
	mine.Upstreams = []tron.Upstream{{URL: "https://other.example"}}
	before := len(w.paths("other.example"))
	if _, err := w.cl.JSON(context.Background(), mine, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err == nil || !strings.Contains(err.Error(), "different chain") {
		t.Fatalf("mainnet node under a Nile-pinned network: %v", err)
	}
	if p := w.paths("other.example")[before:]; len(p) != 1 || p[0] != "/wallet/getblockbynum" {
		t.Fatalf("other.example saw %v", p)
	}
}

// /jsonrpc and /v1 go only to upstreams that serve them.
func TestRouteAwareUpstreams(t *testing.T) {
	w := newWorld(t)
	reg := w.registry(t)
	m, _ := reg.Get("mainnet")
	m.Upstreams = []tron.Upstream{{URL: "https://other.example"}, {URL: "https://api.trongrid.io", JSONRPC: true, V1: true}}
	srv := httptest.NewServer(&gateway.Gateway{Client: w.cl, Nets: reg, Default: "mainnet", Log: w.logf})
	defer srv.Close()
	do(t, "GET", srv.URL+"/v1/accounts/"+testAddr, nil, "")
	do(t, "POST", srv.URL+"/jsonrpc", nil, `{"method":"eth_blockNumber"}`)
	if p := w.paths("other.example"); len(p) != 0 {
		t.Fatalf("plain node got %v", p)
	}
	if p := w.paths("api.trongrid.io"); len(p) != 3 {
		t.Fatalf("TronGrid got %v", p)
	}
	m.Upstreams = m.Upstreams[:1]
	resp, body := do(t, "GET", srv.URL+"/v1/accounts/"+testAddr, nil, "")
	if resp.StatusCode != 502 || !strings.Contains(body, "TronGrid only") || strings.Contains(body, testAddr) {
		t.Fatalf("no /v1 upstream: %d %s", resp.StatusCode, body)
	}
}

// Nothing about the local caller reaches the upstream (not even its own API
// key), and nothing but the content type comes back.
func TestHeaderStripping(t *testing.T) {
	w := newWorld(t)
	srv := w.gateway(t, "mainnet")
	resp, _ := do(t, "POST", srv.URL+"/wallet/getnowblock", map[string]string{
		"Origin": "chrome-extension://ibnejdfjmmkpcnlpebklmnkoeoihofec", "Cookie": "session=1", "Referer": "https://dapp.example/",
		"User-Agent": "TronLink/4.0", "X-Forwarded-For": "192.0.2.77", "Authorization": "Bearer x", "Accept-Language": "da-DK",
		"TRON-PRO-API-KEY": "callers-own-key", "X-Requested-With": "tronweb",
	}, "{}")
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	h := w.last("api.trongrid.io").Header
	for _, k := range []string{"Origin", "Cookie", "Referer", "X-Forwarded-For", "Authorization", "Accept-Language", "Tron-Pro-Api-Key", "X-Requested-With"} {
		if h.Get(k) != "" {
			t.Errorf("%s leaked upstream: %q", k, h.Get(k))
		}
	}
	if h.Get("User-Agent") != tron.UserAgent {
		t.Errorf("User-Agent upstream = %q", h.Get("User-Agent"))
	}
	for _, k := range []string{"Set-Cookie", "Location", "X-Upstream-Secret"} {
		if resp.Header.Get(k) != "" {
			t.Errorf("upstream header %s leaked back: %v", k, resp.Header)
		}
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "chrome-extension://ibnejdfjmmkpcnlpebklmnkoeoihofec" {
		t.Errorf("extension origin not allowed: %v", resp.Header)
	}
	resp, _ = do(t, "OPTIONS", srv.URL+"/wallet/broadcasttransaction", map[string]string{"Origin": "chrome-extension://abc",
		"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type, tron-pro-api-key, bad header"}, "")
	if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Headers") != "content-type, tron-pro-api-key" {
		t.Errorf("preflight: %d %v", resp.StatusCode, resp.Header)
	}
}

// The TronGrid key goes to *.trongrid.io only (the genesis check included)
// and never into a log line or an error.
func TestAPIKeyOnlyToTronGrid(t *testing.T) {
	w := newWorld(t)
	w.cl.APIKey = testKey
	reg := w.registry(t)
	m, _ := reg.Get("mainnet")
	m.Upstreams = []tron.Upstream{{URL: "https://other.example"}}
	var v map[string]any
	if _, err := w.cl.JSON(context.Background(), m, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err != nil {
		t.Fatal(err)
	}
	for _, s := range w.got {
		if s.Header.Get(tron.KeyHeader) != "" {
			t.Fatalf("non-TronGrid upstream got the key on %s", s.Path)
		}
	}
	m.Upstreams = []tron.Upstream{{URL: "https://api.trongrid.io"}}
	if _, err := w.cl.JSON(context.Background(), m, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err != nil {
		t.Fatal(err)
	}
	if p := w.paths("api.trongrid.io"); len(p) != 2 {
		t.Fatalf("api.trongrid.io: %v", p)
	}
	for _, s := range w.got {
		if s.Host == "api.trongrid.io" && s.Header.Get(tron.KeyHeader) != testKey {
			t.Fatalf("TronGrid lacks the key on %s", s.Path)
		}
	}
	// Failures (429 on TronGrid with the key) don't print it either.
	m.Upstreams = []tron.Upstream{{URL: "https://busy.trongrid.io"}}
	_, err := w.cl.JSON(context.Background(), m, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v)
	if err == nil || strings.Contains(err.Error()+w.allLogs(), testKey) {
		t.Fatalf("key in error or logs: %v\n%s", err, w.allLogs())
	}
}

func TestHostAndOriginGuard(t *testing.T) {
	w := newWorld(t)
	srv := w.gateway(t, "mainnet")
	before := len(w.socks.Seen())
	for _, host := range []string{"evil.example", "evil.example:8090", "127.0.0.1.evil.example"} {
		if resp, _ := do(t, "POST", srv.URL+"/wallet/getnowblock", map[string]string{"Host": host}, "{}"); resp.StatusCode != 403 {
			t.Fatalf("rebinding Host %s accepted: %d", host, resp.StatusCode)
		}
	}
	for _, o := range []string{"https://evil.example", "null", "http://127.0.0.1:8080"} {
		if resp, _ := do(t, "POST", srv.URL+"/wallet/broadcasthex", map[string]string{"Origin": o, "Content-Type": "application/json"}, `{"transaction":"`+testTxHex+`"}`); resp.StatusCode != 403 {
			t.Fatalf("web page origin %s accepted: %d", o, resp.StatusCode)
		}
	}
	if resp, _ := do(t, "OPTIONS", srv.URL+"/wallet/broadcasthex", map[string]string{"Origin": "https://evil.example"}, ""); resp.StatusCode != 403 {
		t.Fatalf("preflight from a web page accepted: %d", resp.StatusCode)
	}
	if n := len(w.socks.Seen()); n != before {
		t.Fatalf("refused requests still opened %d mixnet streams", n-before)
	}
	g := &gateway.Gateway{Client: w.cl, Nets: w.registry(t), Default: "mainnet", Origins: []string{"https://wallet.example"}}
	s2 := httptest.NewServer(g)
	defer s2.Close()
	if resp, _ := do(t, "POST", s2.URL+"/wallet/getnowblock", map[string]string{"Origin": "https://wallet.example"}, "{}"); resp.StatusCode != 200 {
		t.Fatalf("allowed origin refused: %d", resp.StatusCode)
	}
}

// Mixnet client down: 502 in java-tron's error shape, and no direct
// connection is ever attempted.
func TestNoClearnetFallback(t *testing.T) {
	w := newWorld(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	cl := &tron.Client{D: &mixnet.Dialer{Proxy: dead, Timeout: time.Second}, Timeout: 3 * time.Second}
	srv := httptest.NewServer(&gateway.Gateway{Client: cl, Nets: w.registry(t), Default: "mainnet"})
	defer srv.Close()
	resp, body := do(t, "POST", srv.URL+"/wallet/getnowblock", nil, "{}")
	var e struct{ Error, Reason string }
	if resp.StatusCode != 502 || json.Unmarshal([]byte(body), &e) != nil || e.Reason != "MixnetUnavailable" || !strings.Contains(e.Error, "no SOCKS5 proxy") {
		t.Fatalf("want 502 MixnetUnavailable, got %d %s", resp.StatusCode, body)
	}
	resp, _ = do(t, "POST", srv.URL+"/wallet/broadcasthex", nil, `{"transaction":"`+testTxHex+`"}`)
	if resp.StatusCode != 502 {
		t.Fatalf("broadcast: want 502, got %d", resp.StatusCode)
	}
	if len(w.got) != 0 {
		t.Fatalf("an upstream was reached without the mixnet: %v", w.got)
	}
	// The mixnet client dies after two upstreams passed their genesis check:
	// the request stops at the first one instead of walking the list.
	d2 := &mixnet.Dialer{Proxy: w.socks.Addr, DNS: mixnet.DNSDoH, RootCAs: w.d.RootCAs, Resolvers: []string{"1.1.1.1"}, Timeout: time.Second}
	cl2 := &tron.Client{D: d2, Timeout: 3 * time.Second, Log: w.logf}
	m := &tron.Network{Name: "mainnet", Genesis: mainGenesis}
	var v map[string]any
	for _, u := range []string{"https://api.trongrid.io", "https://other.example"} {
		m.Upstreams = []tron.Upstream{{URL: u}}
		if _, err := cl2.JSON(context.Background(), m, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err != nil {
			t.Fatal(err)
		}
	}
	d2.Proxy = dead
	cl2.CloseIdle()
	m.Upstreams = []tron.Upstream{{URL: "https://api.trongrid.io"}, {URL: "https://other.example"}}
	n := len(w.logs)
	if _, err := cl2.JSON(context.Background(), m, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err == nil {
		t.Fatal("answered with the proxy down")
	}
	if tries := strings.Count(strings.Join(w.logs[n:], "\n"), "no SOCKS5 proxy"); tries != 1 {
		t.Fatalf("%d attempts with the proxy down:\n%s", tries, strings.Join(w.logs[n:], "\n"))
	}
}

// The upstream is a real, directly reachable TLS server on localhost. With
// the mixnet client down, nothing may reach it, in either DNS mode and at any
// layer (dialer or HTTP client): a direct dial would land here and be seen.
func TestNoFallbackEvenWhenDirectWouldWork(t *testing.T) {
	ca := fakes.NewCA()
	var mu sync.Mutex
	hits := 0
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{ca.Leaf("localhost", "127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		fmt.Fprintf(rw, `{"blockID":"%s","block_header":{"raw_data":{"number":1}}}`, mainGenesis)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	dl, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := dl.Addr().String()
	dl.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	reg := tron.NewRegistry()
	if err := reg.Add("mainnet", []string{"https://localhost:" + port, "https://127.0.0.1:" + port}); err != nil {
		t.Fatal(err)
	}
	m, _ := reg.Get("mainnet")
	for _, mode := range []string{mixnet.DNSDoH, mixnet.DNSExit} {
		cl := &tron.Client{D: &mixnet.Dialer{Proxy: dead, DNS: mode, RootCAs: ca.Pool, Timeout: time.Second}, Timeout: 3 * time.Second}
		gw := httptest.NewServer(&gateway.Gateway{Client: cl, Nets: reg, Default: "mainnet"})
		resp, body := do(t, "POST", gw.URL+"/wallet/getnowblock", nil, "{}")
		gw.Close()
		if resp.StatusCode != 502 || !strings.Contains(body, "no SOCKS5 proxy") {
			t.Errorf("dns=%s: want 502, got %d %s", mode, resp.StatusCode, body)
		}
		var v map[string]any
		if _, err := cl.JSON(context.Background(), m, tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}, &v); err == nil {
			t.Errorf("dns=%s: CLI path answered without the mixnet", mode)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("the upstream was reached directly %d times", hits)
	}
}

func TestFailoverAndRedirects(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	reg := w.registry(t)
	m, _ := reg.Get("mainnet")
	set := func(urls ...string) {
		m.Upstreams = nil
		for _, u := range urls {
			m.Upstreams = append(m.Upstreams, tron.Upstream{URL: "https://" + u})
		}
	}
	getnow := tron.Request{Method: "POST", Path: "/wallet/getnowblock", Body: []byte("{}")}
	var v map[string]any
	// 429, then 500, then a node that passes genesis and answers 503, then a good one.
	set("busy.trongrid.io", "bad.example", "late.example", "api.trongrid.io")
	used, err := w.cl.JSON(ctx, m, getnow, &v)
	if err != nil || used != "https://api.trongrid.io" {
		t.Fatalf("failover: %v %s", err, used)
	}
	if p := w.paths("late.example"); len(p) != 2 || p[1] != "/wallet/getnowblock" {
		t.Fatalf("late.example saw %v", p)
	}
	// Every upstream failing with HTTP errors: the last answer is surfaced.
	set("busy.trongrid.io", "late.example")
	status, _, _, err := w.cl.Fetch(ctx, m, getnow)
	if err != nil || status != 503 {
		t.Fatalf("all-5xx: status %d err %v", status, err)
	}
	// A timeout moves on to the next upstream.
	fast := &tron.Client{D: w.d, Timeout: 700 * time.Millisecond, Log: w.logf}
	set("slow.example", "api.trongrid.io")
	t0 := time.Now()
	used, err = fast.JSON(ctx, m, getnow, &v)
	if err != nil || used != "https://api.trongrid.io" || time.Since(t0) > 4*time.Second {
		t.Fatalf("timeout failover: %v %s after %s", err, used, time.Since(t0))
	}
	if !strings.Contains(w.allLogs(), "no answer within") {
		t.Fatalf("timeout not logged:\n%s", w.allLogs())
	}
	// A POST is re-sent with its body to the next upstream.
	set("late.example", "other.example")
	bc := []byte(`{"transaction":"` + testTxHex + `"}`)
	status, body, used, err := w.cl.Fetch(ctx, m, tron.Request{Method: "POST", Path: "/wallet/broadcasthex", Body: bc})
	if err != nil || status != 200 || used != "https://other.example" || w.last("other.example").Body != string(bc) || !strings.Contains(string(body), "SIGERROR") {
		t.Fatalf("POST failover: %d %s %v", status, body, err)
	}
	// A redirect is never followed (its target was never genesis checked),
	// neither at the genesis check nor later, and its Location never comes back.
	set("redir.example", "other.example")
	before := len(w.paths("other.example"))
	if used, err = w.cl.JSON(ctx, m, getnow, &v); err != nil || used != "https://other.example" {
		t.Fatalf("redirect: %v %s", err, used)
	}
	if p := w.paths("other.example")[before:]; len(p) != 1 {
		t.Fatalf("redirect was followed to other.example: %v", p)
	}
	set("api.trongrid.io")
	if status, _, _, err := w.cl.Fetch(ctx, m, tron.Request{Method: "POST", Path: "/wallet/redirect", Body: []byte("{}")}); err == nil {
		t.Fatalf("redirect answer passed through (HTTP %d)", status)
	}
	srv := w.gateway(t, "mainnet")
	if resp, _ := do(t, "POST", srv.URL+"/wallet/redirect", nil, "{}"); resp.Header.Get("Location") != "" {
		t.Fatalf("Location leaked: %v", resp.Header)
	}
	assertOnlyMixnet(t, w, "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.10", "192.0.2.13", "192.0.2.14")
}

func TestOnlyHTTPSUpstreams(t *testing.T) {
	w := newWorld(t)
	n := &tron.Network{Name: "x", Upstreams: []tron.Upstream{{URL: "http://api.trongrid.io"}}}
	if _, _, _, err := w.cl.Fetch(context.Background(), n, tron.Request{Path: "/wallet/getnowblock"}); err == nil {
		t.Fatal("plain http upstream accepted")
	}
	if len(w.socks.Seen()) != 0 {
		t.Fatal("plain http upstream opened a stream")
	}
}

// Request params (addresses, contract args, tx bytes, query strings) never
// reach a log line, on success or failure.
func TestLogsCarryNoParams(t *testing.T) {
	w := newWorld(t)
	w.cl.APIKey = testKey
	srv := w.gateway(t, "mainnet")
	reqs := func(url string) []string {
		_, b1 := do(t, "POST", url+"/wallet/getaccount", nil, `{"address":"`+testAddr+`","visible":true}`)
		_, b2 := do(t, "GET", url+"/wallet/getaccount?address="+testAddr, nil, "")
		_, b3 := do(t, "POST", url+"/wallet/triggerconstantcontract", nil, `{"owner_address":"`+testAddr+`","contract_address":"`+testUSDT+`","function_selector":"balanceOf(address)","parameter":"`+testParam+`"}`)
		_, b4 := do(t, "POST", url+"/wallet/broadcasthex", nil, `{"transaction":"`+testTxHex+`"}`)
		_, b5 := do(t, "GET", url+"/v1/transactions/"+testTxID+"/events", nil, "")
		_, b6 := do(t, "POST", url+"/jsonrpc", nil, `{"method":"eth_getBalance","params":["0x5a523b449890854c8fc460ab602df9f31fe4293f","latest"]}`)
		_, b7 := do(t, "POST", url+"/wallet/"+testAddr, nil, "{}")
		return []string{b1, b2, b3, b4, b5, b6, b7}
	}
	reqs(srv.URL)
	all := w.allLogs()
	for _, want := range []string{"POST /wallet/getaccount", "GET /wallet/getaccount", "POST /wallet/triggerconstantcontract", "POST /wallet/broadcasthex",
		"GET /v1/transactions/*/events", "POST /jsonrpc eth_getBalance", "POST /wallet/*"} {
		if !strings.Contains(all, want) {
			t.Errorf("log lacks %q:\n%s", want, all)
		}
	}
	// The same with the mixnet client down: errors and logs stay clean too.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	cl := &tron.Client{D: &mixnet.Dialer{Proxy: dead, Timeout: time.Second}, Timeout: 3 * time.Second, Log: w.logf, APIKey: testKey}
	down := httptest.NewServer(&gateway.Gateway{Client: cl, Nets: w.registry(t), Default: "mainnet", Log: w.logf})
	defer down.Close()
	failBodies := reqs(down.URL)
	all = w.allLogs()
	for _, secret := range []string{testAddr, testUSDT, testParam, testTxHex, testTxID, "5a523b449890854c8fc460ab602df9f31fe4293f", "balanceOf", testKey} {
		if strings.Contains(all, secret) {
			t.Errorf("log contains %q:\n%s", secret, all)
		}
		for _, b := range failBodies {
			if strings.Contains(b, secret) {
				t.Errorf("502 answer contains %q: %s", secret, b)
			}
		}
	}
	tries := 0
	for _, l := range strings.Split(all, "\n") {
		if strings.HasPrefix(l, "up ") && strings.Contains(l, "no SOCKS5 proxy") {
			tries++
		}
	}
	if tries != 7 {
		t.Fatalf("%d upstream attempts for 7 requests with no proxy (the next upstream needs the same proxy):\n%s", tries, all)
	}
	// An upstream that drops the connection after its genesis check: Go's
	// *url.Error would carry the full request URL with its query string.
	reg := w.registry(t)
	m, _ := reg.Get("mainnet")
	m.Upstreams = []tron.Upstream{{URL: "https://drop.example"}}
	dropGW := httptest.NewServer(&gateway.Gateway{Client: w.cl, Nets: reg, Default: "mainnet", Log: w.logf})
	defer dropGW.Close()
	resp, body := do(t, "GET", dropGW.URL+"/wallet/getaccount?address="+testAddr+"&visible=true", nil, "")
	// (net/http retries a GET once on a reused connection that drops.)
	if p := w.paths("drop.example"); resp.StatusCode != 502 || len(p) < 2 || p[1] != "/wallet/getaccount" {
		t.Fatalf("drop: %d %s %v", resp.StatusCode, body, w.paths("drop.example"))
	}
	if strings.Contains(body+w.allLogs(), testAddr) {
		t.Fatalf("address in a failure answer or log:\n%s\n%s", body, w.allLogs())
	}
}
