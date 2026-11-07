// Package gateway is a local TRON full-node HTTP endpoint for wallets and
// tools. Point TronWeb (fullHost), tronpy (HTTPProvider), a wallet's custom
// node setting or curl at
//
//	http://127.0.0.1:8090            the default network (mainnet)
//	http://127.0.0.1:8090/nile       Nile testnet (also /shasta, /mainnet, and any --add network)
//
// and every /wallet/..., /walletsolidity/..., /walletpbft/..., /jsonrpc and
// TronGrid /v1/... request is forwarded to a public TRON API through the Nym
// mixnet, after the upstream passed a genesis check.
package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apeirs/trxmix/tron"
)

// Gateway serves the routes above.
type Gateway struct {
	Client  *tron.Client
	Nets    *tron.Registry
	Default string   // network served at the root ("" = none)
	Hosts   []string // extra accepted Host values
	Origins []string // extra accepted Origin values ("*" = any web page)
	Timeout time.Duration
	Log     func(string, ...any)

	Total, Failed atomic.Int64
}

func (g *Gateway) logf(f string, a ...any) {
	if g.Log != nil {
		g.Log(f, a...)
	}
}

func (g *Gateway) hostOK(h string) bool {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	for _, x := range g.Hosts {
		if x == h {
			return true
		}
	}
	return false
}

// originOK: no Origin (CLI tools, node scripts, tronpy), a browser extension
// (TronLink and other wallets), or an origin the user allowed. Any other web
// page is refused, so a site you visit can't use your gateway.
func (g *Gateway) originOK(o string) bool {
	if o == "" {
		return true
	}
	for _, p := range []string{"chrome-extension://", "moz-extension://", "safari-web-extension://"} {
		if strings.HasPrefix(o, p) {
			return true
		}
	}
	for _, x := range g.Origins {
		if x == "*" || x == o {
			return true
		}
	}
	return false
}

type route struct {
	net *tron.Network
	sub string // escaped, cleaned path below the upstream base
}

func (g *Gateway) route(escaped string) (route, bool) {
	// An encoded dot segment would be decoded upstream and could step out of
	// the allowed routes.
	if strings.Contains(strings.ToLower(escaped), "%2e") {
		return route{}, false
	}
	trimmed := strings.TrimPrefix(escaped, "/")
	first, after, _ := strings.Cut(trimmed, "/")
	var rt route
	if n, ok := g.Nets.Get(first); ok && first != "" {
		rt = route{n, path.Clean("/" + after)}
	} else if n, ok := g.Nets.Get(g.Default); ok && g.Default != "" {
		rt = route{n, path.Clean("/" + trimmed)}
	} else {
		return route{}, false
	}
	if !tron.Allowed(rt.sub) {
		return route{}, false
	}
	return rt, true
}

// bodyType maps the caller's Content-Type to the one sent upstream. TRON
// clients post JSON; java-tron reads the body as JSON whatever the type.
// `curl -d '{...}'`, as in most TRON API examples, labels it a form: it goes
// up as JSON. (A web page could post a form cross-site without a preflight,
// but its Origin header is refused before this point.)
func bodyType(ct string) (string, bool) {
	if ct == "" {
		return "application/json", true
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", false
	}
	switch mt {
	case "application/json", "text/plain":
		return mt, true
	case "application/x-www-form-urlencoded":
		return "application/json", true
	}
	return "", false
}

// headerList keeps a CORS request-header list to plain header tokens.
func headerList(s string) string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		h = strings.TrimSpace(h)
		if h != "" && len(h) < 64 && strings.Trim(strings.ToLower(h), "abcdefghijklmnopqrstuvwxyz0123456789-") == "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return "content-type"
	}
	return strings.Join(out, ", ")
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// DNS-rebinding guard: a web page must not reach this through a rebound name.
	if !g.hostOK(r.Host) {
		http.Error(w, "bad Host header", http.StatusForbidden)
		return
	}
	origin := r.Header.Get("Origin")
	if !g.originOK(origin) {
		http.Error(w, "origin not allowed (see --allow-origin)", http.StatusForbidden)
		return
	}
	h := w.Header()
	if origin != "" {
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Vary", "Origin")
	}
	if r.Method == "OPTIONS" {
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		// Whatever the caller asks for is allowed: none of it is forwarded.
		h.Set("Access-Control-Allow-Headers", headerList(r.Header.Get("Access-Control-Request-Headers")))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	escaped := r.URL.EscapedPath()
	if escaped == "/" && r.Method == "GET" && r.Header.Get("Upgrade") == "" {
		g.help(w)
		return
	}
	rt, ok := g.route(escaped)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		g.help(w)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "the TRON HTTP API has no websocket", http.StatusBadRequest)
		return
	}
	if len(rt.net.Upstreams) == 0 {
		http.Error(w, fmt.Sprintf("network %s has no upstream (add one with --add)", rt.net.Name), http.StatusNotFound)
		return
	}
	var body []byte
	var ct string
	if r.Method == "POST" {
		var ok bool
		if ct, ok = bodyType(r.Header.Get("Content-Type")); !ok {
			http.Error(w, "POST body must be JSON (application/json, text/plain or curl's default form type)", http.StatusUnsupportedMediaType)
			return
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, "could not read the request body", http.StatusBadRequest)
			return
		}
		if body == nil {
			body = []byte{}
		}
	}
	label := r.Method + " " + tron.Label(r.Method, rt.sub, body)
	g.Total.Add(1)
	tmo := g.Timeout
	if tmo == 0 {
		tmo = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(r.Context(), tmo)
	defer cancel()
	t0 := time.Now()
	resp, err := g.Client.Do(ctx, rt.net, tron.Request{Method: r.Method, Path: rt.sub, RawQuery: r.URL.RawQuery,
		Body: body, ContentType: ct, Label: label})
	if err != nil {
		g.Failed.Add(1)
		g.logf("%s %s FAILED after %.1fs: %v", rt.net.Name, label, time.Since(t0).Seconds(), err)
		g.fail(w, err)
		return
	}
	defer resp.Body.Close()
	// Only the content type comes back: no Set-Cookie, no Location, no server
	// headers that would tempt the caller to talk to the upstream directly.
	if resp.ContentType != "" {
		h.Set("Content-Type", resp.ContentType)
	}
	w.WriteHeader(resp.Status)
	n, _ := io.Copy(w, resp.Body)
	g.logf("%s %s -> mixnet -> %s HTTP %d, %d bytes in %.1fs", rt.net.Name, label, tron.HostOf(resp.Upstream), resp.Status, n, time.Since(t0).Seconds())
}

// fail answers 502 in java-tron's own error shape ({"Error": ...}), which
// TronWeb and tronpy surface to the caller.
func (g *Gateway) fail(w http.ResponseWriter, err error) {
	msg := fmt.Sprintf("trxmix: all upstreams failed over the mixnet (no clearnet fallback): %v", err)
	js, _ := json.Marshal(msg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, `{"Error":%s,"reason":"MixnetUnavailable"}`, js)
}

func (g *Gateway) help(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "trxmix gateway: the TRON HTTP API over the Nym mixnet.\n")
	if g.Default != "" {
		fmt.Fprintf(w, "  /wallet/... /walletsolidity/... /jsonrpc /v1/...   %s (the default network)\n", g.Default)
	}
	fmt.Fprintf(w, "  /<network>/...                                     that network, e.g. /nile/wallet/getnowblock\n")
	fmt.Fprintf(w, "networks:\n")
	for _, n := range g.Nets.All() {
		fmt.Fprintf(w, "  %-10s upstreams %d\n", n.Name, len(n.Upstreams))
	}
	fmt.Fprintf(w, "requests so far: %d, failed: %d\n", g.Total.Load(), g.Failed.Load())
}
