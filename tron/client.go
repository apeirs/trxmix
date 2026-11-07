package tron

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/apeirs/trxmix/mixnet"
)

// UserAgent is sent upstream instead of whatever the local caller used.
const UserAgent = "Mozilla/5.0"

// KeyHeader carries the optional TronGrid API key ($TRXMIX_TRONGRID_KEY).
const KeyHeader = "TRON-PRO-API-KEY"

// IsTronGrid reports whether host (no port) is a TronGrid host, the only
// ones that ever get the API key.
func IsTronGrid(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "trongrid.io" || strings.HasSuffix(host, ".trongrid.io")
}

// Client sends requests to upstream TRON APIs, always via the mixnet Dialer.
// There is no clearnet fallback.
type Client struct {
	D       *mixnet.Dialer
	Timeout time.Duration // per upstream attempt (genesis check included), until the response headers arrive
	// APIKey is sent as TRON-PRO-API-KEY, and only to *.trongrid.io. It is
	// never logged. Empty = keyless (TronGrid's per-IP limits).
	APIKey string
	Log    func(format string, args ...any)

	once     sync.Once
	http     *http.Client
	mu       sync.Mutex
	verified map[string]bool // upstream|network pairs whose genesis was checked
	Calls    atomic.Int64
}

func (c *Client) logf(f string, a ...any) {
	if c.Log != nil {
		c.Log(f, a...)
	}
}

func (c *Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 50 * time.Second
}

func (c *Client) client() *http.Client {
	c.once.Do(func() {
		// Keep-alives on: one mixnet stream + TLS handshake is expensive, reuse it.
		c.http = &http.Client{
			Transport: &http.Transport{
				Proxy:               nil, // never an environment proxy
				DialContext:         c.D.DialContext,
				TLSHandshakeTimeout: 90 * time.Second,
				TLSClientConfig:     &tls.Config{RootCAs: c.D.RootCAs},
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 4,
			},
			// A redirect is never followed: its target was not genesis
			// checked. It counts as a failed upstream, and its Location never
			// reaches the caller (who would follow it over the clearnet).
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
	return c.http
}

// CloseIdle drops the kept-alive upstream streams, so the next request opens
// a fresh one (after the mixnet client restarted, the old ones are dead).
func (c *Client) CloseIdle() {
	c.client().CloseIdleConnections()
}

// Request is one HTTP request relative to an upstream base URL.
type Request struct {
	Method      string // GET or POST
	Path        string // escaped path below the upstream base, e.g. "/wallet/getnowblock"
	RawQuery    string // passed through untouched
	Body        []byte
	ContentType string
	Label       string // for logs only; must never contain request params
}

// Response is an upstream answer. The caller closes Body.
type Response struct {
	Status      int
	ContentType string
	Body        io.ReadCloser
	Upstream    string
}

// Join appends an escaped path and query to an upstream base URL.
func Join(base, path, rawQuery string) (*url.URL, error) {
	if err := CheckURL(base); err != nil {
		return nil, err
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	u, err := url.Parse(strings.TrimRight(base, "/") + path)
	if err != nil {
		return nil, err
	}
	u.RawQuery = rawQuery
	return u, nil
}

// HostOf returns the host of an upstream URL, for logs.
func HostOf(u string) string {
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		return p.Host
	}
	return u
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelBody) Close() error { err := b.ReadCloser.Close(); b.cancel(); return err }

// retryable: provider-side trouble worth trying the next upstream for. A
// redirect counts: it is never followed.
func retryable(status int) bool {
	return status >= 500 || status == 429 || (status >= 300 && status < 400)
}

// send is one HTTP exchange with only our own headers.
func (c *Client) send(ctx context.Context, method string, u *url.URL, body []byte, ct string) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	// Nothing about the local caller is forwarded: no Origin, Referer,
	// cookies, wallet User-Agent or the caller's own API key.
	hr.Header = http.Header{}
	hr.Header.Set("User-Agent", UserAgent)
	hr.Header.Set("Accept", "application/json, */*;q=0.5")
	if body != nil {
		if ct == "" {
			ct = "application/json"
		}
		hr.Header.Set("Content-Type", ct)
	}
	if c.APIKey != "" && IsTronGrid(u.Hostname()) {
		hr.Header.Set(KeyHeader, c.APIKey)
	}
	resp, err := c.client().Do(hr)
	if err != nil {
		// *url.Error carries the full URL (addresses, txids in a query);
		// keep only the cause so logs and errors never hold params.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	return resp, nil
}

var genesisReq = []byte(`{"num":0}`)

// verify checks once per upstream and network that the upstream's block 0
// is the network's genesis block. An upstream of another chain (a testnet
// URL under mainnet, a typo in --add) never sees a real request.
func (c *Client) verify(ctx context.Context, n *Network, base string) error {
	key := base + "|" + n.Name
	c.mu.Lock()
	done := c.verified[key]
	c.mu.Unlock()
	if done {
		return nil
	}
	u, err := Join(base, "/wallet/getblockbynum", "")
	if err != nil {
		return err
	}
	resp, err := c.send(ctx, "POST", u, genesisReq, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return &statusError{resp.StatusCode, "genesis check"}
	}
	var b struct {
		BlockID string `json:"blockID"`
		Error   string `json:"Error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&b); err != nil {
		return fmt.Errorf("genesis check: not a TRON node answer")
	}
	if b.Error != "" {
		return fmt.Errorf("genesis check: %s", oneLine(b.Error, 120))
	}
	if len(b.BlockID) != 64 {
		return errors.New("genesis check: no block id")
	}
	if _, err := hex.DecodeString(b.BlockID); err != nil {
		return errors.New("genesis check: no block id")
	}
	if err := n.CheckGenesis(b.BlockID); err != nil {
		return err
	}
	c.mu.Lock()
	if c.verified == nil {
		c.verified = map[string]bool{}
	}
	c.verified[key] = true
	c.mu.Unlock()
	return nil
}

type statusError struct {
	status int
	what   string
}

func (e *statusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.what, e.status) }

// Verified reports whether base has passed the genesis check for n.
func (c *Client) Verified(n *Network, base string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.verified[base+"|"+n.Name]
}

// Do sends req to the first upstream of n that serves req.Path, passes the
// genesis check and answers without a server error. 2xx-4xx answers are
// returned as they are (a node's error is an answer). If every upstream
// answered 5xx/429/3xx, the last such answer is returned.
func (c *Client) Do(ctx context.Context, n *Network, req Request) (*Response, error) {
	ups := n.For(req.Path)
	if len(ups) == 0 {
		if len(n.Upstreams) == 0 {
			return nil, fmt.Errorf("network %s has no upstream", n.Name)
		}
		return nil, fmt.Errorf("no upstream of %s serves %s (TronGrid only)", n.Name, Label("GET", req.Path, nil))
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	var errs []error
	var fallback *Response
	for _, up := range ups {
		base := up.URL
		u, err := Join(base, req.Path, req.RawQuery)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		host := u.Host
		tmo := c.timeout()
		actx, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(tmo, cancel)
		t0 := time.Now()
		fail := func(err error) {
			cancel()
			c.logf("%-4s %s %s failed after %.2fs: %v", "up", host, req.Label, time.Since(t0).Seconds(), err)
			errs = append(errs, fmt.Errorf("%s: %w", host, err))
		}
		if err := c.verify(actx, n, base); err != nil {
			if !timer.Stop() {
				err = fmt.Errorf("no answer within %s", tmo)
			}
			fail(err)
			if ctx.Err() != nil || errors.Is(err, mixnet.ErrProxyUnreachable) {
				break // the next upstream would need the same missing proxy
			}
			continue
		}
		resp, err := c.send(actx, req.Method, u, req.Body, req.ContentType)
		stopped := timer.Stop()
		if err != nil {
			if !stopped {
				err = fmt.Errorf("no answer within %s", tmo)
			}
			fail(err)
			if ctx.Err() != nil || errors.Is(err, mixnet.ErrProxyUnreachable) {
				break
			}
			continue
		}
		if retryable(resp.StatusCode) {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			cancel()
			c.logf("%-4s %s %s answered HTTP %d in %.2fs, trying the next upstream", "up", host, req.Label, resp.StatusCode, time.Since(t0).Seconds())
			errs = append(errs, fmt.Errorf("%s: HTTP %d", host, resp.StatusCode))
			if resp.StatusCode < 300 || resp.StatusCode >= 400 {
				fallback = &Response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"), Body: io.NopCloser(bytes.NewReader(b)), Upstream: base}
			}
			continue
		}
		c.Calls.Add(1)
		c.logf("%-4s %s %s answered HTTP %d in %.2fs", "up", host, req.Label, resp.StatusCode, time.Since(t0).Seconds())
		return &Response{Status: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"),
			Body: cancelBody{resp.Body, cancel}, Upstream: base}, nil
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.Join(errs...)
}

// Fetch is Do with the answer read whole (at most 32 MiB).
func (c *Client) Fetch(ctx context.Context, n *Network, req Request) (int, []byte, string, error) {
	if req.Label == "" {
		req.Label = Label(req.Method, req.Path, req.Body)
	}
	resp, err := c.Do(ctx, n, req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return resp.Status, b, resp.Upstream, err
}

// APIError is an error answer from a TRON API.
type APIError struct {
	Status   int
	Upstream string
	Msg      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d from %s: %s", e.Status, HostOf(e.Upstream), e.Msg)
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "..."
	}
	if !utf8.ValidString(s) {
		return fmt.Sprintf("%.*q", max, s)
	}
	return s
}

// ErrorText extracts the message of an error answer: java-tron's
// {"Error": ...}, a broadcast's {"code", "message"} (message in hex),
// TronGrid's {"error": ...} or plain text.
func ErrorText(b []byte) string {
	var e struct {
		Error   string `json:"Error"`
		Err     string `json:"error"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &e) == nil {
		var parts []string
		for _, s := range []string{e.Error, e.Err, e.Code, HexText(e.Message)} {
			if s != "" {
				parts = append(parts, oneLine(s, 300))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, ": ")
		}
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "(empty body)"
	}
	return oneLine(t, 300)
}

// HexText decodes a node message that java-tron sends hex encoded (broadcast
// errors). Anything that isn't printable hex text is returned unchanged.
func HexText(s string) string {
	if len(s) < 2 || len(s)%2 != 0 {
		return s
	}
	b, err := hex.DecodeString(s)
	if err != nil || !utf8.Valid(b) {
		return s
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\t' {
			return s
		}
	}
	return string(b)
}

// JSON sends req and decodes a 200 answer into v. java-tron reports most
// errors as HTTP 200 with an "Error" field: those become an *APIError.
func (c *Client) JSON(ctx context.Context, n *Network, req Request, v any) (string, error) {
	status, b, used, err := c.Fetch(ctx, n, req)
	if err != nil {
		return used, err
	}
	if status != 200 {
		return used, &APIError{status, used, ErrorText(b)}
	}
	var probe struct {
		Error string `json:"Error"`
	}
	if json.Unmarshal(b, &probe) == nil && probe.Error != "" {
		return used, &APIError{status, used, oneLine(probe.Error, 300)}
	}
	if err := json.Unmarshal(b, v); err != nil {
		return used, fmt.Errorf("unexpected answer from %s: %.120q", HostOf(used), b)
	}
	return used, nil
}

// Post is JSON for a java-tron POST with a JSON body.
func (c *Client) Post(ctx context.Context, n *Network, path string, body any, v any) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return c.JSON(ctx, n, Request{Method: "POST", Path: path, Body: b, ContentType: "application/json"}, v)
}
