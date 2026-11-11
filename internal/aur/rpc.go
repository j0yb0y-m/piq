package aur

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	rpcBase = "https://aur.archlinux.org/rpc"

	userAgent = "piq/0.2 (+https://github.com/j0yb0y-m/piq)"

	// maxBatch is the largest number of names sent in a single info request.
	maxBatch = 200
	// maxURLLen bounds the encoded request URL; longer batches are halved.
	maxURLLen = 4000
	// maxAttempts caps retries of transient failures, including the first try.
	maxAttempts = 3
)

type Client struct {
	http       *http.Client
	base       string
	retryDelay func(int) time.Duration
}

func NewClient() *Client {
	return NewClientWithBase(rpcBase)
}

// NewClientWithBase returns a Client talking to base instead of the real AUR.
func NewClientWithBase(base string) *Client {
	return &Client{
		http: &http.Client{Timeout: 15 * time.Second},
		base: base,
		retryDelay: func(attempt int) time.Duration {
			return 250 * time.Millisecond * time.Duration(1<<attempt)
		},
	}
}

// Package mirrors the field that we actually use from an RPC v5 result.
// Add more fields as needed.

type Package struct {
	Name           string
	PackageBase    string
	PackageBaseID  int
	Version        string
	Description    string
	URL            string
	NumVotes       int
	Popularity     float64
	Maintainer     string
	OutOfDate      *int64
	FirstSubmitted int64
	LastModified   int64
	URLPath        string

	// Dependency metadata returned by AUR RPC v5's info endpoint. piq
	// uses it to resolve the AUR dependency closure without cloning
	// every candidate first.
	Depends      []string
	MakeDepends  []string
	CheckDepends []string
}

type rpcResponse struct {
	Type        string    `json:"type"`
	ResultCount int       `json:"resultcount"`
	Results     []Package `json:"results"`
	Error       string    `json:"error"`
}

// retryable reports whether a response status is worth another attempt.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

func (c *Client) do(params url.Values) (*rpcResponse, error) {
	params.Set("v", "5")
	full := c.base + "?" + params.Encode()

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodGet, full, nil)
		if err != nil {
			return nil, fmt.Errorf("aur rpc request %w", err)
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("aur rpc result %w", err)
		}

		if resp.StatusCode == http.StatusOK {
			var out rpcResponse
			err := json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("aur rpc result %w", err)
			}
			if out.Type == "error" {
				return nil, fmt.Errorf("aur rpc error: %s", out.Error)
			}
			return &out, nil
		}

		// Drain and close so the connection can be reused on the next attempt.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()

		lastErr = fmt.Errorf("aur rpc: unexpected status %s", resp.Status)
		if !retryable(resp.StatusCode) || attempt == maxAttempts-1 {
			break
		}

		delay := c.retryDelay(attempt)
		if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
				delay = time.Duration(secs) * time.Second
			}
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}

// search runs a name and description search, same as piq search <term>
func (c *Client) Search(term string) ([]Package, error) {
	v := url.Values{}
	v.Set("type", "search")
	v.Set("arg", term)
	resp, err := c.do(v)
	if err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// Info batch fetches exact name metadata for one or more Packages. Names are
// sent in batches of at most maxBatch, shrinking further when the encoded URL
// would exceed maxURLLen. Results are concatenated in server order per batch;
// names are neither sorted nor deduplicated.
func (c *Client) Info(names ...string) ([]Package, error) {
	if len(names) == 0 {
		return []Package{}, nil
	}

	out := make([]Package, 0, len(names))
	batch := names
	for len(batch) > 0 {
		chunk := batch[:min(len(batch), maxBatch)]
		for {
			v := url.Values{}
			v.Set("type", "info")
			v.Set("v", "5")
			for _, name := range chunk {
				v.Add("arg[]", name)
			}
			if len(c.base)+1+len(v.Encode()) <= maxURLLen || len(chunk) == 1 {
				resp, err := c.do(v)
				if err != nil {
					return nil, err
				}
				out = append(out, resp.Results...)
				batch = batch[len(chunk):]
				break
			}
			chunk = chunk[:(len(chunk)+1)/2]
		}
	}
	return out, nil
}

// CloneURL returns the git URL for a package's AUR repo. Every AUR
// package — source, PKGBUILD, .SRCINFO, everything — lives in one
// of these, keyed by *package base*, not package name (a split
// package's pieces share one repo).
func CloneURL(pkgbase string) string {
	return "https://aur.archlinux.org/" + strings.TrimSpace(pkgbase) + ".git"
}
