package aur

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const rpcBase = "https://aur.archlinux.org/rpc"

type Client struct {
	http *http.Client
}

func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 15 * time.Second}}
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
}

type rpcResponse struct {
	Type        string    `json:"type"`
	ResultCount int       `json:"resultcount"`
	Results     []Package `json:"results"`
	Error       string    `json:"error"`
}

func (c *Client) do(params url.Values) (*rpcResponse, error) {
	params.Set("v", "5")
	full := rpcBase + "?" + params.Encode()
	resp, err := c.http.Get(full)
	if err != nil {
		return nil, fmt.Errorf("aur rpc result %w", err)
	}
	defer resp.Body.Close()

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("aur rpc result %w", err)
	}
	if out.Type == "error" {
		return nil, fmt.Errorf("aur rpc error %s", out.Error)
	}
	return &out, nil
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

// info batch fetches exact name metadata for one or more Packages
func (c *Client) Info(names ...string) ([]Package, error) {
	v := url.Values{}
	v.Set("type", "info")
	for _, n := range names {
		v.Add("arg[]", n)
	}
	resp, err := c.do(v)
	if err != nil {
		return nil, err
	}
	return resp.Results, nil
}

// CloneURL returns the git URL for a package's AUR repo. Every AUR
// package — source, PKGBUILD, .SRCINFO, everything — lives in one
// of these, keyed by *package base*, not package name (a split
// package's pieces share one repo).
func CloneURL(pkgbase string) string {
	return "https://aur.archlinux.org/" + strings.TrimSpace(pkgbase) + ".git"
}
