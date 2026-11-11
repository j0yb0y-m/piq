package aur

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClient(base string) *Client {
	c := NewClientWithBase(base)
	c.retryDelay = func(int) time.Duration { return 0 }
	return c
}

func TestInfoSendsUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("missing User-Agent")
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q, want application/json", got)
		}
		if got := r.URL.Query().Get("v"); got != "5" {
			t.Errorf("v = %q, want 5", got)
		}
		io.WriteString(w, `{"type":"multiinfo","resultcount":0,"results":[]}`)
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL).Info("paru"); err != nil {
		t.Fatal(err)
	}
}

func TestInfoParsesDependencyFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"type":"multiinfo","resultcount":1,"results":[{"Name":"x","Depends":["go>=1.22"],"MakeDepends":["git"],"CheckDepends":["bats"]}]}`)
	}))
	defer srv.Close()

	pkgs, err := testClient(srv.URL).Info("x")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages", len(pkgs))
	}
	p := pkgs[0]
	if len(p.Depends) != 1 || p.Depends[0] != "go>=1.22" ||
		len(p.MakeDepends) != 1 || p.MakeDepends[0] != "git" ||
		len(p.CheckDepends) != 1 || p.CheckDepends[0] != "bats" {
		t.Fatalf("dependencies not decoded: %+v", p)
	}
}

func TestInfoBatches(t *testing.T) {
	var requests, args atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		args.Add(int64(len(r.URL.Query()["arg[]"])))
		io.WriteString(w, `{"type":"multiinfo","resultcount":0,"results":[]}`)
	}))
	defer srv.Close()

	names := make([]string, 450)
	for i := range names {
		names[i] = fmt.Sprintf("pkg-%03d", i)
	}
	if _, err := testClient(srv.URL).Info(names...); err != nil {
		t.Fatal(err)
	}
	if got, want := requests.Load(), int64(3); got != want {
		t.Fatalf("requests = %d, want %d", got, want)
	}
	if got, want := args.Load(), int64(450); got != want {
		t.Fatalf("args = %d, want %d", got, want)
	}
}

func TestInfoRetries429(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, `{"type":"multiinfo","resultcount":0,"results":[]}`)
	}))
	defer srv.Close()

	if _, err := testClient(srv.URL).Info("paru"); err != nil {
		t.Fatal(err)
	}
	if got, want := attempts.Load(), int64(2); got != want {
		t.Fatalf("attempts = %d, want %d", got, want)
	}
}

func TestInfoGivesUpAfterThree(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Info("paru")
	if err == nil {
		t.Fatal("expected error after repeated 500s")
	}
	if got, want := attempts.Load(), int64(3); got != want {
		t.Fatalf("attempts = %d, want %d", got, want)
	}
}

func TestInfoHTTPErrorStatus(t *testing.T) {
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Info("paru")
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error %q does not mention status", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (no retry on 4xx)", got)
	}
}

func TestInfoRPCErrorType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"type":"error","error":"gone"}`)
	}))
	defer srv.Close()

	_, err := testClient(srv.URL).Info("paru")
	if err == nil {
		t.Fatal("expected rpc error")
	}
	if !strings.Contains(err.Error(), "gone") {
		t.Fatalf("error %q does not mention rpc error", err)
	}
}

func TestInfoEmpty(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	defer srv.Close()

	pkgs, err := testClient(srv.URL).Info()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("got %d packages, want 0", len(pkgs))
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
}

func TestSearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if got := q.Get("type"); got != "search" {
			t.Errorf("type = %q, want search", got)
		}
		if got := q.Get("arg"); got != "paru" {
			t.Errorf("arg = %q, want paru", got)
		}
		io.WriteString(w, `{"type":"search","resultcount":1,"results":[{"Name":"paru"}]}`)
	}))
	defer srv.Close()

	pkgs, err := testClient(srv.URL).Search("paru")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "paru" {
		t.Fatalf("results = %+v, want one paru", pkgs)
	}
}

func TestInfoShrinksBatchForLongNames(t *testing.T) {
	var requests, args atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		args.Add(int64(len(r.URL.Query()["arg[]"])))
		io.WriteString(w, `{"type":"multiinfo","resultcount":0,"results":[]}`)
	}))
	defer srv.Close()

	names := make([]string, 20)
	for i := range names {
		names[i] = fmt.Sprintf("%03d", i) + strings.Repeat("a", 197)
	}
	if _, err := testClient(srv.URL).Info(names...); err != nil {
		t.Fatal(err)
	}
	if got, want := args.Load(), int64(20); got != want {
		t.Fatalf("args = %d, want %d", got, want)
	}
	if got := requests.Load(); got <= 1 {
		t.Fatalf("requests = %d, want more than 1", got)
	}
}
