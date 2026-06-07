package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStaticServesAssetWithRevalidationHeaders(t *testing.T) {
	server, err := NewServer("test")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header on static asset")
	}
	if cc := rr.Header().Get("Cache-Control"); cc == "no-store" || cc == "" {
		t.Fatalf("expected revalidation cache policy, got %q", cc)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "javascript") {
		t.Fatalf("expected a javascript content type for nosniff compatibility, got %q", ct)
	}
	if rr.Body.Len() == 0 {
		t.Fatal("expected asset body on first fetch")
	}
}

func TestStaticReturnsNotModifiedForMatchingETag(t *testing.T) {
	server, err := NewServer("test")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	routes := server.Routes()

	first := httptest.NewRecorder()
	routes.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/static/styles.css", nil))
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag on first fetch")
	}

	req := httptest.NewRequest(http.MethodGet, "/static/styles.css", nil)
	req.Header.Set("If-None-Match", etag)
	second := httptest.NewRecorder()
	routes.ServeHTTP(second, req)

	if second.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Fatalf("expected empty body on 304, got %d bytes", second.Body.Len())
	}
}

func TestStaticRejectsUnknownAsset(t *testing.T) {
	server, err := NewServer("test")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/static/nope.txt", nil)
	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown asset, got %d", rr.Code)
	}
}

func TestStaticServesNestedVendorAsset(t *testing.T) {
	server, err := NewServer("test")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/static/vendor/openpgp.min.js", nil)
	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for vendor asset, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("expected javascript content type, got %q", rr.Header().Get("Content-Type"))
	}
	if rr.Body.Len() == 0 {
		t.Fatal("expected vendor asset body")
	}
}

func TestStaticBlocksTraversal(t *testing.T) {
	server, err := NewServer("test")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// A traversal attempt must not escape the embedded asset map.
	req := httptest.NewRequest(http.MethodGet, "/static/../server.go", nil)
	rr := httptest.NewRecorder()
	server.Routes().ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("expected traversal to be rejected, got 200")
	}
}
