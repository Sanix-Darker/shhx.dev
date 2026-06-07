package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

// staticCacheControl lets browsers cache embedded assets but always revalidate
// against the content-hash ETag. A new build changes the hash, so clients
// re-fetch changed files while unchanged ones return a bodyless 304. This
// avoids re-downloading the embedded OpenPGP library and app bundle on every
// page load, which the blanket no-store header on dynamic routes would force.
const staticCacheControl = "public, max-age=0, must-revalidate"

// staticAsset is an embedded file resolved once at startup: its bytes, an
// ETag derived from the content hash, and its MIME type.
type staticAsset struct {
	body        []byte
	etag        string
	contentType string
}

// staticHandler serves embedded static assets from memory with content-hash
// ETags. All assets are read and hashed once in newStaticHandler, so request
// handling is an O(1) map lookup with no per-request I/O or hashing.
type staticHandler struct {
	assets map[string]staticAsset
}

// newStaticHandler walks the embedded static tree once, reading and hashing
// every file. Returning an error keeps asset-loading failures visible at
// startup rather than surfacing as confusing 404s later.
func newStaticHandler(staticFS fs.FS) (*staticHandler, error) {
	assets := make(map[string]staticAsset)
	err := fs.WalkDir(staticFS, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		body, readErr := fs.ReadFile(staticFS, p)
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(body)
		etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
		contentType := mime.TypeByExtension(path.Ext(p))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		assets["/"+p] = staticAsset{body: body, etag: etag, contentType: contentType}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &staticHandler{assets: assets}, nil
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	asset, ok := h.assets[cleanStaticPath(r.URL.Path)]
	if !ok {
		http.NotFound(w, r)
		return
	}

	header := w.Header()
	header.Set("Content-Type", asset.contentType)
	header.Set("ETag", asset.etag)
	// Override the dynamic-route no-store policy for cacheable static assets.
	header.Set("Cache-Control", staticCacheControl)

	if clientHasFreshCopy(r, asset.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(asset.body))
}

// cleanStaticPath normalizes a request path (after the /static/ prefix has
// been stripped) into a leading-slash map key, defeating any "../" traversal.
func cleanStaticPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return path.Clean(p)
}

// clientHasFreshCopy reports whether the request's If-None-Match matches the
// asset ETag, allowing a 304 response without sending the body.
func clientHasFreshCopy(r *http.Request, etag string) bool {
	match := r.Header.Get("If-None-Match")
	if match == "" {
		return false
	}
	for part := range strings.SplitSeq(match, ",") {
		candidate := strings.TrimSpace(part)
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag || candidate == "*" {
			return true
		}
	}
	return false
}
