package api

import (
	_ "embed"
	"net/http"
)

//go:embed web/admin.html
var adminPage []byte

// serveAdminPage serves the admin page. It is one self-contained file, so the
// server needs nothing on disk and nothing from the internet to offer it.
func serveAdminPage(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	// Inline script and style only, nothing loaded from elsewhere, and not
	// to be framed by another site that would like an administrator's clicks.
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	w.Write(adminPage)
}
